use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use aegisproxy_config::{Config, MiddlewareConfig, RateLimitKey, RouteConfig};

pub(crate) type RateLimiters = Arc<HashMap<String, Arc<RateLimiter>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Allowed,
    Limited { retry_after_secs: u64 },
}

pub(crate) fn build(config: &Config, previous: Option<(&Config, &RateLimiters)>) -> RateLimiters {
    Arc::new(
        config
            .middlewares
            .iter()
            .filter_map(|(id, definition)| {
                let MiddlewareConfig::RateLimit {
                    key: _,
                    requests_per_second,
                    burst,
                    max_keys,
                    idle_secs,
                } = definition
                else {
                    return None;
                };
                let limiter = previous
                    .and_then(|(old_config, old_limiters)| {
                        (old_config.middlewares.get(id) == Some(definition))
                            .then(|| old_limiters.get(id))
                            .flatten()
                            .cloned()
                    })
                    .unwrap_or_else(|| {
                        Arc::new(RateLimiter::new(
                            *requests_per_second,
                            *burst,
                            *max_keys,
                            Duration::from_secs(*idle_secs),
                        ))
                    });
                Some((id.clone(), limiter))
            })
            .collect(),
    )
}

pub(crate) fn check(
    limiters: &RateLimiters,
    config: &Config,
    route: &RouteConfig,
    address: IpAddr,
) -> Result<Outcome, ()> {
    let Some(id) = route.middlewares.iter().find(|id| {
        matches!(
            config.middlewares.get(id.as_str()),
            Some(MiddlewareConfig::RateLimit {
                key: RateLimitKey::ClientIp,
                ..
            })
        )
    }) else {
        return Ok(Outcome::Allowed);
    };
    limiters
        .get(id)
        .ok_or(())?
        .check(LimiterKey::Ip(address), Instant::now())
}

pub(crate) fn check_principal(
    limiters: &RateLimiters,
    config: &Config,
    route: &RouteConfig,
    principal: Option<&str>,
) -> Result<Outcome, ()> {
    let Some(id) = route.middlewares.iter().find(|id| {
        matches!(
            config.middlewares.get(id.as_str()),
            Some(MiddlewareConfig::RateLimit {
                key: RateLimitKey::Principal,
                ..
            })
        )
    }) else {
        return Ok(Outcome::Allowed);
    };
    let principal = principal.ok_or(())?;
    limiters
        .get(id)
        .ok_or(())?
        .check(LimiterKey::Principal(principal.to_owned()), Instant::now())
}

#[derive(Debug)]
pub(crate) struct RateLimiter {
    requests_per_second: u64,
    burst: u64,
    max_keys: usize,
    idle: Duration,
    buckets: Mutex<HashMap<LimiterKey, Bucket>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum LimiterKey {
    Ip(IpAddr),
    Principal(String),
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated: Instant,
    last_seen: Instant,
}

impl RateLimiter {
    fn new(requests_per_second: u64, burst: u64, max_keys: usize, idle: Duration) -> Self {
        Self {
            requests_per_second,
            burst,
            max_keys,
            idle,
            buckets: Mutex::new(HashMap::with_capacity(max_keys.min(1024))),
        }
    }

    fn check(&self, key: LimiterKey, now: Instant) -> Result<Outcome, ()> {
        let mut buckets = self.buckets.lock().map_err(|_| ())?;
        if !buckets.contains_key(&key) && buckets.len() >= self.max_keys {
            buckets.retain(|_, bucket| {
                now.checked_duration_since(bucket.last_seen)
                    .unwrap_or_default()
                    < self.idle
            });
            if buckets.len() >= self.max_keys {
                return Ok(Outcome::Limited {
                    retry_after_secs: self.idle.as_secs().clamp(1, 60),
                });
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: self.burst as f64,
            updated: now,
            last_seen: now,
        });
        let elapsed = now
            .checked_duration_since(bucket.updated)
            .unwrap_or_default()
            .as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.requests_per_second as f64).min(self.burst as f64);
        bucket.updated = now;
        bucket.last_seen = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(Outcome::Allowed);
        }
        let retry_after_secs = ((1.0 - bucket.tokens) / self.requests_per_second as f64)
            .ceil()
            .clamp(1.0, 60.0) as u64;
        Ok(Outcome::Limited { retry_after_secs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn token_bucket_refills_and_key_store_stays_bounded() {
        let limiter = RateLimiter::new(1, 2, 2, Duration::from_secs(10));
        let now = Instant::now();
        let first = "192.0.2.1".parse().expect("IP");
        assert_eq!(
            limiter.check(LimiterKey::Ip(first), now),
            Ok(Outcome::Allowed)
        );
        assert_eq!(
            limiter.check(LimiterKey::Ip(first), now),
            Ok(Outcome::Allowed)
        );
        assert_eq!(
            limiter.check(LimiterKey::Ip(first), now),
            Ok(Outcome::Limited {
                retry_after_secs: 1
            })
        );
        assert_eq!(
            limiter.check(LimiterKey::Ip(first), now + Duration::from_secs(1)),
            Ok(Outcome::Allowed)
        );

        let second = "192.0.2.2".parse().expect("IP");
        let third = "192.0.2.3".parse().expect("IP");
        assert_eq!(
            limiter.check(LimiterKey::Ip(second), now),
            Ok(Outcome::Allowed)
        );
        assert!(matches!(
            limiter.check(LimiterKey::Ip(third), now),
            Ok(Outcome::Limited { .. })
        ));
        assert_eq!(
            limiter.check(LimiterKey::Ip(third), now + Duration::from_secs(11)),
            Ok(Outcome::Allowed)
        );
        assert!(limiter.buckets.lock().expect("buckets").len() <= 2);
    }

    #[test]
    fn unchanged_reload_reuses_limiter_state() {
        let initial = config(2);
        let first = build(&initial, None);
        let second = build(&initial, Some((&initial, &first)));
        assert!(Arc::ptr_eq(&first["edge"], &second["edge"]));

        let changed = config(3);
        let third = build(&changed, Some((&initial, &second)));
        assert!(!Arc::ptr_eq(&second["edge"], &third["edge"]));
    }

    #[test]
    fn principal_limits_use_only_authenticated_identity() {
        let mut config = config(1);
        let Some(MiddlewareConfig::RateLimit { key, .. }) = config.middlewares.get_mut("edge")
        else {
            panic!("rate limiter");
        };
        *key = RateLimitKey::Principal;
        let limiters = build(&config, None);
        let route = RouteConfig {
            id: "route".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec!["edge".into()],
            upstream_group: Some("app".into()),
        };
        assert_eq!(
            check_principal(&limiters, &config, &route, Some("alice")),
            Ok(Outcome::Allowed)
        );
        assert!(matches!(
            check_principal(&limiters, &config, &route, Some("alice")),
            Ok(Outcome::Limited { .. })
        ));
        assert_eq!(
            check_principal(&limiters, &config, &route, Some("bob")),
            Ok(Outcome::Allowed)
        );
        assert!(check_principal(&limiters, &config, &route, None).is_err());
    }

    fn config(burst: u64) -> Config {
        let mut config: Config = toml::from_str(
            r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
        "#,
        )
        .expect("test config");
        config.middlewares = BTreeMap::from([(
            "edge".into(),
            MiddlewareConfig::RateLimit {
                key: RateLimitKey::ClientIp,
                requests_per_second: 1,
                burst,
                max_keys: 2,
                idle_secs: 60,
            },
        )]);
        config
    }
}
