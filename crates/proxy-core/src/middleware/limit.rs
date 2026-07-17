use std::{
    collections::HashMap,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use hyper::{StatusCode, body::Body};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::ResponseBody;

pub(crate) type InFlightLimiters = Arc<HashMap<String, Arc<InFlightLimiter>>>;

#[derive(Debug)]
pub(crate) enum Outcome {
    NotConfigured,
    Acquired(InFlightPermit),
    Limited(StatusCode),
    Unavailable,
}

pub(crate) fn build(
    config: &Config,
    previous: Option<(&Config, &InFlightLimiters)>,
) -> InFlightLimiters {
    Arc::new(
        config
            .middlewares
            .iter()
            .filter_map(|(id, definition)| {
                let MiddlewareConfig::InFlightLimit {
                    max_requests,
                    max_per_client,
                    status,
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
                        Arc::new(InFlightLimiter {
                            global: Arc::new(Semaphore::new(*max_requests)),
                            clients: Arc::new(Mutex::new(HashMap::new())),
                            max_per_client: *max_per_client,
                            status: *status,
                        })
                    });
                Some((id.clone(), limiter))
            })
            .collect(),
    )
}

pub(crate) fn acquire(
    limiters: &InFlightLimiters,
    config: &Config,
    route: &RouteConfig,
    client: IpAddr,
) -> Outcome {
    let Some(id) = route.middlewares.iter().find(|id| {
        matches!(
            config.middlewares.get(id.as_str()),
            Some(MiddlewareConfig::InFlightLimit { .. })
        )
    }) else {
        return Outcome::NotConfigured;
    };
    let Some(limiter) = limiters.get(id) else {
        return Outcome::Unavailable;
    };
    limiter.acquire(client)
}

pub(crate) fn hold(body: ResponseBody, permit: InFlightPermit) -> ResponseBody {
    http_body_util::BodyExt::boxed(PermitBody {
        body: Box::pin(body),
        _permit: permit,
    })
}

#[derive(Debug)]
pub(crate) struct InFlightLimiter {
    global: Arc<Semaphore>,
    clients: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_client: usize,
    status: u16,
}

impl InFlightLimiter {
    fn acquire(&self, client: IpAddr) -> Outcome {
        let Ok(global) = Arc::clone(&self.global).try_acquire_owned() else {
            return self.limited();
        };
        let Ok(mut clients) = self.clients.lock() else {
            return Outcome::Unavailable;
        };
        let active = clients.entry(client).or_default();
        if *active >= self.max_per_client {
            return self.limited();
        }
        *active += 1;
        drop(clients);
        Outcome::Acquired(InFlightPermit {
            _global: global,
            clients: Arc::clone(&self.clients),
            client,
        })
    }

    fn limited(&self) -> Outcome {
        StatusCode::from_u16(self.status)
            .map(Outcome::Limited)
            .unwrap_or(Outcome::Unavailable)
    }
}

#[derive(Debug)]
pub(crate) struct InFlightPermit {
    _global: OwnedSemaphorePermit,
    clients: Arc<Mutex<HashMap<IpAddr, usize>>>,
    client: IpAddr,
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        let Ok(mut clients) = self.clients.lock() else {
            return;
        };
        if let Some(active) = clients.get_mut(&self.client) {
            *active = active.saturating_sub(1);
            if *active == 0 {
                clients.remove(&self.client);
            }
        }
    }
}

#[derive(Debug)]
struct PermitBody {
    body: Pin<Box<ResponseBody>>,
    _permit: InFlightPermit,
}

impl Body for PermitBody {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.body.as_mut().poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::RouteConfig;
    use std::collections::BTreeMap;

    #[test]
    fn global_and_client_capacity_release_without_queueing() {
        let config = config();
        let limiters = build(&config, None);
        let route = route();
        let first_ip = "192.0.2.1".parse().expect("IP");
        let second_ip = "192.0.2.2".parse().expect("IP");
        let third_ip = "192.0.2.3".parse().expect("IP");
        let Outcome::Acquired(first) = acquire(&limiters, &config, &route, first_ip) else {
            panic!("first request");
        };
        assert!(matches!(
            acquire(&limiters, &config, &route, first_ip),
            Outcome::Limited(StatusCode::TOO_MANY_REQUESTS)
        ));
        let Outcome::Acquired(second) = acquire(&limiters, &config, &route, second_ip) else {
            panic!("second client");
        };
        assert!(matches!(
            acquire(&limiters, &config, &route, third_ip),
            Outcome::Limited(StatusCode::TOO_MANY_REQUESTS)
        ));
        drop(first);
        assert!(matches!(
            acquire(&limiters, &config, &route, first_ip),
            Outcome::Acquired(_)
        ));
        drop(second);
    }

    #[test]
    fn unchanged_reload_reuses_active_capacity() {
        let config = config();
        let first = build(&config, None);
        let second = build(&config, Some((&config, &first)));
        assert!(Arc::ptr_eq(&first["inflight"], &second["inflight"]));
    }

    fn config() -> Config {
        let mut config: Config = toml::from_str("schema_version = 1").expect("config");
        config.middlewares = BTreeMap::from([(
            "inflight".into(),
            MiddlewareConfig::InFlightLimit {
                max_requests: 2,
                max_per_client: 1,
                status: 429,
            },
        )]);
        config
    }

    fn route() -> RouteConfig {
        RouteConfig {
            id: "route".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec!["inflight".into()],
            upstream_group: Some("app".into()),
        }
    }
}
