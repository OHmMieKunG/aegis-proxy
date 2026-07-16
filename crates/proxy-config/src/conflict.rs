//! Deterministic HTTP route overlap analysis.

use std::collections::HashMap;

use crate::{ConfigError, RouteConfig};

pub(crate) fn validate_route_conflicts(routes: &[RouteConfig]) -> Result<(), ConfigError> {
    for (left_index, left) in routes.iter().enumerate() {
        for (right_index, right) in routes.iter().enumerate().skip(left_index + 1) {
            if same_matchers(left, right) {
                return Err(conflict_error(
                    left_index,
                    left,
                    right_index,
                    right,
                    "duplicate matchers",
                ));
            }
            if !listeners_overlap(left, right) {
                continue;
            }
            if left.default || right.default {
                if left.default && right.default {
                    return Err(conflict_error(
                        left_index,
                        left,
                        right_index,
                        right,
                        "multiple default routes share a listener",
                    ));
                }
                continue;
            }
            if left.priority != right.priority
                || !methods_overlap(left, right)
                || !headers_overlap(left, right)
                || !equal_host_specificity_can_overlap(left, right)
                || !equal_path_specificity_can_overlap(left, right)
                || constraint_specificity(left) != constraint_specificity(right)
            {
                continue;
            }
            return Err(conflict_error(
                left_index,
                left,
                right_index,
                right,
                "ambiguous equal-priority overlap; assign distinct priorities",
            ));
        }
    }
    Ok(())
}

fn constraint_specificity(route: &RouteConfig) -> (bool, usize, usize, usize) {
    (
        !route.methods.is_empty(),
        route.methods.len(),
        route.headers.len(),
        route
            .headers
            .iter()
            .filter(|predicate| predicate.value.is_some())
            .count(),
    )
}

fn conflict_error(
    left_index: usize,
    left: &RouteConfig,
    right_index: usize,
    right: &RouteConfig,
    reason: &str,
) -> ConfigError {
    ConfigError::Invalid(format!(
        "routes[{left_index}] ({}) and routes[{right_index}] ({}) conflict: {reason}",
        left.id, right.id
    ))
}

fn same_matchers(left: &RouteConfig, right: &RouteConfig) -> bool {
    left.default == right.default
        && same_string_set(&left.listeners, &right.listeners)
        && same_string_set(&left.hosts, &right.hosts)
        && same_string_set(&left.paths, &right.paths)
        && same_string_set(&left.path_prefixes, &right.path_prefixes)
        && same_string_set(&left.methods, &right.methods)
        && same_headers(left, right)
}

fn same_string_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|value| right.contains(value))
}

fn same_headers(left: &RouteConfig, right: &RouteConfig) -> bool {
    left.headers.len() == right.headers.len()
        && left.headers.iter().all(|predicate| {
            right.headers.iter().any(|candidate| {
                candidate.name == predicate.name && candidate.value == predicate.value
            })
        })
}

fn listeners_overlap(left: &RouteConfig, right: &RouteConfig) -> bool {
    left.listeners
        .iter()
        .any(|listener| right.listeners.contains(listener))
}

fn methods_overlap(left: &RouteConfig, right: &RouteConfig) -> bool {
    left.methods.is_empty()
        || right.methods.is_empty()
        || left
            .methods
            .iter()
            .any(|method| right.methods.contains(method))
}

fn headers_overlap(left: &RouteConfig, right: &RouteConfig) -> bool {
    let left_values: HashMap<&str, Option<&str>> = left
        .headers
        .iter()
        .map(|predicate| (predicate.name.as_str(), predicate.value.as_deref()))
        .collect();
    right.headers.iter().all(|predicate| {
        left_values
            .get(predicate.name.as_str())
            .is_none_or(
                |left_value| match (*left_value, predicate.value.as_deref()) {
                    (Some(left), Some(right)) => left == right,
                    _ => true,
                },
            )
    })
}

fn equal_host_specificity_can_overlap(left: &RouteConfig, right: &RouteConfig) -> bool {
    if left.hosts.is_empty() || right.hosts.is_empty() {
        return left.hosts.is_empty() && right.hosts.is_empty();
    }
    left.hosts.iter().any(|left_host| {
        right.hosts.iter().any(|right_host| {
            left_host.starts_with("*.") == right_host.starts_with("*.")
                && left_host.len() == right_host.len()
                && hosts_overlap(left_host, right_host)
        })
    })
}

fn hosts_overlap(left: &str, right: &str) -> bool {
    match (left.strip_prefix("*."), right.strip_prefix("*.")) {
        (Some(left_suffix), Some(right_suffix)) => left_suffix == right_suffix,
        (Some(_), None) => wildcard_matches(left, right),
        (None, Some(_)) => wildcard_matches(right, left),
        (None, None) => left == right,
    }
}

fn wildcard_matches(pattern: &str, exact: &str) -> bool {
    let Some(suffix) = pattern.strip_prefix('*') else {
        return false;
    };
    exact
        .strip_suffix(suffix)
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

fn equal_path_specificity_can_overlap(left: &RouteConfig, right: &RouteConfig) -> bool {
    if left
        .paths
        .iter()
        .any(|left_path| right.paths.iter().any(|right_path| left_path == right_path))
    {
        return true;
    }
    if left.path_prefixes.is_empty() || right.path_prefixes.is_empty() {
        return left.paths.is_empty()
            && right.paths.is_empty()
            && left.path_prefixes.is_empty()
            && right.path_prefixes.is_empty();
    }
    left.path_prefixes.iter().any(|left_path| {
        right.path_prefixes.iter().any(|right_path| {
            left_path.len() == right_path.len() && paths_overlap(left_path, right_path)
        })
    })
}

fn paths_overlap(left: &str, right: &str) -> bool {
    left == "/"
        || right == "/"
        || left == right
        || segment_prefix(left, right)
        || segment_prefix(right, left)
}

fn segment_prefix(prefix: &str, value: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMatch;

    fn route(id: &str) -> RouteConfig {
        RouteConfig {
            id: id.into(),
            listeners: vec!["public".into()],
            hosts: vec!["example.test".into()],
            paths: vec![],
            path_prefixes: vec!["/api".into()],
            methods: vec!["GET".into()],
            headers: vec![],
            default: false,
            priority: 0,
            middlewares: vec![],
            upstream_group: Some("app".into()),
        }
    }

    #[test]
    fn rejects_duplicate_matchers_even_with_different_priority() {
        let left = route("left");
        let mut right = route("right");
        right.priority = 1;
        assert!(validate_route_conflicts(&[left, right]).is_err());
    }

    #[test]
    fn rejects_equal_score_overlap_but_accepts_explicit_priority() {
        let mut left = route("left");
        left.headers.push(HeaderMatch {
            name: "x-left".into(),
            value: Some("yes".into()),
        });
        let mut right = route("right");
        right.headers.push(HeaderMatch {
            name: "x-right".into(),
            value: Some("yes".into()),
        });
        assert!(validate_route_conflicts(&[left.clone(), right.clone()]).is_err());
        right.priority = 1;
        assert!(validate_route_conflicts(&[left, right]).is_ok());
    }

    #[test]
    fn accepts_disjoint_or_more_specific_routes() {
        let left = route("left");
        let mut right = route("right");
        right.methods = vec!["POST".into()];
        assert!(validate_route_conflicts(&[left.clone(), right]).is_ok());

        let mut right = route("right");
        right.path_prefixes = vec!["/api/admin".into()];
        assert!(validate_route_conflicts(&[left.clone(), right]).is_ok());

        let mut right = route("right");
        right.hosts = vec!["*.example.test".into()];
        assert!(validate_route_conflicts(&[left, right]).is_ok());
    }

    #[test]
    fn same_header_with_different_values_is_disjoint() {
        let mut left = route("left");
        left.headers.push(HeaderMatch {
            name: "x-tenant".into(),
            value: Some("blue".into()),
        });
        let mut right = route("right");
        right.headers.push(HeaderMatch {
            name: "x-tenant".into(),
            value: Some("green".into()),
        });
        assert!(validate_route_conflicts(&[left, right]).is_ok());
    }

    #[test]
    fn accepts_more_specific_method_header_host_and_path() {
        let mut broad = route("broad");
        broad.methods.clear();
        broad.headers.push(HeaderMatch {
            name: "x-authenticated".into(),
            value: None,
        });
        let mut narrow = route("narrow");
        narrow.headers.push(HeaderMatch {
            name: "x-authenticated".into(),
            value: Some("yes".into()),
        });
        assert!(validate_route_conflicts(&[broad, narrow]).is_ok());

        let mut wildcard = route("wildcard");
        wildcard.hosts = vec!["*.example.test".into()];
        let exact = route("exact");
        assert!(validate_route_conflicts(&[wildcard, exact]).is_ok());

        let prefix = route("prefix");
        let mut exact = route("exact");
        exact.paths = vec!["/api".into()];
        exact.path_prefixes.clear();
        assert!(validate_route_conflicts(&[prefix, exact]).is_ok());
    }

    #[test]
    fn rejects_multiple_defaults_on_one_listener() {
        let mut left = route("left");
        left.default = true;
        left.hosts.clear();
        left.paths.clear();
        left.path_prefixes.clear();
        left.methods.clear();
        let mut right = left.clone();
        right.id = "right".into();
        assert!(validate_route_conflicts(&[left, right]).is_err());
    }
}
