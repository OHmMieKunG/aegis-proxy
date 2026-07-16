use std::{collections::HashMap, sync::Arc};

use arc_swap::ArcSwap;
use rustls::{server::ResolvesServerCert, sign::CertifiedKey};

use crate::{
    Identity, TlsError,
    acme::{TlsAlpnChallengeRegistry, tls_alpn_protocol},
};

/// SNI resolver with exact-name precedence and single-label wildcards.
#[derive(Clone)]
pub struct CertificateResolver {
    current: Arc<ArcSwap<CertificateMaps>>,
    acme: TlsAlpnChallengeRegistry,
}

struct CertificateMaps {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcard: HashMap<String, Arc<CertifiedKey>>,
}

impl std::fmt::Debug for CertificateResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let current = self.current.load();
        formatter
            .debug_struct("CertificateResolver")
            .field("exact_names", &current.exact.len())
            .field("wildcard_names", &current.wildcard.len())
            .finish()
    }
}

impl CertificateResolver {
    /// Build a resolver, rejecting duplicate exact or wildcard names.
    pub fn new(identities: &[Identity]) -> Result<Self, TlsError> {
        Self::with_acme_challenges(identities, TlsAlpnChallengeRegistry::default())
    }

    /// Build a resolver retaining one process-wide ephemeral ACME challenge registry.
    pub fn with_acme_challenges(
        identities: &[Identity],
        acme: TlsAlpnChallengeRegistry,
    ) -> Result<Self, TlsError> {
        let maps = build_maps(identities)?;
        Ok(Self {
            current: Arc::new(ArcSwap::from_pointee(maps)),
            acme,
        })
    }

    /// Atomically replace all identities after fully validating the new map.
    pub fn replace(&self, identities: &[Identity]) -> Result<(), TlsError> {
        let maps = build_maps(identities)?;
        self.current.store(Arc::new(maps));
        Ok(())
    }

    /// Select a key for a canonical lower-case DNS name.
    pub fn resolve_name(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.current.load().resolve_name(name)
    }
}

fn build_maps(identities: &[Identity]) -> Result<CertificateMaps, TlsError> {
    let mut exact = HashMap::new();
    let mut wildcard = HashMap::new();
    for identity in identities {
        for host in identity.hosts() {
            let (map, name) = match host.strip_prefix("*.") {
                Some(suffix) => (&mut wildcard, suffix),
                None => (&mut exact, host.as_str()),
            };
            if map.insert(name.to_owned(), identity.key()).is_some() {
                return Err(TlsError::DuplicateName(host.clone()));
            }
        }
    }
    Ok(CertificateMaps { exact, wildcard })
}

impl CertificateMaps {
    fn resolve_name(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.exact.get(name).cloned().or_else(|| {
            name.split_once('.')
                .and_then(|(_, suffix)| self.wildcard.get(suffix))
                .cloned()
        })
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let acme_alpn = client_hello
            .alpn()
            .is_some_and(|mut protocols| protocols.any(|protocol| protocol == tls_alpn_protocol()));
        if acme_alpn {
            return client_hello
                .server_name()
                .and_then(|name| self.acme.resolve_name(name).ok().flatten());
        }
        client_hello
            .server_name()
            .and_then(|name| self.resolve_name(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::identity_from_pem;
    use rcgen::generate_simple_self_signed;

    fn identity(id: &str, certificate_host: &str, configured_hosts: Vec<String>) -> Identity {
        let generated = generate_simple_self_signed(vec![certificate_host.into()])
            .expect("generate test identity");
        identity_from_pem(
            id.into(),
            configured_hosts,
            generated.cert.pem().as_bytes(),
            generated.signing_key.serialize_pem().as_bytes(),
        )
        .expect("valid identity")
    }

    #[test]
    fn exact_name_wins_over_wildcard() {
        let wildcard = identity("wildcard", "*.example.test", vec!["*.example.test".into()]);
        let exact = identity("exact", "api.example.test", vec!["api.example.test".into()]);
        let exact_key = exact.key();
        let resolver = CertificateResolver::new(&[wildcard, exact]).expect("resolver");
        assert!(Arc::ptr_eq(
            &resolver.resolve_name("api.example.test").expect("exact"),
            &exact_key
        ));
    }

    #[test]
    fn wildcard_matches_one_label_only() {
        let wildcard = identity("wildcard", "*.example.test", vec!["*.example.test".into()]);
        let resolver = CertificateResolver::new(&[wildcard]).expect("resolver");
        assert!(resolver.resolve_name("app.example.test").is_some());
        assert!(resolver.resolve_name("deep.app.example.test").is_none());
        assert!(resolver.resolve_name("example.test").is_none());
    }

    #[test]
    fn no_sni_fallback_exists() {
        let exact = identity("exact", "api.example.test", vec!["api.example.test".into()]);
        let resolver = CertificateResolver::new(&[exact]).expect("resolver");
        assert!(resolver.resolve_name("unknown.example.test").is_none());
    }

    #[test]
    fn replacement_is_atomic_and_old_keys_remain_valid() {
        let first = identity("first", "api.example.test", vec!["api.example.test".into()]);
        let resolver = CertificateResolver::new(&[first]).expect("resolver");
        let old_key = resolver.resolve_name("api.example.test").expect("old key");
        let second = identity(
            "second",
            "api.example.test",
            vec!["api.example.test".into()],
        );
        resolver.replace(&[second]).expect("replace");
        let new_key = resolver.resolve_name("api.example.test").expect("new key");
        assert!(!Arc::ptr_eq(&old_key, &new_key));
        assert!(!old_key.cert.is_empty());
    }
}
