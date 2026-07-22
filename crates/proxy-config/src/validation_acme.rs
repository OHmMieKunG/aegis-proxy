use super::*;

pub(crate) fn validate_acme<'a>(
    config: &'a Config,
    certificate_ids: &mut HashSet<&'a str>,
    certificate_hosts: &mut HashSet<&'a str>,
) -> Result<(), ConfigError> {
    let acme = &config.acme;
    if acme.max_concurrent_orders == 0 || acme.max_concurrent_orders > 32 {
        return Err(ConfigError::Invalid(
            "acme.max_concurrent_orders is outside 1..=32".into(),
        ));
    }
    if let Some(owner) = acme.renewal_owner.as_deref() {
        valid_id(owner)?;
    }
    if acme.issuers.len() > MAX_ACME_ISSUERS
        || acme.certificates.len() > MAX_ACME_CERTIFICATES
        || acme.dns_providers.len() > MAX_ACME_DNS_PROVIDERS
        || config.certificates.len() + acme.certificates.len() > MAX_ACME_CERTIFICATES
    {
        return Err(ConfigError::Invalid(
            "ACME issuer, certificate, or DNS provider count exceeds its bound".into(),
        ));
    }

    let mut issuer_ids = HashSet::new();
    for issuer in &acme.issuers {
        valid_id(&issuer.id)?;
        if !issuer_ids.insert(issuer.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate ACME issuer id {}",
                issuer.id
            )));
        }
        validate_acme_directory(issuer)?;
        if let Some(email) = issuer.account_email.as_deref()
            && (email.is_empty()
                || email.len() > 254
                || !email.is_ascii()
                || email.chars().any(char::is_control)
                || email.matches('@').count() != 1)
        {
            return Err(ConfigError::Invalid(format!(
                "ACME issuer {} has an invalid account_email",
                issuer.id
            )));
        }
        if let Some(ca_bundle) = issuer.ca_bundle.as_deref() {
            SecretRef::parse(ca_bundle).map_err(|_| {
                ConfigError::Invalid(format!(
                    "ACME issuer {} has an invalid ca_bundle secret reference",
                    issuer.id
                ))
            })?;
        }
        if let Some(external) = &issuer.external_account {
            if external.key_id.is_empty()
                || external.key_id.len() > 256
                || external.key_id.chars().any(char::is_control)
            {
                return Err(ConfigError::Invalid(format!(
                    "ACME issuer {} has an invalid external account key ID",
                    issuer.id
                )));
            }
            SecretRef::parse(&external.hmac_key).map_err(|_| {
                ConfigError::Invalid(format!(
                    "ACME issuer {} has an invalid external account HMAC secret reference",
                    issuer.id
                ))
            })?;
        }
        if issuer.max_concurrent_orders == 0
            || issuer.max_concurrent_orders > acme.max_concurrent_orders
        {
            return Err(ConfigError::Invalid(format!(
                "ACME issuer {} order limit exceeds the global bound",
                issuer.id
            )));
        }
    }

    let mut provider_ids = HashSet::new();
    for provider in &acme.dns_providers {
        valid_id(provider.id())?;
        if !provider_ids.insert(provider.id()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate ACME DNS provider id {}",
                provider.id()
            )));
        }
        match provider {
            AcmeDnsProviderConfig::Cloudflare {
                id,
                zone_id,
                api_token,
            } => {
                if zone_id.len() != 32
                    || !zone_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                {
                    return Err(ConfigError::Invalid(format!(
                        "ACME DNS provider {id} has an invalid Cloudflare zone_id"
                    )));
                }
                SecretRef::parse(api_token).map_err(|_| {
                    ConfigError::Invalid(format!(
                        "ACME DNS provider {id} has an invalid api_token secret reference"
                    ))
                })?;
            }
        }
    }

    for certificate in &acme.certificates {
        valid_id(&certificate.id)?;
        if !certificate_ids.insert(certificate.id.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "duplicate certificate id {}",
                certificate.id
            )));
        }
        if certificate.hosts.is_empty() || certificate.hosts.len() > 64 {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} must contain 1..=64 hosts",
                certificate.id
            )));
        }
        for host in &certificate.hosts {
            valid_certificate_host(host)?;
            if !certificate_hosts.insert(host.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "certificate host {host} is assigned more than once"
                )));
            }
            if host.starts_with("*.") && certificate.challenge != AcmeChallenge::Dns01 {
                return Err(ConfigError::Invalid(format!(
                    "ACME wildcard {host} requires dns-01"
                )));
            }
        }
        if !issuer_ids.contains(certificate.issuer.as_str()) {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} references unknown issuer {}",
                certificate.id, certificate.issuer
            )));
        }
        if acme
            .issuers
            .iter()
            .find(|issuer| issuer.id == certificate.issuer)
            .is_some_and(|issuer| !issuer.terms_of_service_agreed)
        {
            return Err(ConfigError::Invalid(format!(
                "ACME issuer {} requires explicit terms_of_service_agreed = true",
                certificate.issuer
            )));
        }
        validate_acme_challenge(config, certificate, &provider_ids)?;
        if let Some(profile) = certificate.profile.as_deref()
            && (profile.is_empty()
                || profile.len() > 64
                || !profile
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} has an invalid profile",
                certificate.id
            )));
        }
        if !(1..=90).contains(&certificate.renew_before_days) {
            return Err(ConfigError::Invalid(format!(
                "ACME certificate {} renew_before_days is outside 1..=90",
                certificate.id
            )));
        }
    }

    if !acme.certificates.is_empty() {
        if config.tls.identity.is_none() {
            return Err(ConfigError::Invalid(
                "tls.identity is required for encrypted ACME state".into(),
            ));
        }
        if config.tls.state_encryption_recipients.is_empty()
            || config.tls.state_encryption_recipients.len() > 8
        {
            return Err(ConfigError::Invalid(
                "tls.state_encryption_recipients must contain 1..=8 recipients for ACME".into(),
            ));
        }
        for recipient in &config.tls.state_encryption_recipients {
            validate_age_recipient(recipient).map_err(|_| {
                ConfigError::Invalid("tls.state_encryption_recipients is invalid".into())
            })?;
        }
    }
    Ok(())
}

fn validate_acme_directory(issuer: &AcmeIssuerConfig) -> Result<(), ConfigError> {
    let url = &issuer.directory_url;
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host_str().is_none()
    {
        return Err(ConfigError::Invalid(format!(
            "ACME issuer {} directory_url contains forbidden URL components",
            issuer.id
        )));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    let valid_transport = url.scheme() == "https"
        || issuer.environment == AcmeEnvironment::Staging && url.scheme() == "http" && loopback;
    if !valid_transport {
        return Err(ConfigError::Invalid(format!(
            "ACME issuer {} directory_url must use HTTPS; staging permits loopback HTTP only",
            issuer.id
        )));
    }
    Ok(())
}

fn validate_acme_challenge(
    config: &Config,
    certificate: &AcmeCertificateConfig,
    provider_ids: &HashSet<&str>,
) -> Result<(), ConfigError> {
    match certificate.challenge {
        AcmeChallenge::Dns01 => {
            if certificate.challenge_listener.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} dns-01 cannot set challenge_listener",
                    certificate.id
                )));
            }
            let provider = certificate.dns_provider.as_deref().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "ACME certificate {} dns-01 requires dns_provider",
                    certificate.id
                ))
            })?;
            if !provider_ids.contains(provider) {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} references unknown DNS provider {provider}",
                    certificate.id
                )));
            }
        }
        AcmeChallenge::Http01 | AcmeChallenge::TlsAlpn01 => {
            if certificate.dns_provider.is_some() {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} non-DNS challenge cannot set dns_provider",
                    certificate.id
                )));
            }
            let listener_id = certificate.challenge_listener.as_deref().ok_or_else(|| {
                ConfigError::Invalid(format!(
                    "ACME certificate {} requires challenge_listener",
                    certificate.id
                ))
            })?;
            let listener = config
                .listeners
                .iter()
                .find(|listener| listener.id == listener_id)
                .ok_or_else(|| {
                    ConfigError::Invalid(format!(
                        "ACME certificate {} references unknown challenge listener {listener_id}",
                        certificate.id
                    ))
                })?;
            let expected = if certificate.challenge == AcmeChallenge::Http01 {
                "http"
            } else {
                "https"
            };
            if listener.protocol != expected {
                return Err(ConfigError::Invalid(format!(
                    "ACME certificate {} challenge listener must use {expected}",
                    certificate.id
                )));
            }
        }
    }
    Ok(())
}
