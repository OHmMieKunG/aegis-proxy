//! ACME challenge and certificate-lifecycle primitives.

mod account;
mod challenge;
mod client;
mod dns_provider;
mod order;
mod scheduler;
mod transport;

pub use account::{
    AcmeAccountError, StoredAcmeAccount, StoredAcmeEnvironment, decrypt_account_credentials,
    encrypt_account_credentials, load_account_generation, persist_account_generation,
};
pub use challenge::{
    HttpChallengeError, HttpChallengeLease, HttpChallengeRegistry, TlsAlpnChallengeError,
    TlsAlpnChallengeLease, TlsAlpnChallengeRegistry, tls_alpn_protocol,
};
pub use client::{
    AcmeAccountCreateRequest, AcmeClient, AcmeClientError, AcmeExternalAccountBinding,
};
pub use dns_provider::{CloudflareDnsProvider, CloudflareDnsRecord, DnsProviderError};
pub use order::{
    AcmeChallengeKind, AcmeChallengeMaterial, AcmeIssuedCertificate, AcmeOrder, AcmeOrderError,
    AcmeOrderRequest,
};
pub use scheduler::{
    RenewalSchedule, RenewalScheduleError, expiry_alert_days, fallback_renewal_schedule,
    retry_delay,
};
