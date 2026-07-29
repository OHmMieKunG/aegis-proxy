#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Administrative control-plane boundary.

mod access_policy;
mod api;
mod audit;
mod auth;
mod backup;
mod certificate;
mod compile;
mod credential;
mod diff;
mod discovery_source;
mod object_store;
mod preview;
mod proxy_host;
mod rbac;
mod server;
mod startup;
mod stream_host;
mod typed_store;
mod user;

pub use access_policy::{
    AccessPolicyCompileError, AccessPolicyMetadata, AccessPolicyStore, AccessPolicyStoreError,
    StoredAccessPolicy, compile_access_policy_metadata,
};
pub use api::{
    API_VERSION, AccessPolicyRef, AccessPolicySpec, ApiObject, ApiVersion, AutomaticHttps,
    CertificateRef, CertificateSpec, ContractError, DiscoverySourceSpec, ForwardProtocol,
    MiddlewareRef, ObjectId, ObjectMetadata, ProxyHostSpec, StreamHostSpec, StreamProtocol,
};
pub use audit::{AuditError, AuditEvent, AuditLog, AuditOutcome, AuditRecord};
pub use auth::{IssuedToken, TokenError, TokenMetadata, TokenRecord, TokenStore, TokenStoreError};
pub use backup::{BackupError, BackupSummary, create_backup, validate_backup};
pub use certificate::{
    CertificateCompileError, CertificateMetadata, CertificateStore, CertificateStoreError,
    StoredCertificate, compile_certificate_metadata, select_managed_https_policy,
};
pub use compile::{
    CompileContext, ManagedHttpsPolicy, ProxyHostCandidate, ProxyHostCompileError,
    ProxyHostSetCandidate, ProxyHostSetCompileContext, compile_proxy_host, compile_proxy_hosts,
};
pub use credential::{
    CredentialReplacement, CredentialStore, CredentialStoreError, StoredCredential,
};
pub use diff::{
    DiffOperation, ProxyHostDiff, ProxyHostDiffError, ProxyHostDiffValue, ProxyHostField,
    ProxyHostFieldChange, diff_proxy_host_previews,
};
pub use discovery_source::{
    DiscoverySourceCompileError, DiscoverySourceStore, DiscoverySourceStoreError,
    StoredDiscoverySource, compile_discovery_sources,
};
pub use object_store::{
    BoundProxyHostCandidate, ProxyHostClaims, ProxyHostSnapshot, ProxyHostStore,
    ProxyHostStoreError, StoredProxyHost, UnifiedCandidateState,
};
pub use preview::{
    CandidateActivation, GeneratedProxyHostPreview, ProxyHostCandidatePreview,
    ProxyHostPreviewError, ProxyHostPreviewSummary, preview_proxy_host_candidate,
};
pub use proxy_host::{PreparedProxyHost, ProxyHostPreparationError, prepare_proxy_host};
pub use rbac::{Action, Role, TokenScopeError, TokenScopes};
pub use server::{AdminServerError, WebAsset, WebAssetLoader, serve, serve_with_web_assets};
pub use startup::{ReconciledStartup, StartupReconcileError, reconcile_startup};
pub use stream_host::{
    StoredStreamHost, StreamHostCompileError, StreamHostStore, StreamHostStoreError,
    compile_stream_hosts,
};
pub use user::{StoredUser, UserSpec, UserStore, UserStoreError};
