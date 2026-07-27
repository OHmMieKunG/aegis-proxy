#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Administrative control-plane boundary.

mod access_policy;
mod api;
mod audit;
mod auth;
mod backup;
mod compile;
mod diff;
mod object_store;
mod preview;
mod proxy_host;
mod rbac;
mod server;

pub use access_policy::{
    AccessPolicyCompileError, AccessPolicyMetadata, compile_access_policy_metadata,
};
pub use api::{
    API_VERSION, AccessPolicyRef, AccessPolicySpec, ApiObject, ApiVersion, AutomaticHttps,
    ContractError, ForwardProtocol, MiddlewareRef, ObjectId, ObjectMetadata, ProxyHostSpec,
};
pub use audit::{AuditError, AuditEvent, AuditLog, AuditOutcome, AuditRecord};
pub use auth::{IssuedToken, TokenError, TokenMetadata, TokenRecord, TokenStore, TokenStoreError};
pub use backup::{BackupError, BackupSummary, create_backup, validate_backup};
pub use compile::{
    CompileContext, ManagedHttpsPolicy, ProxyHostCandidate, ProxyHostCompileError,
    ProxyHostSetCandidate, ProxyHostSetCompileContext, compile_proxy_host, compile_proxy_hosts,
};
pub use diff::{
    DiffOperation, ProxyHostDiff, ProxyHostDiffError, ProxyHostDiffValue, ProxyHostField,
    ProxyHostFieldChange, diff_proxy_host_previews,
};
pub use object_store::{
    BoundProxyHostCandidate, ProxyHostClaims, ProxyHostSnapshot, ProxyHostStore,
    ProxyHostStoreError, StoredProxyHost,
};
pub use preview::{
    CandidateActivation, GeneratedProxyHostPreview, ProxyHostCandidatePreview,
    ProxyHostPreviewError, ProxyHostPreviewSummary, preview_proxy_host_candidate,
};
pub use proxy_host::{PreparedProxyHost, ProxyHostPreparationError, prepare_proxy_host};
pub use rbac::{Action, Role, TokenScopeError, TokenScopes};
pub use server::{AdminServerError, serve};
