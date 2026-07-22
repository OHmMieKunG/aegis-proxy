#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Administrative control-plane boundary.

mod api;
mod audit;
mod auth;
mod backup;
mod compile;
mod rbac;
mod server;

pub use api::{
    API_VERSION, AccessPolicyRef, ApiObject, ApiVersion, AutomaticHttps, ContractError,
    ForwardProtocol, ObjectId, ObjectMetadata, ProxyHostSpec,
};
pub use audit::{AuditError, AuditEvent, AuditLog, AuditOutcome, AuditRecord};
pub use auth::{IssuedToken, TokenError, TokenMetadata, TokenRecord, TokenStore, TokenStoreError};
pub use backup::{BackupError, BackupSummary, create_backup, validate_backup};
pub use compile::{
    AccessPolicyMetadata, CompileContext, ManagedHttpsPolicy, ProxyHostCandidate,
    ProxyHostCompileError, compile_proxy_host,
};
pub use rbac::{Action, Role};
pub use server::{AdminServerError, serve};
