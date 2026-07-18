#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Administrative control-plane boundary.

mod audit;
mod auth;
mod backup;
mod rbac;

pub use audit::{AuditError, AuditEvent, AuditLog, AuditOutcome, AuditRecord};
pub use auth::{IssuedToken, TokenError, TokenMetadata, TokenRecord, TokenStore, TokenStoreError};
pub use backup::{BackupError, BackupSummary, create_backup, validate_backup};
pub use rbac::{Action, Role};

/// Administrative API marker for the initial workspace.
#[derive(Clone, Debug, Default)]
pub struct AdminApi;
