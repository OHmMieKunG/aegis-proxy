#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Administrative control-plane boundary.

mod auth;
mod rbac;

pub use auth::{IssuedToken, TokenError, TokenRecord};
pub use rbac::{Action, Role};

/// Administrative API marker for the initial workspace.
#[derive(Clone, Debug, Default)]
pub struct AdminApi;
