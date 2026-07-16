#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Administrative control-plane boundary.

/// Administrative API marker for the initial workspace.
#[derive(Clone, Debug, Default)]
pub struct AdminApi;
