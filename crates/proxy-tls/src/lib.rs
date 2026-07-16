#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! TLS boundary. Full certificate lifecycle lands in the TLS phase.

/// TLS policy marker for the initial workspace.
#[derive(Clone, Debug, Default)]
pub struct TlsPolicy;
