//! Fixed-stage request and response middleware.

pub(crate) mod auth;
pub(crate) mod compression;
pub(crate) mod cors;
pub(crate) mod custom_error;
pub(crate) mod headers;
pub(crate) mod ip;
pub(crate) mod maintenance;
pub(crate) mod normalize;
pub(crate) mod rate;
pub(crate) mod redirect;
pub(crate) mod rewrite;
