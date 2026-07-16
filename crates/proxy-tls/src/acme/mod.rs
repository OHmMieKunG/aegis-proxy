//! ACME challenge and certificate-lifecycle primitives.

mod challenge;

pub use challenge::{HttpChallengeError, HttpChallengeLease, HttpChallengeRegistry};
