use std::{fmt, sync::Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ObjectId;

const TOKEN_BYTES: usize = 32;
pub(super) const TOKEN_TTL_SECS: u64 = 10 * 60;

#[derive(Clone)]
struct SetupToken {
    digest: [u8; 32],
    owner_id: ObjectId,
    expires_unix_secs: u64,
}

impl fmt::Debug for SetupToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SetupToken")
            .field(
                "digest",
                &format_args!("[REDACTED; {} bytes]", self.digest.len()),
            )
            .field("owner_id", &self.owner_id)
            .field("expires_unix_secs", &self.expires_unix_secs)
            .finish()
    }
}

pub(super) struct WebSetupTokens(Mutex<Option<SetupToken>>);

pub(super) struct PreparedWebSetupToken {
    plaintext: Zeroizing<String>,
    record: SetupToken,
}

impl WebSetupTokens {
    pub(super) fn new() -> Self {
        Self(Mutex::new(None))
    }

    pub(super) fn prepare(owner_id: ObjectId, now_unix_secs: u64) -> Option<PreparedWebSetupToken> {
        let expires_unix_secs = now_unix_secs.checked_add(TOKEN_TTL_SECS)?;
        let mut random = Zeroizing::new([0_u8; TOKEN_BYTES]);
        getrandom::fill(&mut *random).ok()?;
        let plaintext = Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_ref()));
        Some(PreparedWebSetupToken {
            record: SetupToken {
                digest: Sha256::digest(plaintext.as_bytes()).into(),
                owner_id,
                expires_unix_secs,
            },
            plaintext,
        })
    }

    pub(super) fn install(&self, prepared: &PreparedWebSetupToken) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(prepared.record.clone());
    }

    pub(super) fn is_active(&self, now_unix_secs: u64) -> bool {
        let mut token = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if token
            .as_ref()
            .is_some_and(|token| now_unix_secs >= token.expires_unix_secs)
        {
            *token = None;
        }
        token.is_some()
    }
}

impl PreparedWebSetupToken {
    pub(super) fn plaintext(&self) -> &str {
        self.plaintext.as_str()
    }

    pub(super) fn owner_id(&self) -> &ObjectId {
        &self.record.owner_id
    }

    pub(super) fn expires_unix_secs(&self) -> u64 {
        self.record.expires_unix_secs
    }
}

impl fmt::Debug for PreparedWebSetupToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWebSetupToken")
            .field("plaintext", &"[REDACTED]")
            .field("record", &self.record)
            .finish()
    }
}

impl fmt::Debug for WebSetupTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("WebSetupTokens")
            .field(
                &*self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
            .finish()
    }
}

#[cfg(test)]
impl WebSetupTokens {
    fn consume(&self, presented: &str, now_unix_secs: u64) -> Option<ObjectId> {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let mut token = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let matches = token
            .as_ref()
            .is_some_and(|token| now_unix_secs < token.expires_unix_secs && token.digest == digest);
        matches.then(|| token.take().expect("matched setup token").owner_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_token_is_hash_only_bounded_one_use_and_replaced() {
        let tokens = WebSetupTokens::new();
        let owner: ObjectId = "uid-1000".parse().expect("owner");
        let first = WebSetupTokens::prepare(owner.clone(), 100).expect("first token");
        assert_eq!(first.plaintext().len(), 43);
        assert_eq!(first.expires_unix_secs(), 700);
        tokens.install(&first);
        assert!(tokens.is_active(699));

        let second = WebSetupTokens::prepare(owner.clone(), 200).expect("second token");
        assert_ne!(first.plaintext(), second.plaintext());
        tokens.install(&second);
        assert!(tokens.consume(first.plaintext(), 200).is_none());
        assert_eq!(tokens.consume(second.plaintext(), 200), Some(owner));
        assert!(tokens.consume(second.plaintext(), 200).is_none());
        assert!(!format!("{tokens:?}").contains(second.plaintext()));

        let expiring =
            WebSetupTokens::prepare("uid-1000".parse().expect("owner"), 300).expect("token");
        tokens.install(&expiring);
        assert!(!tokens.is_active(900));
        assert!(WebSetupTokens::prepare("uid-1000".parse().expect("owner"), u64::MAX).is_none());
    }
}
