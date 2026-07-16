use std::io::{BufReader, Read, Write};

use age::{Decryptor, Encryptor, x25519};

use crate::{SecretBytes, SecretError};

const MAX_RECIPIENTS: usize = 8;
const MAX_IDENTITIES: usize = 8;

/// Encrypt secret bytes to one or more age X25519 recipients.
pub fn encrypt_age(plaintext: &[u8], recipients: &[String]) -> Result<Vec<u8>, SecretError> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(SecretError::Envelope);
    }
    let recipients: Result<Vec<x25519::Recipient>, _> =
        recipients.iter().map(|value| value.parse()).collect();
    let recipients = recipients.map_err(|_| SecretError::Envelope)?;
    let encryptor = Encryptor::with_recipients(
        recipients
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient),
    )
    .map_err(|_| SecretError::Envelope)?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| SecretError::Envelope)?;
    writer
        .write_all(plaintext)
        .map_err(|_| SecretError::Envelope)?;
    writer.finish().map_err(|_| SecretError::Envelope)?;
    Ok(ciphertext)
}

/// Decrypt a bounded age envelope using injected X25519 identity lines.
pub fn decrypt_age(
    ciphertext: &[u8],
    identity_source: &[u8],
    max_plaintext: usize,
) -> Result<SecretBytes, SecretError> {
    let identity_text = std::str::from_utf8(identity_source).map_err(|_| SecretError::Envelope)?;
    let identities: Result<Vec<x25519::Identity>, _> = identity_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::parse)
        .collect();
    let identities = identities.map_err(|_| SecretError::Envelope)?;
    if identities.is_empty() || identities.len() > MAX_IDENTITIES {
        return Err(SecretError::Envelope);
    }
    let decryptor =
        Decryptor::new_buffered(BufReader::new(ciphertext)).map_err(|_| SecretError::Envelope)?;
    let mut reader = decryptor
        .decrypt(
            identities
                .iter()
                .map(|identity| identity as &dyn age::Identity),
        )
        .map_err(|_| SecretError::Envelope)?;
    let mut plaintext = Vec::new();
    reader
        .by_ref()
        .take(max_plaintext.saturating_add(1) as u64)
        .read_to_end(&mut plaintext)
        .map_err(|_| SecretError::Envelope)?;
    if plaintext.len() > max_plaintext {
        return Err(SecretError::TooLarge(max_plaintext));
    }
    Ok(SecretBytes::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    #[test]
    fn encrypted_envelope_round_trips_without_plaintext_canary() {
        let identity = x25519::Identity::generate();
        let recipients = vec![identity.to_public().to_string()];
        let ciphertext = encrypt_age(b"private-key-canary", &recipients).expect("encrypt");
        assert!(
            !ciphertext
                .windows(b"private-key-canary".len())
                .any(|window| window == b"private-key-canary")
        );
        let identity_text = identity.to_string();
        let plaintext = decrypt_age(&ciphertext, identity_text.expose_secret().as_bytes(), 1024)
            .expect("decrypt");
        assert_eq!(plaintext.as_ref(), b"private-key-canary");
    }

    #[test]
    fn wrong_identity_and_oversized_plaintext_fail_closed() {
        let identity = x25519::Identity::generate();
        let ciphertext = encrypt_age(b"private-key-canary", &[identity.to_public().to_string()])
            .expect("encrypt");
        let wrong = x25519::Identity::generate().to_string();
        assert!(decrypt_age(&ciphertext, wrong.expose_secret().as_bytes(), 1024).is_err());
        let correct = identity.to_string();
        assert!(matches!(
            decrypt_age(&ciphertext, correct.expose_secret().as_bytes(), 4),
            Err(SecretError::TooLarge(4))
        ));
    }
}
