use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aegisproxy_secrets::{SecretRef, encrypt_age};
use serde::{Deserialize, Serialize};
use x509_parser::parse_x509_certificate;

use crate::{
    TlsError,
    store::{identity_from_pem, parse_certificates},
};

const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 256 * 1024;
const MAX_ENCRYPTED_KEY_BYTES: usize = 512 * 1024;
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_ISSUER_BYTES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CertificatePointer {
    schema_version: u32,
    current: String,
    previous: Option<String>,
}

/// Public metadata for one immutable certificate generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCertificate {
    /// Stable configured certificate ID.
    pub id: String,
    /// Validated exact or wildcard names.
    pub hosts: Vec<String>,
    /// Immutable generation ID.
    pub generation: String,
    /// Certificate issuer display name.
    pub issuer: String,
    /// Certificate validity start as a Unix timestamp.
    pub not_before_unix_secs: i64,
    /// Certificate validity end as a Unix timestamp.
    pub not_after_unix_secs: i64,
    /// Import time as a Unix timestamp.
    pub imported_unix_secs: u64,
    /// Managed-certificate provenance; absent for manually imported identities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<ManagedCertificateProvenance>,
}

/// Operator-classified ACME environment recorded with a managed generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCertificateEnvironment {
    /// Test CA material that cannot replace production or manual material.
    Staging,
    /// Production CA material.
    Production,
}

/// Non-secret source metadata for a managed certificate generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCertificateProvenance {
    /// Stable configured ACME issuer ID.
    pub issuer_id: String,
    /// Explicit staging or production classification.
    pub environment: ManagedCertificateEnvironment,
    /// Optional CA profile used for the order.
    pub profile: Option<String>,
}

/// Result of a successful import, including safe configuration references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateImport {
    /// Imported public metadata.
    pub certificate: StoredCertificate,
    /// `file://` reference to the stored public certificate chain.
    pub certificate_chain: String,
    /// `file://` reference to the stored age-encrypted private key.
    pub private_key: String,
}

/// Validate and atomically import a new BYO certificate ID.
pub fn import_certificate(
    state_dir: &Path,
    id: &str,
    hosts: Vec<String>,
    certificate_chain: &str,
    private_key: &str,
    recipients: &[String],
) -> Result<CertificateImport, TlsError> {
    validate_id(id)?;
    if hosts.is_empty() || hosts.len() > 128 {
        return Err(TlsError::StoreFormat(
            "certificate hosts must contain 1 to 128 names".into(),
        ));
    }
    for host in &hosts {
        validate_host(host)?;
    }
    let certificate_pem = SecretRef::parse(certificate_chain)?.resolve(MAX_CERTIFICATE_BYTES)?;
    let private_key_pem = SecretRef::parse(private_key)?.resolve(MAX_PRIVATE_KEY_BYTES)?;
    identity_from_pem(
        id.to_owned(),
        hosts.clone(),
        certificate_pem.as_ref(),
        private_key_pem.as_ref(),
    )?;
    let (issuer, not_before_unix_secs, not_after_unix_secs) =
        parse_public_metadata(certificate_pem.as_ref())?;
    let generation = generation_id()?;
    let metadata = StoredCertificate {
        id: id.to_owned(),
        hosts,
        generation: generation.clone(),
        issuer,
        not_before_unix_secs,
        not_after_unix_secs,
        imported_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TlsError::StoreFormat("system clock predates Unix epoch".into()))?
            .as_secs(),
        managed: None,
    };
    let encrypted_key = encrypt_age(private_key_pem.as_ref(), recipients)?;
    let root = state_dir.join("certificates");
    create_private_dir(&root)?;
    let final_dir = root.join(id);
    if final_dir.exists() {
        return Err(TlsError::StoreFormat(format!(
            "certificate ID {id} already exists"
        )));
    }
    let staging = root.join(format!(".import-{id}-{}-{generation}", std::process::id()));
    create_private_dir(&staging)?;
    let result = write_generation(
        &staging,
        &metadata,
        certificate_pem.as_ref(),
        &encrypted_key,
    )
    .and_then(|()| fs::rename(&staging, &final_dir).map_err(TlsError::from))
    .and_then(|()| sync_directory(&root));
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result?;
    let generation_dir = fs::canonicalize(final_dir.join("generations").join(&generation))?;
    Ok(CertificateImport {
        certificate: metadata,
        certificate_chain: file_reference(&generation_dir.join("chain.pem")),
        private_key: file_reference(&generation_dir.join("key.age")),
    })
}

/// Validate, encrypt, and atomically activate one ACME-managed certificate generation.
pub fn persist_managed_certificate(
    state_dir: &Path,
    id: &str,
    hosts: Vec<String>,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    provenance: ManagedCertificateProvenance,
    recipients: &[String],
) -> Result<CertificateImport, TlsError> {
    validate_id(id)?;
    validate_hosts(&hosts)?;
    validate_managed_provenance(&provenance)?;
    if certificate_pem.is_empty()
        || certificate_pem.len() > MAX_CERTIFICATE_BYTES
        || private_key_pem.is_empty()
        || private_key_pem.len() > MAX_PRIVATE_KEY_BYTES
    {
        return Err(TlsError::StoreFormat(
            "managed certificate material exceeds its bound".into(),
        ));
    }
    identity_from_pem(
        id.to_owned(),
        hosts.clone(),
        certificate_pem,
        private_key_pem,
    )?;
    let (issuer, not_before_unix_secs, not_after_unix_secs) =
        parse_public_metadata(certificate_pem)?;
    let metadata = StoredCertificate {
        id: id.to_owned(),
        hosts,
        generation: generation_id()?,
        issuer,
        not_before_unix_secs,
        not_after_unix_secs,
        imported_unix_secs: unix_now()?,
        managed: Some(provenance),
    };
    let root = state_dir.join("certificates");
    create_private_dir(&root)?;
    let certificate_dir = root.join(id);
    if !certificate_dir.exists() {
        let encrypted_key = encrypt_age(private_key_pem, recipients)?;
        return persist_new_managed_certificate(
            &root,
            &certificate_dir,
            &metadata,
            certificate_pem,
            &encrypted_key,
        );
    }

    let active = inspect_certificate(state_dir, id)?;
    validate_managed_replacement(&active, &metadata)?;
    let encrypted_key = encrypt_age(private_key_pem, recipients)?;
    let previous_pointer = read_certificate_pointer(&certificate_dir)?;
    let generations_dir = certificate_dir.join("generations");
    create_private_dir(&generations_dir)?;
    let staging = generations_dir.join(format!(
        ".managed-{}-{}",
        std::process::id(),
        metadata.generation
    ));
    create_private_dir(&staging)?;
    let written = write_generation_payload(&staging, &metadata, certificate_pem, &encrypted_key)
        .and_then(|()| {
            fs::rename(&staging, generations_dir.join(&metadata.generation)).map_err(TlsError::from)
        })
        .and_then(|()| sync_directory(&generations_dir));
    if written.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    written?;

    let prepared_import = certificate_import(&certificate_dir, metadata.clone())?;
    write_certificate_pointer(
        &certificate_dir.join("current.json"),
        &CertificatePointer {
            schema_version: 1,
            current: metadata.generation.clone(),
            previous: Some(previous_pointer.current),
        },
    )?;
    Ok(prepared_import)
}

/// List all complete imported certificate IDs in stable order.
pub fn list_certificates(state_dir: &Path) -> Result<Vec<StoredCertificate>, TlsError> {
    let root = state_dir.join("certificates");
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut certificates = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        if id.starts_with('.') {
            continue;
        }
        certificates.push(inspect_certificate(state_dir, &id)?);
    }
    certificates.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(certificates)
}

/// Read and cross-check public metadata for one active certificate generation.
pub fn inspect_certificate(state_dir: &Path, id: &str) -> Result<StoredCertificate, TlsError> {
    validate_id(id)?;
    let certificate_dir = state_dir.join("certificates").join(id);
    let pointer = read_certificate_pointer(&certificate_dir)?;
    let metadata = inspect_generation(&certificate_dir, id, &pointer.current)?;
    if let Some(previous) = pointer.previous.as_deref() {
        inspect_generation(&certificate_dir, id, previous)?;
    }
    Ok(metadata)
}

fn inspect_generation(
    certificate_dir: &Path,
    id: &str,
    generation: &str,
) -> Result<StoredCertificate, TlsError> {
    validate_generation(generation)?;
    let generation_dir = certificate_dir.join("generations").join(generation);
    let metadata_path = generation_dir.join("metadata.toml");
    let metadata: StoredCertificate = toml::from_str(
        std::str::from_utf8(&read_bounded(&metadata_path, MAX_METADATA_BYTES)?)
            .map_err(|_| TlsError::StoreFormat("metadata is not UTF-8".into()))?,
    )
    .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    if metadata.id != id || metadata.generation != generation || metadata.hosts.is_empty() {
        return Err(TlsError::StoreFormat(
            "metadata does not match the active generation".into(),
        ));
    }
    validate_hosts(&metadata.hosts)?;
    if let Some(provenance) = metadata.managed.as_ref() {
        validate_managed_provenance(provenance)?;
    }
    let chain = read_bounded(&generation_dir.join("chain.pem"), MAX_CERTIFICATE_BYTES)?;
    let encrypted_key = read_bounded(&generation_dir.join("key.age"), MAX_ENCRYPTED_KEY_BYTES)?;
    if encrypted_key.is_empty() {
        return Err(TlsError::StoreFormat(
            "encrypted private key is empty".into(),
        ));
    }
    let (issuer, not_before, not_after) = parse_public_metadata(&chain)?;
    if metadata.issuer != issuer
        || metadata.not_before_unix_secs != not_before
        || metadata.not_after_unix_secs != not_after
    {
        return Err(TlsError::StoreFormat(
            "metadata does not match the active certificate".into(),
        ));
    }
    Ok(metadata)
}

/// Decrypt and revalidate the active private key for an offline recovery drill.
pub fn verify_stored_certificate(
    state_dir: &Path,
    id: &str,
    identity: &str,
) -> Result<StoredCertificate, TlsError> {
    let metadata = inspect_certificate(state_dir, id)?;
    let generation_dir = fs::canonicalize(
        state_dir
            .join("certificates")
            .join(id)
            .join("generations")
            .join(&metadata.generation),
    )?;
    crate::load_identity(
        id.to_owned(),
        metadata.hosts.clone(),
        &file_reference(&generation_dir.join("chain.pem")),
        &file_reference(&generation_dir.join("key.age")),
        identity,
    )?;
    Ok(metadata)
}

/// Decrypt, revalidate, and load the active stored generation for runtime use.
pub fn load_stored_identity(
    state_dir: &Path,
    id: &str,
    identity: &str,
) -> Result<crate::Identity, TlsError> {
    let metadata = inspect_certificate(state_dir, id)?;
    let generation_dir = fs::canonicalize(
        state_dir
            .join("certificates")
            .join(id)
            .join("generations")
            .join(&metadata.generation),
    )?;
    crate::load_identity(
        id.to_owned(),
        metadata.hosts,
        &file_reference(&generation_dir.join("chain.pem")),
        &file_reference(&generation_dir.join("key.age")),
        identity,
    )
}

/// Return active certificates expiring at or before `now + warning_window`.
pub fn scan_expiring_certificates(
    state_dir: &Path,
    now: SystemTime,
    warning_window: Duration,
) -> Result<Vec<StoredCertificate>, TlsError> {
    let deadline = now
        .checked_add(warning_window)
        .ok_or_else(|| TlsError::StoreFormat("expiry scan deadline overflow".into()))?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsError::StoreFormat("expiry scan predates Unix epoch".into()))?
        .as_secs();
    Ok(list_certificates(state_dir)?
        .into_iter()
        .filter(|certificate| {
            certificate.not_after_unix_secs >= 0
                && certificate.not_after_unix_secs as u64 <= deadline
        })
        .collect())
}

fn write_generation(
    staging: &Path,
    metadata: &StoredCertificate,
    certificate_pem: &[u8],
    encrypted_key: &[u8],
) -> Result<(), TlsError> {
    let generations = staging.join("generations");
    create_private_dir(&generations)?;
    let generation = generations.join(&metadata.generation);
    create_private_dir(&generation)?;
    write_generation_payload(&generation, metadata, certificate_pem, encrypted_key)?;
    sync_directory(&generations)?;
    write_certificate_pointer(
        &staging.join("current.json"),
        &CertificatePointer {
            schema_version: 1,
            current: metadata.generation.clone(),
            previous: None,
        },
    )?;
    Ok(())
}

fn write_generation_payload(
    generation: &Path,
    metadata: &StoredCertificate,
    certificate_pem: &[u8],
    encrypted_key: &[u8],
) -> Result<(), TlsError> {
    write_private_file(&generation.join("chain.pem"), certificate_pem)?;
    write_private_file(&generation.join("key.age"), encrypted_key)?;
    let metadata_toml =
        toml::to_string(metadata).map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    write_private_file(&generation.join("metadata.toml"), metadata_toml.as_bytes())?;
    sync_directory(generation)?;
    Ok(())
}

fn persist_new_managed_certificate(
    root: &Path,
    certificate_dir: &Path,
    metadata: &StoredCertificate,
    certificate_pem: &[u8],
    encrypted_key: &[u8],
) -> Result<CertificateImport, TlsError> {
    let staging = root.join(format!(
        ".managed-{}-{}-{}",
        metadata.id,
        std::process::id(),
        metadata.generation
    ));
    create_private_dir(&staging)?;
    let written = write_generation(&staging, metadata, certificate_pem, encrypted_key)
        .and_then(|()| fs::rename(&staging, certificate_dir).map_err(TlsError::from))
        .and_then(|()| sync_directory(root));
    if written.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    written?;
    certificate_import(certificate_dir, metadata.clone())
}

fn certificate_import(
    certificate_dir: &Path,
    metadata: StoredCertificate,
) -> Result<CertificateImport, TlsError> {
    let generation_dir = fs::canonicalize(
        certificate_dir
            .join("generations")
            .join(&metadata.generation),
    )?;
    Ok(CertificateImport {
        certificate: metadata,
        certificate_chain: file_reference(&generation_dir.join("chain.pem")),
        private_key: file_reference(&generation_dir.join("key.age")),
    })
}

fn validate_managed_replacement(
    active: &StoredCertificate,
    candidate: &StoredCertificate,
) -> Result<(), TlsError> {
    let candidate_provenance = candidate
        .managed
        .as_ref()
        .ok_or_else(|| TlsError::StoreFormat("managed provenance is missing".into()))?;
    if candidate_provenance.environment == ManagedCertificateEnvironment::Staging
        && !active.managed.as_ref().is_some_and(|provenance| {
            provenance.environment == ManagedCertificateEnvironment::Staging
        })
    {
        return Err(TlsError::StoreFormat(
            "staging certificate cannot replace active non-staging material".into(),
        ));
    }
    if candidate.not_after_unix_secs <= active.not_after_unix_secs {
        return Err(TlsError::StoreFormat(
            "managed certificate does not extend active expiry".into(),
        ));
    }
    let active_lifetime = active
        .not_after_unix_secs
        .checked_sub(active.not_before_unix_secs)
        .ok_or_else(|| TlsError::StoreFormat("active certificate lifetime is invalid".into()))?;
    let candidate_lifetime = candidate
        .not_after_unix_secs
        .checked_sub(candidate.not_before_unix_secs)
        .ok_or_else(|| TlsError::StoreFormat("candidate certificate lifetime is invalid".into()))?;
    const LIFETIME_TOLERANCE_SECS: i64 = 24 * 60 * 60;
    if candidate_lifetime
        .checked_add(LIFETIME_TOLERANCE_SECS)
        .is_none_or(|with_tolerance| with_tolerance < active_lifetime)
    {
        return Err(TlsError::StoreFormat(
            "managed certificate lifetime is unexpectedly shorter".into(),
        ));
    }
    Ok(())
}

fn validate_managed_provenance(provenance: &ManagedCertificateProvenance) -> Result<(), TlsError> {
    validate_id(&provenance.issuer_id)?;
    if let Some(profile) = provenance.profile.as_deref()
        && (profile.is_empty()
            || profile.len() > 64
            || !profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(TlsError::StoreFormat(
            "managed certificate profile is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_hosts(hosts: &[String]) -> Result<(), TlsError> {
    if hosts.is_empty() || hosts.len() > 128 {
        return Err(TlsError::StoreFormat(
            "certificate hosts must contain 1 to 128 names".into(),
        ));
    }
    for host in hosts {
        validate_host(host)?;
    }
    Ok(())
}

fn unix_now() -> Result<u64, TlsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsError::StoreFormat("system clock predates Unix epoch".into()))
        .map(|duration| duration.as_secs())
}

fn read_certificate_pointer(certificate_dir: &Path) -> Result<CertificatePointer, TlsError> {
    let path = certificate_dir.join("current.json");
    if path.exists() {
        let pointer: CertificatePointer =
            serde_json::from_slice(&read_bounded(&path, MAX_METADATA_BYTES)?)
                .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
        if pointer.schema_version != 1 {
            return Err(TlsError::StoreFormat(
                "unsupported certificate pointer version".into(),
            ));
        }
        validate_generation(&pointer.current)?;
        if let Some(previous) = pointer.previous.as_deref() {
            validate_generation(previous)?;
            if previous == pointer.current {
                return Err(TlsError::StoreFormat(
                    "certificate pointer generations are duplicated".into(),
                ));
            }
        }
        return Ok(pointer);
    }

    let legacy = String::from_utf8(read_bounded(&certificate_dir.join("current"), 128)?)
        .map_err(|_| TlsError::StoreFormat("legacy certificate pointer is not UTF-8".into()))?;
    let current = legacy.trim().to_owned();
    validate_generation(&current)?;
    Ok(CertificatePointer {
        schema_version: 1,
        current,
        previous: None,
    })
}

fn write_certificate_pointer(path: &Path, pointer: &CertificatePointer) -> Result<(), TlsError> {
    let bytes = serde_json::to_vec_pretty(pointer)
        .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    let temporary = path.with_file_name(format!(
        ".current-{}-{}.json",
        std::process::id(),
        generation_id()?
    ));
    write_private_file(&temporary, &bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_directory(
        path.parent()
            .ok_or_else(|| TlsError::StoreFormat("certificate pointer has no parent".into()))?,
    )
}

fn validate_generation(generation: &str) -> Result<(), TlsError> {
    if generation.is_empty()
        || generation.len() > 32
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(TlsError::StoreFormat(
            "invalid certificate generation".into(),
        ));
    }
    Ok(())
}

pub(crate) fn generation_id() -> Result<String, TlsError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsError::StoreFormat("system clock predates Unix epoch".into()))?
        .as_nanos()
        .to_string())
}

fn parse_public_metadata(pem: &[u8]) -> Result<(String, i64, i64), TlsError> {
    let certificates = parse_certificates(pem)?;
    let (_, certificate) = parse_x509_certificate(certificates[0].as_ref())
        .map_err(|error| TlsError::StoreFormat(error.to_string()))?;
    let issuer = certificate.issuer().to_string();
    if issuer.len() > MAX_ISSUER_BYTES || issuer.chars().any(char::is_control) {
        return Err(TlsError::StoreFormat("certificate issuer is unsafe".into()));
    }
    Ok((
        issuer,
        certificate.validity().not_before.timestamp(),
        certificate.validity().not_after.timestamp(),
    ))
}

pub(crate) fn validate_id(id: &str) -> Result<(), TlsError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || id.starts_with('-')
        || id.ends_with('-')
    {
        return Err(TlsError::StoreFormat(format!(
            "invalid certificate ID {id:?}"
        )));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), TlsError> {
    let name = host.strip_prefix("*.").unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || host != host.to_ascii_lowercase()
        || host.ends_with('.')
        || host.contains(':')
        || host.contains('*') && !host.starts_with("*.")
        || name.split('.').count() < 2
    {
        return Err(TlsError::StoreFormat(format!(
            "invalid certificate host {host:?}"
        )));
    }
    let probe = host
        .strip_prefix("*.")
        .map(|suffix| format!("a.{suffix}"))
        .unwrap_or_else(|| host.to_owned());
    rustls::pki_types::ServerName::try_from(probe)
        .map(|_| ())
        .map_err(|_| TlsError::StoreFormat(format!("invalid certificate host {host:?}")))
}

pub(crate) fn create_private_dir(path: &Path) -> Result<(), TlsError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), TlsError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, TlsError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(TlsError::StoreFormat(format!(
            "store file exceeds {max_bytes} bytes"
        )));
    }
    Ok(bytes)
}

fn file_reference(path: &Path) -> String {
    let path = path.to_string_lossy();
    #[cfg(windows)]
    let path = path.strip_prefix(r"\\?\").unwrap_or(&path);
    format!("file://{path}")
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> Result<(), TlsError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> Result<(), TlsError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::{secrecy::ExposeSecret, x25519};
    use rcgen::{CertificateParams, KeyPair, date_time_ymd};

    fn private_file(path: &Path, contents: &[u8]) {
        fs::write(path, contents).expect("write test file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure test file");
        }
    }

    #[test]
    fn import_restart_inspect_and_expiry_scan() {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-generation-{}-{}",
            std::process::id(),
            generation_id().expect("generation")
        ));
        fs::create_dir(&root).expect("create test root");
        let mut params = CertificateParams::new(vec!["example.test".into()]).expect("parameters");
        params.not_before = date_time_ymd(2025, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        let key = KeyPair::generate().expect("key");
        let certificate = params.self_signed(&key).expect("certificate");
        let certificate_path = root.join("source-cert.pem");
        let private_key_path = root.join("source-key.pem");
        let identity_path = root.join("identity.txt");
        private_file(&certificate_path, certificate.pem().as_bytes());
        private_file(&private_key_path, key.serialize_pem().as_bytes());
        let identity = x25519::Identity::generate();
        private_file(
            &identity_path,
            identity.to_string().expose_secret().as_bytes(),
        );
        let imported = import_certificate(
            &root,
            "site",
            vec!["example.test".into()],
            &file_reference(&certificate_path),
            &file_reference(&private_key_path),
            &[identity.to_public().to_string()],
        )
        .expect("import certificate");
        assert_eq!(list_certificates(&root).expect("list").len(), 1);
        assert_eq!(
            inspect_certificate(&root, "site").expect("inspect"),
            imported.certificate
        );
        let certificate_dir = root.join("certificates").join("site");
        assert!(certificate_dir.join("current.json").is_file());
        assert!(
            import_certificate(
                &root,
                "site",
                vec!["example.test".into()],
                &file_reference(&certificate_path),
                &file_reference(&private_key_path),
                &[identity.to_public().to_string()],
            )
            .is_err()
        );
        fs::remove_file(&private_key_path).expect("remove plaintext key");
        crate::load_identity(
            "site".into(),
            vec!["example.test".into()],
            &imported.certificate_chain,
            &imported.private_key,
            &file_reference(&identity_path),
        )
        .expect("restart load");
        let scan = scan_expiring_certificates(
            &root,
            UNIX_EPOCH + Duration::from_secs(1_880_000_000),
            Duration::from_secs(365 * 24 * 60 * 60),
        )
        .expect("scan");
        assert_eq!(scan.len(), 1);
        let pointer =
            fs::read_to_string(certificate_dir.join("current.json")).expect("read current pointer");
        let pointer: CertificatePointer = serde_json::from_str(&pointer).expect("parse pointer");
        fs::remove_file(certificate_dir.join("current.json")).expect("remove JSON pointer");
        private_file(&certificate_dir.join("current"), pointer.current.as_bytes());
        assert_eq!(
            inspect_certificate(&root, "site").expect("legacy pointer inspect"),
            imported.certificate
        );
        let generation_dir = certificate_dir
            .join("generations")
            .join(&imported.certificate.generation);
        let encrypted = fs::read(generation_dir.join("key.age")).expect("read envelope");
        assert!(
            !encrypted
                .windows(16)
                .any(|window| window == b"PRIVATE KEY-----")
        );
        private_file(&generation_dir.join("chain.pem"), b"tampered");
        assert!(inspect_certificate(&root, "site").is_err());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn managed_rotation_retains_previous_and_rejects_unsafe_replacements() {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-managed-generation-{}-{}",
            std::process::id(),
            generation_id().expect("generation")
        ));
        fs::create_dir(&root).expect("create test root");
        let identity = x25519::Identity::generate();
        let identity_path = root.join("identity.txt");
        private_file(
            &identity_path,
            identity.to_string().expose_secret().as_bytes(),
        );
        let recipients = vec![identity.to_public().to_string()];
        let provenance = ManagedCertificateProvenance {
            issuer_id: "pebble-production".into(),
            environment: ManagedCertificateEnvironment::Production,
            profile: None,
        };

        let (first_certificate, first_key) = managed_test_material(2020, 2030);
        let first = persist_managed_certificate(
            &root,
            "managed-site",
            vec!["example.test".into()],
            first_certificate.as_bytes(),
            first_key.as_bytes(),
            provenance.clone(),
            &recipients,
        )
        .expect("persist initial managed certificate");
        let (second_certificate, second_key) = managed_test_material(2020, 2031);
        let second = persist_managed_certificate(
            &root,
            "managed-site",
            vec!["example.test".into()],
            second_certificate.as_bytes(),
            second_key.as_bytes(),
            provenance.clone(),
            &recipients,
        )
        .expect("rotate managed certificate");
        let certificate_dir = root.join("certificates").join("managed-site");
        let pointer: CertificatePointer = serde_json::from_slice(
            &read_bounded(&certificate_dir.join("current.json"), MAX_METADATA_BYTES)
                .expect("read pointer"),
        )
        .expect("parse pointer");
        assert_eq!(pointer.current, second.certificate.generation);
        assert_eq!(
            pointer.previous.as_deref(),
            Some(first.certificate.generation.as_str())
        );
        assert!(
            certificate_dir
                .join("generations")
                .join(&first.certificate.generation)
                .is_dir()
        );
        assert_eq!(
            verify_stored_certificate(&root, "managed-site", &file_reference(&identity_path))
                .expect("verify rotated certificate"),
            second.certificate
        );
        let loaded = load_stored_identity(&root, "managed-site", &file_reference(&identity_path))
            .expect("load rotated identity");
        assert!(
            crate::CertificateResolver::new(&[loaded])
                .expect("resolver")
                .resolve_name("example.test")
                .is_some()
        );

        let (staging_certificate, staging_key) = managed_test_material(2020, 2032);
        let staging = ManagedCertificateProvenance {
            issuer_id: "pebble-staging".into(),
            environment: ManagedCertificateEnvironment::Staging,
            profile: None,
        };
        assert!(
            persist_managed_certificate(
                &root,
                "managed-site",
                vec!["example.test".into()],
                staging_certificate.as_bytes(),
                staging_key.as_bytes(),
                staging,
                &recipients,
            )
            .is_err()
        );

        let (short_certificate, short_key) = managed_test_material(2025, 2032);
        assert!(
            persist_managed_certificate(
                &root,
                "managed-site",
                vec!["example.test".into()],
                short_certificate.as_bytes(),
                short_key.as_bytes(),
                provenance,
                &recipients,
            )
            .is_err()
        );
        assert_eq!(
            inspect_certificate(&root, "managed-site").expect("active remains unchanged"),
            second.certificate
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    fn managed_test_material(not_before_year: i32, not_after_year: i32) -> (String, String) {
        let mut parameters =
            CertificateParams::new(vec!["example.test".into()]).expect("parameters");
        parameters.not_before = date_time_ymd(not_before_year, 1, 1);
        parameters.not_after = date_time_ymd(not_after_year, 1, 1);
        let key = KeyPair::generate().expect("key");
        let certificate = parameters.self_signed(&key).expect("certificate");
        (certificate.pem(), key.serialize_pem())
    }
}
