//! Feature-gated entry points for out-of-workspace fuzz targets.

/// Exercise strict stored-certificate metadata parsing and validation.
pub fn certificate_metadata(input: &[u8]) {
    if input.len() > super::generation::MAX_METADATA_BYTES {
        return;
    }
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let Ok(metadata) = toml::from_str::<super::StoredCertificate>(text) else {
        return;
    };
    let _ = super::generation::validate_id(&metadata.id);
    let _ = super::generation::validate_generation(&metadata.generation);
    let _ = super::generation::validate_hosts(&metadata.hosts);
    if let Some(provenance) = metadata.managed.as_ref() {
        let _ = super::generation::validate_managed_provenance(provenance);
    }
}
