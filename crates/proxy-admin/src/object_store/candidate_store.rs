use super::*;

impl ProxyHostStore {
    /// Return the canonical typed desired-state hash used by revision metadata.
    pub fn binding_hash(
        objects: &[ApiObject<ProxyHostSpec>],
    ) -> Result<String, ProxyHostStoreError> {
        let objects = canonical_objects(objects)?;
        let bytes = serde_json::to_vec(&ProxyHostBinding {
            schema_version: STORE_SCHEMA_VERSION,
            objects: &objects,
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Return canonical hash of desired Proxy Hosts and referenced Access Policy generations.
    pub fn binding_hash_with_access_policies(
        objects: &[ApiObject<ProxyHostSpec>],
        access_policies: &[StoredAccessPolicy],
    ) -> Result<String, ProxyHostStoreError> {
        if access_policies.is_empty() {
            return Self::binding_hash(objects);
        }
        let objects = canonical_objects(objects)?;
        let access_policies = canonical_access_policies(access_policies)?;
        let bytes = serde_json::to_vec(&ProxyHostPolicyBinding {
            schema_version: STORE_SCHEMA_VERSION,
            objects: &objects,
            access_policies: &access_policies,
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Return canonical schema-2 hash across every typed desired-state domain and dependency.
    pub fn unified_binding_hash(
        proxy_hosts: &[ApiObject<ProxyHostSpec>],
        stream_hosts: &[ApiObject<StreamHostSpec>],
        discovery_sources: &[ApiObject<DiscoverySourceSpec>],
        access_policies: &[StoredAccessPolicy],
        certificates: &[StoredCertificate],
    ) -> Result<String, ProxyHostStoreError> {
        let proxy_hosts = canonical_objects(proxy_hosts)?;
        let stream_hosts = canonical_stream_hosts(stream_hosts)?;
        let discovery_sources = canonical_discovery_sources(discovery_sources)?;
        let access_policies = canonical_access_policies(access_policies)?;
        let certificates = canonical_certificates(certificates)?;
        let bytes = serde_json::to_vec(&UnifiedBinding {
            schema_version: CANDIDATE_SCHEMA_V2,
            proxy_hosts: &proxy_hosts,
            stream_hosts: &stream_hosts,
            discovery_sources: &discovery_sources,
            access_policies: &access_policies,
            certificates: &certificates,
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Persist one immutable typed desired-state snapshot for a revision.
    pub fn bind_candidate(
        &self,
        revision_id: &str,
        expected_hash: &str,
        objects: &[ApiObject<ProxyHostSpec>],
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        self.bind_candidate_with_access_policies(revision_id, expected_hash, objects, &[])
    }

    /// Persist one immutable desired-state snapshot with Access Policy dependencies.
    pub fn bind_candidate_with_access_policies(
        &self,
        revision_id: &str,
        expected_hash: &str,
        objects: &[ApiObject<ProxyHostSpec>],
        access_policies: &[StoredAccessPolicy],
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        validate_revision_id(revision_id)?;
        let objects = canonical_objects(objects)?;
        let access_policies = canonical_access_policies(access_policies)?;
        let binding_hash = Self::binding_hash_with_access_policies(&objects, &access_policies)?;
        if binding_hash != expected_hash {
            return Err(ProxyHostStoreError::Invalid);
        }
        create_private_directory(&self.candidate_dir)?;
        let path = self.candidate_path(revision_id);
        if path.exists() {
            let existing = self.load_candidate(revision_id, expected_hash)?;
            if existing.objects == objects && existing.access_policies == access_policies {
                return Ok(existing);
            }
            return Err(ProxyHostStoreError::Conflict);
        }
        if directory_entry_count(&self.candidate_dir)? >= MAX_CANDIDATE_SNAPSHOTS {
            return Err(ProxyHostStoreError::Limit);
        }
        let bytes = serde_json::to_vec_pretty(&ProxyHostCandidateFile {
            schema_version: CANDIDATE_SCHEMA_V1,
            revision_id: revision_id.to_owned(),
            binding_hash: binding_hash.clone(),
            objects: objects.clone(),
            access_policies: access_policies.clone(),
            stream_hosts: Vec::new(),
            discovery_sources: Vec::new(),
            certificates: Vec::new(),
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        write_private_file(&path, &bytes)?;
        File::open(&self.candidate_dir)?.sync_all()?;
        Ok(BoundProxyHostCandidate {
            schema_version: CANDIDATE_SCHEMA_V1,
            binding_hash,
            objects,
            stream_hosts: Vec::new(),
            discovery_sources: Vec::new(),
            access_policies,
            certificates: Vec::new(),
        })
    }

    /// Persist one immutable schema-2 snapshot across every typed domain.
    pub fn bind_unified_candidate(
        &self,
        revision_id: &str,
        expected_hash: &str,
        state: UnifiedCandidateState<'_>,
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        validate_revision_id(revision_id)?;
        let proxy_hosts = canonical_objects(state.proxy_hosts)?;
        let stream_hosts = canonical_stream_hosts(state.stream_hosts)?;
        let discovery_sources = canonical_discovery_sources(state.discovery_sources)?;
        let access_policies = canonical_access_policies(state.access_policies)?;
        let certificates = canonical_certificates(state.certificates)?;
        let binding_hash = Self::unified_binding_hash(
            &proxy_hosts,
            &stream_hosts,
            &discovery_sources,
            &access_policies,
            &certificates,
        )?;
        if binding_hash != expected_hash {
            return Err(ProxyHostStoreError::Invalid);
        }
        create_private_directory(&self.candidate_dir)?;
        let path = self.candidate_path(revision_id);
        if path.exists() {
            let existing = self.load_candidate(revision_id, expected_hash)?;
            if existing.schema_version == CANDIDATE_SCHEMA_V2
                && existing.objects == proxy_hosts
                && existing.stream_hosts == stream_hosts
                && existing.discovery_sources == discovery_sources
                && existing.access_policies == access_policies
                && existing.certificates == certificates
            {
                return Ok(existing);
            }
            return Err(ProxyHostStoreError::Conflict);
        }
        if directory_entry_count(&self.candidate_dir)? >= MAX_CANDIDATE_SNAPSHOTS {
            return Err(ProxyHostStoreError::Limit);
        }
        let bytes = serde_json::to_vec_pretty(&ProxyHostCandidateFile {
            schema_version: CANDIDATE_SCHEMA_V2,
            revision_id: revision_id.into(),
            binding_hash: binding_hash.clone(),
            objects: proxy_hosts.clone(),
            access_policies: access_policies.clone(),
            stream_hosts: stream_hosts.clone(),
            discovery_sources: discovery_sources.clone(),
            certificates: certificates.clone(),
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        write_private_file(&path, &bytes)?;
        File::open(&self.candidate_dir)?.sync_all()?;
        Ok(BoundProxyHostCandidate {
            schema_version: CANDIDATE_SCHEMA_V2,
            binding_hash,
            objects: proxy_hosts,
            stream_hosts,
            discovery_sources,
            access_policies,
            certificates,
        })
    }

    /// Load and verify a revision-bound typed desired-state snapshot.
    pub fn load_candidate(
        &self,
        revision_id: &str,
        expected_hash: &str,
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        let candidate = self.load_candidate_file(revision_id)?;
        if candidate.binding_hash != expected_hash {
            return Err(ProxyHostStoreError::Invalid);
        }
        Ok(candidate)
    }

    /// Remove valid typed snapshots only after their authoritative revisions are gone.
    pub fn reconcile_candidates(
        &self,
        retained_revisions: &[RevisionMetadata],
    ) -> Result<usize, ProxyHostStoreError> {
        let mut retained = BTreeMap::new();
        for revision in retained_revisions {
            validate_revision_id(&revision.id)?;
            if revision
                .binding_hash
                .as_deref()
                .is_some_and(|hash| !valid_binding_hash(hash))
            {
                return Err(ProxyHostStoreError::Invalid);
            }
            if retained
                .insert(revision.id.as_str(), revision.binding_hash.as_deref())
                .is_some()
            {
                return Err(ProxyHostStoreError::Invalid);
            }
        }
        let metadata = match fs::symlink_metadata(&self.candidate_dir) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ProxyHostStoreError::Invalid);
        }
        reject_insecure_directory_permissions(&metadata)?;

        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.candidate_dir)? {
            entries.push(entry?);
            if entries.len() > MAX_CANDIDATE_SNAPSHOTS {
                return Err(ProxyHostStoreError::Limit);
            }
        }
        entries.sort_unstable_by_key(fs::DirEntry::file_name);

        let mut stale = Vec::new();
        for entry in entries {
            if !entry.file_type()?.is_file() {
                return Err(ProxyHostStoreError::Invalid);
            }
            let file_name = entry.file_name();
            let revision_id = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .ok_or(ProxyHostStoreError::Invalid)?;
            validate_revision_id(revision_id)?;
            let candidate = self.load_candidate_file(revision_id)?;
            match retained.get(revision_id) {
                Some(Some(expected_hash)) if candidate.binding_hash == *expected_hash => {}
                Some(_) => return Err(ProxyHostStoreError::Invalid),
                None => stale.push(entry.path()),
            }
        }
        for path in &stale {
            remove_private_file(path)?;
        }
        Ok(stale.len())
    }

    fn load_candidate_file(
        &self,
        revision_id: &str,
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        validate_revision_id(revision_id)?;
        let path = self.candidate_path(revision_id);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_TRANSACTION_BYTES
        {
            return Err(ProxyHostStoreError::Invalid);
        }
        reject_insecure_file_permissions(&metadata)?;
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_TRANSACTION_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        let file: ProxyHostCandidateFile =
            serde_json::from_slice(&bytes).map_err(|_| ProxyHostStoreError::Invalid)?;
        let objects = canonical_objects(&file.objects)?;
        let access_policies = canonical_access_policies(&file.access_policies)?;
        let stream_hosts = canonical_stream_hosts(&file.stream_hosts)?;
        let discovery_sources = canonical_discovery_sources(&file.discovery_sources)?;
        let certificates = canonical_certificates(&file.certificates)?;
        let binding_hash = match file.schema_version {
            CANDIDATE_SCHEMA_V1
                if stream_hosts.is_empty()
                    && discovery_sources.is_empty()
                    && certificates.is_empty() =>
            {
                Self::binding_hash_with_access_policies(&objects, &access_policies)?
            }
            CANDIDATE_SCHEMA_V2 => Self::unified_binding_hash(
                &objects,
                &stream_hosts,
                &discovery_sources,
                &access_policies,
                &certificates,
            )?,
            _ => return Err(ProxyHostStoreError::Invalid),
        };
        if file.revision_id != revision_id || file.binding_hash != binding_hash {
            return Err(ProxyHostStoreError::Invalid);
        }
        Ok(BoundProxyHostCandidate {
            schema_version: file.schema_version,
            binding_hash,
            objects,
            stream_hosts,
            discovery_sources,
            access_policies,
            certificates,
        })
    }

    pub(super) fn candidate_path(&self, revision_id: &str) -> PathBuf {
        self.candidate_dir.join(format!("{revision_id}.json"))
    }
}
