//! Fixed deny-by-default administrative authorization.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Built-in administrative role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read redacted runtime state.
    Viewer,
    /// Read runtime state and audit records.
    Auditor,
    /// Validate candidates and request bounded operational actions.
    Operator,
    /// Perform policy, identity, backup, and restore mutations.
    Admin,
}

/// One server-side authorization decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read redacted status.
    ReadStatus,
    /// Read active redacted configuration.
    ReadConfig,
    /// Validate configuration without persistence.
    ValidateConfig,
    /// Preview redacted configuration, fingerprints, and activation class.
    PreviewConfig,
    /// Persist an immutable candidate.
    CreateCandidate,
    /// Activate an immutable candidate.
    ActivateConfig,
    /// Roll back by creating and activating a forward revision.
    RollbackConfig,
    /// Read revision metadata and redacted content.
    ReadRevisions,
    /// Read typed Proxy Hosts within authenticated owner scope.
    ReadProxyHosts,
    /// Create an owned typed Proxy Host and immutable candidate.
    CreateProxyHost,
    /// Update an owned typed Proxy Host and immutable candidate.
    UpdateProxyHost,
    /// Delete an owned typed Proxy Host and create an immutable candidate.
    DeleteProxyHost,
    /// Activate a verified complete typed Proxy Host candidate.
    ActivateProxyHost,
    /// Restore bound typed Proxy Host desired state through a forward revision.
    RollbackProxyHost,
    /// Read typed Access Policies within authenticated owner scope.
    ReadAccessPolicies,
    /// Create an owned typed Access Policy.
    CreateAccessPolicy,
    /// Update an owned typed Access Policy.
    UpdateAccessPolicy,
    /// Delete an owned typed Access Policy.
    DeleteAccessPolicy,
    /// Read effective routes.
    ReadRoutes,
    /// Read upstream health state.
    ReadUpstreams,
    /// Drain an upstream or node.
    Drain,
    /// Read certificate metadata.
    ReadCertificates,
    /// Read owned typed Certificate objects.
    ReadCertificateObjects,
    /// Create an owned typed Certificate object.
    CreateCertificate,
    /// Update an owned typed Certificate object.
    UpdateCertificate,
    /// Delete an owned typed Certificate object.
    DeleteCertificate,
    /// Read owned typed Stream Hosts.
    ReadStreamHosts,
    /// Create an owned typed Stream Host.
    CreateStreamHost,
    /// Update an owned typed Stream Host.
    UpdateStreamHost,
    /// Delete an owned typed Stream Host.
    DeleteStreamHost,
    /// Read owned typed Discovery Sources.
    ReadDiscoverySources,
    /// Create an owned typed Discovery Source.
    CreateDiscoverySource,
    /// Update an owned typed Discovery Source.
    UpdateDiscoverySource,
    /// Delete an owned typed Discovery Source.
    DeleteDiscoverySource,
    /// Request managed certificate renewal.
    RenewCertificate,
    /// Read or export audit records.
    ReadAudit,
    /// Create a protected backup.
    CreateBackup,
    /// Validate a restore archive.
    ValidateRestore,
    /// Manage administrative identities and roles.
    ManageIdentities,
}

/// Invalid API-token scope set.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TokenScopeError {
    /// New tokens must grant at least one explicit action.
    #[error("API token requires at least one scope")]
    Empty,
    /// A scope appeared more than once.
    #[error("API token scopes contain a duplicate")]
    Duplicate,
    /// A scope exceeds the selected role.
    #[error("API token scope exceeds its role")]
    ExceedsRole,
}

/// Canonically ordered explicit action scopes for one API token.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TokenScopes(Vec<Action>);

impl TokenScopes {
    /// Validate, sort, and construct a nonempty scope set bounded by `role`.
    pub fn new(role: Role, mut actions: Vec<Action>) -> Result<Self, TokenScopeError> {
        if actions.is_empty() {
            return Err(TokenScopeError::Empty);
        }
        if actions.iter().any(|action| !role.allows(*action)) {
            return Err(TokenScopeError::ExceedsRole);
        }
        actions.sort_unstable();
        if actions.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TokenScopeError::Duplicate);
        }
        Ok(Self(actions))
    }

    /// Return whether this token explicitly grants `action`.
    #[must_use]
    pub fn allows(&self, action: Action) -> bool {
        self.0.binary_search(&action).is_ok()
    }

    /// Return the canonical read-only scope slice.
    #[must_use]
    pub fn as_slice(&self) -> &[Action] {
        &self.0
    }

    pub(crate) fn validate_stored(&self, role: Role) -> Result<(), TokenScopeError> {
        if self.0.is_empty() {
            return Ok(());
        }
        if self.0.iter().any(|action| !role.allows(*action)) {
            return Err(TokenScopeError::ExceedsRole);
        }
        if self.0.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(TokenScopeError::Duplicate);
        }
        Ok(())
    }

    pub(crate) fn validate_for_issue(&self, role: Role) -> Result<(), TokenScopeError> {
        if self.0.is_empty() {
            return Err(TokenScopeError::Empty);
        }
        self.validate_stored(role)
    }
}

impl Role {
    /// Return whether this role permits an action.
    #[must_use]
    pub fn allows(self, action: Action) -> bool {
        match self {
            Self::Admin => true,
            Self::Operator => matches!(
                action,
                Action::ReadStatus
                    | Action::ReadConfig
                    | Action::ValidateConfig
                    | Action::PreviewConfig
                    | Action::CreateCandidate
                    | Action::ReadRevisions
                    | Action::ReadProxyHosts
                    | Action::CreateProxyHost
                    | Action::UpdateProxyHost
                    | Action::DeleteProxyHost
                    | Action::ReadAccessPolicies
                    | Action::CreateAccessPolicy
                    | Action::UpdateAccessPolicy
                    | Action::DeleteAccessPolicy
                    | Action::ReadRoutes
                    | Action::ReadUpstreams
                    | Action::Drain
                    | Action::ReadCertificates
                    | Action::ReadCertificateObjects
                    | Action::CreateCertificate
                    | Action::UpdateCertificate
                    | Action::DeleteCertificate
                    | Action::ReadStreamHosts
                    | Action::CreateStreamHost
                    | Action::UpdateStreamHost
                    | Action::DeleteStreamHost
                    | Action::ReadDiscoverySources
                    | Action::CreateDiscoverySource
                    | Action::UpdateDiscoverySource
                    | Action::DeleteDiscoverySource
                    | Action::RenewCertificate
            ),
            Self::Auditor => matches!(
                action,
                Action::ReadStatus
                    | Action::ReadConfig
                    | Action::ReadRevisions
                    | Action::ReadProxyHosts
                    | Action::ReadAccessPolicies
                    | Action::ReadRoutes
                    | Action::ReadUpstreams
                    | Action::ReadCertificates
                    | Action::ReadCertificateObjects
                    | Action::ReadStreamHosts
                    | Action::ReadDiscoverySources
                    | Action::ReadAudit
            ),
            Self::Viewer => matches!(
                action,
                Action::ReadStatus
                    | Action::ReadConfig
                    | Action::ReadRevisions
                    | Action::ReadProxyHosts
                    | Action::ReadAccessPolicies
                    | Action::ReadRoutes
                    | Action::ReadUpstreams
                    | Action::ReadCertificates
                    | Action::ReadCertificateObjects
                    | Action::ReadStreamHosts
                    | Action::ReadDiscoverySources
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Role, TokenScopeError, TokenScopes};

    const ACTIONS: [Action; 39] = [
        Action::ReadStatus,
        Action::ReadConfig,
        Action::ValidateConfig,
        Action::PreviewConfig,
        Action::CreateCandidate,
        Action::ActivateConfig,
        Action::RollbackConfig,
        Action::ReadRevisions,
        Action::ReadProxyHosts,
        Action::CreateProxyHost,
        Action::UpdateProxyHost,
        Action::DeleteProxyHost,
        Action::ActivateProxyHost,
        Action::RollbackProxyHost,
        Action::ReadAccessPolicies,
        Action::CreateAccessPolicy,
        Action::UpdateAccessPolicy,
        Action::DeleteAccessPolicy,
        Action::ReadRoutes,
        Action::ReadUpstreams,
        Action::Drain,
        Action::ReadCertificates,
        Action::ReadCertificateObjects,
        Action::CreateCertificate,
        Action::UpdateCertificate,
        Action::DeleteCertificate,
        Action::ReadStreamHosts,
        Action::CreateStreamHost,
        Action::UpdateStreamHost,
        Action::DeleteStreamHost,
        Action::ReadDiscoverySources,
        Action::CreateDiscoverySource,
        Action::UpdateDiscoverySource,
        Action::DeleteDiscoverySource,
        Action::RenewCertificate,
        Action::ReadAudit,
        Action::CreateBackup,
        Action::ValidateRestore,
        Action::ManageIdentities,
    ];

    #[test]
    fn role_matrix_is_deny_by_default() {
        let expected = [
            (Role::Viewer, 11),
            (Role::Auditor, 12),
            (Role::Operator, 31),
            (Role::Admin, ACTIONS.len()),
        ];
        for (role, count) in expected {
            assert_eq!(
                ACTIONS
                    .iter()
                    .filter(|action| role.allows(**action))
                    .count(),
                count,
                "unexpected permission count for {role:?}"
            );
        }
        assert!(!Role::Viewer.allows(Action::ValidateConfig));
        assert!(Role::Viewer.allows(Action::ReadProxyHosts));
        assert!(Role::Viewer.allows(Action::ReadAccessPolicies));
        assert!(!Role::Viewer.allows(Action::CreateAccessPolicy));
        assert!(Role::Operator.allows(Action::DeleteAccessPolicy));
        assert!(!Role::Auditor.allows(Action::CreateCandidate));
        assert!(!Role::Operator.allows(Action::ActivateConfig));
        assert!(!Role::Operator.allows(Action::ReadAudit));
        assert!(Role::Admin.allows(Action::ManageIdentities));
    }

    #[test]
    fn token_scopes_are_explicit_canonical_and_role_bounded() {
        let scopes = TokenScopes::new(Role::Operator, vec![Action::ReadRoutes, Action::ReadStatus])
            .expect("operator scopes");
        assert_eq!(scopes.as_slice(), &[Action::ReadStatus, Action::ReadRoutes]);
        assert!(scopes.allows(Action::ReadRoutes));
        assert!(!scopes.allows(Action::CreateCandidate));
        assert_eq!(
            TokenScopes::new(Role::Viewer, Vec::new()).expect_err("empty"),
            TokenScopeError::Empty
        );
        assert_eq!(
            TokenScopes::new(Role::Viewer, vec![Action::ReadStatus, Action::ReadStatus])
                .expect_err("duplicate"),
            TokenScopeError::Duplicate
        );
        assert_eq!(
            TokenScopes::new(Role::Viewer, vec![Action::ActivateConfig])
                .expect_err("role escalation"),
            TokenScopeError::ExceedsRole
        );
    }
}
