//! Fixed deny-by-default administrative authorization.

use serde::{Deserialize, Serialize};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    /// Read redacted status.
    ReadStatus,
    /// Read active redacted configuration.
    ReadConfig,
    /// Validate configuration without persistence.
    ValidateConfig,
    /// Preview configuration and its diff.
    PreviewConfig,
    /// Persist an immutable candidate.
    CreateCandidate,
    /// Activate an immutable candidate.
    ActivateConfig,
    /// Roll back by creating and activating a forward revision.
    RollbackConfig,
    /// Read revision metadata and redacted content.
    ReadRevisions,
    /// Read effective routes.
    ReadRoutes,
    /// Read upstream health state.
    ReadUpstreams,
    /// Drain an upstream or node.
    Drain,
    /// Read certificate metadata.
    ReadCertificates,
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
                    | Action::ReadRoutes
                    | Action::ReadUpstreams
                    | Action::Drain
                    | Action::ReadCertificates
                    | Action::RenewCertificate
            ),
            Self::Auditor => matches!(
                action,
                Action::ReadStatus
                    | Action::ReadConfig
                    | Action::ReadRevisions
                    | Action::ReadRoutes
                    | Action::ReadUpstreams
                    | Action::ReadCertificates
                    | Action::ReadAudit
            ),
            Self::Viewer => matches!(
                action,
                Action::ReadStatus
                    | Action::ReadConfig
                    | Action::ReadRevisions
                    | Action::ReadRoutes
                    | Action::ReadUpstreams
                    | Action::ReadCertificates
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Role};

    const ACTIONS: [Action; 17] = [
        Action::ReadStatus,
        Action::ReadConfig,
        Action::ValidateConfig,
        Action::PreviewConfig,
        Action::CreateCandidate,
        Action::ActivateConfig,
        Action::RollbackConfig,
        Action::ReadRevisions,
        Action::ReadRoutes,
        Action::ReadUpstreams,
        Action::Drain,
        Action::ReadCertificates,
        Action::RenewCertificate,
        Action::ReadAudit,
        Action::CreateBackup,
        Action::ValidateRestore,
        Action::ManageIdentities,
    ];

    #[test]
    fn role_matrix_is_deny_by_default() {
        let expected = [
            (Role::Viewer, 6),
            (Role::Auditor, 7),
            (Role::Operator, 11),
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
        assert!(!Role::Auditor.allows(Action::CreateCandidate));
        assert!(!Role::Operator.allows(Action::ActivateConfig));
        assert!(!Role::Operator.allows(Action::ReadAudit));
        assert!(Role::Admin.allows(Action::ManageIdentities));
    }
}
