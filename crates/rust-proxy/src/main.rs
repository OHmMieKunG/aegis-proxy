#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Command-line entry point for the AegisProxy daemon.

mod admin_client;
mod fleet;
mod telemetry;

use std::{
    error::Error,
    fmt,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use hyper::Method;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(name = "rust-proxy", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate configuration without binding listeners.
    Validate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print the validated configuration.
    Preview {
        #[arg(long)]
        config: PathBuf,
    },
    /// Format validated configuration to stdout without resolving secrets.
    Fmt {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run the data plane.
    Run {
        #[arg(long)]
        config: PathBuf,
        /// Explicitly ignore an invalid configured file and resume durable active state.
        #[arg(long, requires = "state_dir")]
        resume_last_known_good: bool,
        /// Durable state directory required for explicit recovery.
        #[arg(long, requires = "resume_last_known_good")]
        state_dir: Option<PathBuf>,
        /// Stable lowercase node identifier; unique across an HA fleet.
        #[arg(long, default_value = "standalone")]
        node_id: String,
        /// Externally monotonic rollout generation; zero is standalone mode.
        #[arg(long, default_value_t = 0)]
        fleet_generation: u64,
    },
    /// Inspect durable configuration state while the daemon is stopped.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Manage encrypted certificate generations offline.
    Cert {
        #[command(subcommand)]
        command: CertificateCommand,
    },
    /// Manage typed Certificate objects through the private socket.
    Certificate {
        #[command(subcommand)]
        command: CertificateObjectCommand,
    },
    /// Manage hash-only administrative API tokens through the private socket.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Read, validate, or preview typed Proxy Hosts through the private socket.
    ProxyHost {
        #[command(subcommand)]
        command: ProxyHostCommand,
    },
    /// Read typed Access Policies through the private socket.
    AccessPolicy {
        #[command(subcommand)]
        command: AccessPolicyCommand,
    },
    /// Manage encrypted Stored Credentials through the private socket.
    Credential {
        #[command(subcommand)]
        command: AccessPolicyCommand,
    },
    /// Manage administrative users and inspect immutable roles.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// List immutable built-in roles.
    Role {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Manage typed Stream Hosts through the private socket.
    StreamHost {
        #[command(subcommand)]
        command: TypedDomainCommand,
    },
    /// Manage typed Discovery Sources through the private socket.
    DiscoverySource {
        #[command(subcommand)]
        command: TypedDomainCommand,
    },
    /// Create or verify encrypted state backups.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Validate recovery archives through the audited private API.
    Restore {
        #[command(subcommand)]
        command: RestoreCommand,
    },
    /// Query private liveness and readiness.
    Health {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Mark this node unready before external load-balancer drain and restart.
    Drain {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
    },
    /// Print private OpenMetrics exposition.
    Metrics {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Export private node status or verify a complete offline fleet snapshot.
    Fleet {
        #[command(subcommand)]
        command: FleetCommand,
    },
}

#[derive(Debug, Subcommand)]
enum FleetCommand {
    /// Print exact canonical configuration content hash without persistence.
    Hash {
        #[arg(long)]
        config: PathBuf,
    },
    /// Print authenticated node status JSON from the private Unix API.
    Status {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Reject missing, divergent, unready, or duplicate-owner node exports.
    Check {
        #[arg(long)]
        expected_hash: String,
        #[arg(long)]
        generation: u64,
        #[arg(long = "node", required = true)]
        nodes: Vec<String>,
        #[arg(long = "status", required = true)]
        statuses: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// List immutable revisions and active/previous status.
    Revisions {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Validate, persist, and atomically activate one file through the private API.
    Activate {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expect: String,
    },
    /// Create and activate a forward revision from retained content.
    Rollback {
        #[command(flatten)]
        admin: AdminConnection,
        revision: String,
        #[arg(long)]
        expect: String,
    },
}

#[derive(Clone, Debug, Args)]
struct AdminConnection {
    /// Private Unix socket path.
    #[arg(long, default_value = "/run/rust-proxy/admin.sock")]
    socket: PathBuf,
    /// Optional env:// or absolute file:// API-token reference.
    #[arg(long)]
    token_ref: Option<String>,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Create a token and print its plaintext once.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        user_ref: String,
        /// Explicit action scope; repeat for multiple scopes.
        #[arg(long, value_enum, required = true)]
        scope: Vec<CliScope>,
        #[arg(long, default_value_t = 3_600)]
        ttl_secs: u64,
    },
    /// List redacted token metadata.
    List {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Revoke one token ID.
    Revoke {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProxyHostCommand {
    /// List typed Proxy Hosts owned by authenticated principal.
    List {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Get one typed Proxy Host owned by authenticated principal.
    Get {
        #[command(flatten)]
        admin: AdminConnection,
        id: String,
    },
    /// Create owned desired state and a non-active immutable candidate.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        /// Exact active revision required by optimistic concurrency.
        #[arg(long)]
        expect: String,
        file: PathBuf,
    },
    /// Replace owned desired state and create a non-active immutable candidate.
    Update {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
        file: PathBuf,
    },
    /// Delete owned desired state and create a non-active immutable candidate.
    Delete {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
    },
    /// Verify and atomically activate a complete typed candidate.
    Activate {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        candidate: String,
    },
    /// Restore bound typed desired state through a new forward revision.
    Rollback {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        revision: String,
    },
    /// Compile and semantically validate one owned Proxy Host without persistence.
    Validate {
        #[command(flatten)]
        admin: AdminConnection,
        file: PathBuf,
    },
    /// Print a redacted candidate preview and typed creation diff without activation.
    Preview {
        #[command(flatten)]
        admin: AdminConnection,
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AccessPolicyCommand {
    /// List typed Access Policies owned by authenticated principal.
    List {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Get one typed Access Policy owned by authenticated principal.
    Get {
        #[command(flatten)]
        admin: AdminConnection,
        id: String,
    },
    /// Validate and persist one owned Access Policy without activation.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        file: PathBuf,
    },
    /// Replace one owned Access Policy without activation.
    Update {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
        file: PathBuf,
    },
    /// Delete one owned Access Policy without activation.
    Delete {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// List users.
    List {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Get one user.
    Get {
        #[command(flatten)]
        admin: AdminConnection,
        id: String,
    },
    /// Create one user.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        file: PathBuf,
    },
    /// Replace one user.
    Update {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
        file: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CertificateObjectCommand {
    /// List typed Certificates owned by authenticated principal.
    List {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Get one typed Certificate owned by authenticated principal.
    Get {
        #[command(flatten)]
        admin: AdminConnection,
        id: String,
    },
    /// Validate and persist one owned Certificate without activation.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        file: PathBuf,
    },
    /// Replace one owned Certificate without activation.
    Update {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
        file: PathBuf,
    },
    /// Delete one owned Certificate without activation.
    Delete {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
    },
    /// Request renewal by owned Certificate object ID.
    Renew {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        id: String,
    },
}

#[derive(Debug, Subcommand)]
enum TypedDomainCommand {
    /// List objects owned by authenticated principal.
    List {
        #[command(flatten)]
        admin: AdminConnection,
    },
    /// Get one object owned by authenticated principal.
    Get {
        #[command(flatten)]
        admin: AdminConnection,
        id: String,
    },
    /// Validate, persist, and create a non-active candidate.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        file: PathBuf,
    },
    /// Replace one object and create a non-active candidate.
    Update {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
        file: PathBuf,
    },
    /// Delete one object and create a non-active candidate.
    Delete {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        generation: u64,
        id: String,
    },
    /// Validate one object without persistence.
    Validate {
        #[command(flatten)]
        admin: AdminConnection,
        file: PathBuf,
    },
    /// Preview one object without persistence or activation.
    Preview {
        #[command(flatten)]
        admin: AdminConnection,
        file: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliScope {
    ReadStatus,
    ReadConfig,
    ValidateConfig,
    PreviewConfig,
    CreateCandidate,
    ActivateConfig,
    RollbackConfig,
    ReadRevisions,
    ReadProxyHosts,
    CreateProxyHost,
    UpdateProxyHost,
    DeleteProxyHost,
    ActivateProxyHost,
    RollbackProxyHost,
    ActivateTypedCandidate,
    RollbackTypedRevision,
    ReadAccessPolicies,
    CreateAccessPolicy,
    UpdateAccessPolicy,
    DeleteAccessPolicy,
    ReadRoutes,
    ReadUpstreams,
    Drain,
    ReadCertificates,
    ReadCertificateObjects,
    CreateCertificate,
    UpdateCertificate,
    DeleteCertificate,
    ReadStreamHosts,
    CreateStreamHost,
    UpdateStreamHost,
    DeleteStreamHost,
    ReadDiscoverySources,
    CreateDiscoverySource,
    UpdateDiscoverySource,
    DeleteDiscoverySource,
    ReadCredentials,
    CreateCredential,
    UpdateCredential,
    RevokeCredential,
    ReadTokens,
    CreateToken,
    RevokeToken,
    ReadUsers,
    CreateUser,
    UpdateUser,
    ReadRoles,
    RenewCertificate,
    ReadAudit,
    CreateBackup,
    ValidateRestore,
    ManageIdentities,
}

impl CliScope {
    const fn as_api_str(self) -> &'static str {
        match self {
            Self::ReadStatus => "read_status",
            Self::ReadConfig => "read_config",
            Self::ValidateConfig => "validate_config",
            Self::PreviewConfig => "preview_config",
            Self::CreateCandidate => "create_candidate",
            Self::ActivateConfig => "activate_config",
            Self::RollbackConfig => "rollback_config",
            Self::ReadRevisions => "read_revisions",
            Self::ReadProxyHosts => "read_proxy_hosts",
            Self::CreateProxyHost => "create_proxy_host",
            Self::UpdateProxyHost => "update_proxy_host",
            Self::DeleteProxyHost => "delete_proxy_host",
            Self::ActivateProxyHost => "activate_proxy_host",
            Self::RollbackProxyHost => "rollback_proxy_host",
            Self::ActivateTypedCandidate => "activate_typed_candidate",
            Self::RollbackTypedRevision => "rollback_typed_revision",
            Self::ReadAccessPolicies => "read_access_policies",
            Self::CreateAccessPolicy => "create_access_policy",
            Self::UpdateAccessPolicy => "update_access_policy",
            Self::DeleteAccessPolicy => "delete_access_policy",
            Self::ReadRoutes => "read_routes",
            Self::ReadUpstreams => "read_upstreams",
            Self::Drain => "drain",
            Self::ReadCertificates => "read_certificates",
            Self::ReadCertificateObjects => "read_certificate_objects",
            Self::CreateCertificate => "create_certificate",
            Self::UpdateCertificate => "update_certificate",
            Self::DeleteCertificate => "delete_certificate",
            Self::ReadStreamHosts => "read_stream_hosts",
            Self::CreateStreamHost => "create_stream_host",
            Self::UpdateStreamHost => "update_stream_host",
            Self::DeleteStreamHost => "delete_stream_host",
            Self::ReadDiscoverySources => "read_discovery_sources",
            Self::CreateDiscoverySource => "create_discovery_source",
            Self::UpdateDiscoverySource => "update_discovery_source",
            Self::DeleteDiscoverySource => "delete_discovery_source",
            Self::ReadCredentials => "read_credentials",
            Self::CreateCredential => "create_credential",
            Self::UpdateCredential => "update_credential",
            Self::RevokeCredential => "revoke_credential",
            Self::ReadTokens => "read_tokens",
            Self::CreateToken => "create_token",
            Self::RevokeToken => "revoke_token",
            Self::ReadUsers => "read_users",
            Self::CreateUser => "create_user",
            Self::UpdateUser => "update_user",
            Self::ReadRoles => "read_roles",
            Self::RenewCertificate => "renew_certificate",
            Self::ReadAudit => "read_audit",
            Self::CreateBackup => "create_backup",
            Self::ValidateRestore => "validate_restore",
            Self::ManageIdentities => "manage_identities",
        }
    }
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    /// Create an encrypted backup through the audited private API.
    Create {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Authenticate and validate an encrypted backup offline.
    Verify {
        input: PathBuf,
        #[arg(long)]
        identity: String,
    },
}

#[derive(Debug, Subcommand)]
enum RestoreCommand {
    /// Validate an archive without extraction or activation.
    Validate {
        #[command(flatten)]
        admin: AdminConnection,
        #[arg(long)]
        expect: String,
        input: PathBuf,
        #[arg(long)]
        identity: String,
    },
}

#[derive(Debug, Deserialize)]
struct CandidateResponse {
    id: String,
}

#[derive(Debug, Serialize)]
struct TokenCreateBody<'a> {
    user_ref: &'a str,
    scopes: Vec<&'static str>,
    expires_unix_secs: u64,
}

#[derive(Debug, Serialize)]
struct BackupCreateBody<'a> {
    output: &'a str,
}

#[derive(Debug, Serialize)]
struct RestoreValidateBody<'a> {
    input: &'a str,
    identity: &'a str,
}

#[derive(Debug, Subcommand)]
enum CertificateCommand {
    /// Show managed certificate renewal state from validated configuration and durable storage.
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    /// Durably request renewal from the running daemon's next reconciliation.
    Renew {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Validate and import a new certificate ID. Existing IDs are never replaced.
    Import {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long = "host", required = true)]
        hosts: Vec<String>,
        #[arg(long)]
        certificate_chain: String,
        #[arg(long)]
        private_key: String,
        #[arg(long = "recipient", required = true)]
        recipients: Vec<String>,
    },
    /// List active imported certificate generations.
    List {
        #[arg(long)]
        state_dir: PathBuf,
    },
    /// Inspect one active imported certificate generation.
    Inspect {
        #[arg(long)]
        state_dir: PathBuf,
        /// Optional age identity reference for offline key recovery verification.
        #[arg(long)]
        identity: Option<String>,
        id: String,
    },
}

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    if !matches!(&cli.command, Command::Run { .. })
        && let Err(error) = telemetry::init(&Default::default())
    {
        eprintln!("telemetry initialization failed: {error}");
        return ExitCode::from(6);
    }
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(exit_code(error.as_ref()))
        }
    }
}

async fn run(cli: Cli) -> Result<(), BoxError> {
    match cli.command {
        Command::Validate { config } => {
            load_config(config).await?;
            writeln!(io::stdout().lock(), "valid")?;
        }
        Command::Preview { config } => {
            let config = load_config(config).await?;
            let routes = aegisproxy_core::RouteIndex::compile(&config);
            let mut output = io::stdout().lock();
            writeln!(
                output,
                "# route_fingerprint = {:016x}",
                routes.fingerprint()
            )?;
            writeln!(
                output,
                "{}",
                toml::to_string_pretty(&aegisproxy_config::redacted(&config))?
            )?;
        }
        Command::Fmt { config } => {
            let config = load_config(config).await?;
            writeln!(io::stdout().lock(), "{}", toml::to_string_pretty(&config)?)?;
        }
        Command::Run {
            config,
            resume_last_known_good,
            state_dir,
            node_id,
            fleet_generation,
        } => {
            let identity = aegisproxy_core::NodeIdentity::new(node_id, fleet_generation)?;
            let startup_config = if resume_last_known_good {
                let state_dir = state_dir.as_ref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--state-dir is required")
                })?;
                aegisproxy_core::load_last_known_good(state_dir.clone()).await?
            } else {
                load_config(config.clone()).await?
            };
            let telemetry = telemetry::init(&startup_config.observability)?;
            let cancel = CancellationToken::new();
            let signal = cancel.clone();
            tokio::spawn(async move {
                if let Err(error) = wait_for_shutdown_signal().await {
                    tracing::error!(%error, "shutdown signal listener failed");
                }
                signal.cancel();
            });
            let result = if resume_last_known_good {
                let state_dir = state_dir.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--state-dir is required")
                })?;
                aegisproxy_core::run_last_known_good_with_control_on_node(
                    config, state_dir, identity, cancel, run_admin,
                )
                .await
            } else {
                aegisproxy_core::run_managed_config_with_control_on_node(
                    config,
                    startup_config,
                    identity,
                    cancel,
                    run_admin,
                )
                .await
            };
            telemetry.shutdown().await;
            result?;
        }
        Command::Config { command } => {
            run_config_command(command).await?;
        }
        Command::Cert { command } => {
            run_certificate_command(command).await?;
        }
        Command::Certificate { command } => run_certificate_object_command(command).await?,
        Command::Token { command } => run_token_command(command).await?,
        Command::ProxyHost { command } => run_proxy_host_command(command).await?,
        Command::AccessPolicy { command } => {
            run_owned_object_command(command, "access-policies").await?
        }
        Command::Credential { command } => run_owned_object_command(command, "credentials").await?,
        Command::User { command } => run_user_command(command).await?,
        Command::Role { admin } => {
            let response =
                admin_request(&admin, Method::GET, "/v1/roles", None, None, Vec::new()).await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        Command::StreamHost { command } => {
            run_typed_domain_command(command, "stream-hosts").await?
        }
        Command::DiscoverySource { command } => {
            run_typed_domain_command(command, "discovery-sources").await?
        }
        Command::Backup { command } => run_backup_command(command).await?,
        Command::Restore { command } => run_restore_command(command).await?,
        Command::Health { admin } => {
            let live =
                admin_request(&admin, Method::GET, "/v1/live", None, None, Vec::new()).await?;
            require_admin_success(&live)?;
            let ready =
                admin_request(&admin, Method::GET, "/v1/ready", None, None, Vec::new()).await?;
            require_admin_success(&ready)?;
            writeln!(io::stdout().lock(), "live\nready")?;
        }
        Command::Drain { admin, expect } => {
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/node/drain",
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        Command::Metrics { admin } => {
            let response =
                admin_request(&admin, Method::GET, "/metrics", None, None, Vec::new()).await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
        }
        Command::Fleet { command } => match command {
            FleetCommand::Hash { config } => {
                let config = load_config(config).await?;
                let hash = aegisproxy_config::revision::content_hash(&config)?;
                writeln!(io::stdout().lock(), "{hash}")?;
            }
            FleetCommand::Status { admin } => {
                let response =
                    admin_request(&admin, Method::GET, "/v1/status", None, None, Vec::new())
                        .await?;
                require_admin_success(&response)?;
                io::stdout().lock().write_all(&response.body)?;
                writeln!(io::stdout().lock())?;
            }
            FleetCommand::Check {
                expected_hash,
                generation,
                nodes,
                statuses,
            } => {
                let summary = fleet::check(&expected_hash, generation, &nodes, &statuses)?;
                let owner = summary.certificate_owner.as_deref().unwrap_or("none");
                writeln!(
                    io::stdout().lock(),
                    "fleet verified: nodes={} generation={} hash={} certificate_owner={owner}",
                    summary.nodes,
                    generation,
                    expected_hash
                )?;
            }
        },
    }
    Ok(())
}

async fn wait_for_shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            received = terminate.recv() => received
                .ok_or_else(|| io::Error::other("SIGTERM listener closed")),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

#[derive(Debug)]
struct AdminHttpError {
    status: hyper::StatusCode,
    body: String,
}

impl fmt::Display for AdminHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "administrative request returned {}: {}",
            self.status, self.body
        )
    }
}

impl Error for AdminHttpError {}

fn exit_code(error: &(dyn Error + 'static)) -> u8 {
    if error.is::<aegisproxy_config::ConfigError>() {
        return 3;
    }
    if matches!(
        error.downcast_ref::<aegisproxy_config::revision::RevisionError>(),
        Some(aegisproxy_config::revision::RevisionError::Conflict)
    ) {
        return 4;
    }
    if let Some(error) = error.downcast_ref::<AdminHttpError>() {
        return match error.status {
            hyper::StatusCode::BAD_REQUEST
            | hyper::StatusCode::UNPROCESSABLE_ENTITY
            | hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE => 3,
            hyper::StatusCode::CONFLICT | hyper::StatusCode::PRECONDITION_FAILED => 4,
            hyper::StatusCode::UNAUTHORIZED | hyper::StatusCode::FORBIDDEN => 5,
            _ => 6,
        };
    }
    6
}

mod admin_commands;
use admin_commands::*;

async fn load_config(path: PathBuf) -> Result<aegisproxy_config::Config, BoxError> {
    tokio::task::spawn_blocking(move || aegisproxy_config::load_file(path))
        .await
        .map_err(|error| -> BoxError { Box::new(error) })?
        .map_err(|error| -> BoxError { Box::new(error) })
}

async fn run_certificate_command(command: CertificateCommand) -> Result<(), BoxError> {
    match command {
        CertificateCommand::Status { config } => {
            let config = load_config(config).await?;
            tokio::task::spawn_blocking(move || write_certificate_status(&config))
                .await
                .map_err(|error| -> BoxError { Box::new(error) })??;
        }
        CertificateCommand::Renew { config, id } => {
            let config = load_config(config).await?;
            if !config
                .acme
                .certificates
                .iter()
                .any(|certificate| certificate.id == id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "certificate ID is not managed by ACME configuration",
                )
                .into());
            }
            let state_dir = PathBuf::from(config.runtime.state_dir);
            tokio::task::spawn_blocking(move || {
                aegisproxy_tls::acme::request_certificate_renewal(&state_dir, &id)
            })
            .await
            .map_err(|error| -> BoxError { Box::new(error) })??;
            writeln!(io::stdout().lock(), "renewal requested")?;
        }
        CertificateCommand::Import {
            state_dir,
            id,
            hosts,
            certificate_chain,
            private_key,
            recipients,
        } => {
            let imported = tokio::task::spawn_blocking(move || {
                aegisproxy_tls::import_certificate(
                    &state_dir,
                    &id,
                    hosts,
                    &certificate_chain,
                    &private_key,
                    &recipients,
                )
            })
            .await
            .map_err(|error| -> BoxError { Box::new(error) })??;
            write_certificate(&imported.certificate)?;
            let mut output = io::stdout().lock();
            writeln!(
                output,
                "certificate_chain = {:?}",
                imported.certificate_chain
            )?;
            writeln!(output, "private_key = {:?}", imported.private_key)?;
        }
        CertificateCommand::List { state_dir } => {
            let certificates =
                tokio::task::spawn_blocking(move || aegisproxy_tls::list_certificates(&state_dir))
                    .await
                    .map_err(|error| -> BoxError { Box::new(error) })??;
            let mut output = io::stdout().lock();
            for certificate in certificates {
                writeln!(
                    output,
                    "{}\t{}\t{}",
                    certificate.id, certificate.generation, certificate.not_after_unix_secs
                )?;
            }
        }
        CertificateCommand::Inspect {
            state_dir,
            identity,
            id,
        } => {
            let verified = identity.is_some();
            let certificate = tokio::task::spawn_blocking(move || match identity {
                Some(identity) => {
                    aegisproxy_tls::verify_stored_certificate(&state_dir, &id, &identity)
                }
                None => aegisproxy_tls::inspect_certificate(&state_dir, &id),
            })
            .await
            .map_err(|error| -> BoxError { Box::new(error) })??;
            if verified {
                writeln!(io::stdout().lock(), "private_key_verified = true")?;
            }
            write_certificate(&certificate)?;
        }
    }
    Ok(())
}

fn write_certificate_status(config: &aegisproxy_config::Config) -> Result<(), BoxError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let mut output = io::stdout().lock();
    writeln!(output, "id\tstatus\tnot_after\trenew_at\trequested")?;
    for managed in &config.acme.certificates {
        let requested =
            aegisproxy_tls::acme::certificate_renewal_requested(&state_dir, &managed.id)?;
        let certificate_dir = state_dir.join("certificates").join(&managed.id);
        if !certificate_dir.exists() {
            writeln!(output, "{}\tmissing\t-\t-\t{requested}", managed.id)?;
            continue;
        }
        let stored = aegisproxy_tls::inspect_certificate(&state_dir, &managed.id)?;
        let schedule = aegisproxy_tls::acme::fallback_renewal_schedule(
            &managed.id,
            stored.not_before_unix_secs,
            stored.not_after_unix_secs,
            now,
            managed.renew_before_days,
        )?;
        let status = if stored.not_after_unix_secs < 0 || stored.not_after_unix_secs as u64 <= now {
            "expired"
        } else if requested || schedule.renew_at_unix_secs <= now {
            "renewal_due"
        } else {
            "active"
        };
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            managed.id, status, stored.not_after_unix_secs, schedule.renew_at_unix_secs, requested
        )?;
    }
    Ok(())
}

fn write_certificate(certificate: &aegisproxy_tls::StoredCertificate) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "id = {:?}", certificate.id)?;
    writeln!(output, "generation = {:?}", certificate.generation)?;
    writeln!(output, "hosts = {:?}", certificate.hosts)?;
    writeln!(output, "issuer = {:?}", certificate.issuer)?;
    writeln!(
        output,
        "not_before_unix_secs = {}",
        certificate.not_before_unix_secs
    )?;
    writeln!(
        output,
        "not_after_unix_secs = {}",
        certificate.not_after_unix_secs
    )?;
    writeln!(
        output,
        "imported_unix_secs = {}",
        certificate.imported_unix_secs
    )
}

#[cfg(test)]
mod cli_tests {
    use clap::Parser;

    use super::{Cli, Command, TokenCommand};

    #[test]
    fn revoke_accepts_generated_token_id_starting_with_hyphen() {
        let cli = Cli::try_parse_from([
            "rust-proxy",
            "token",
            "revoke",
            "--expect",
            "revision",
            "-generated-token-id",
        ])
        .expect("hyphen-prefixed token ID");
        assert!(matches!(
            cli.command,
            Command::Token {
                command: TokenCommand::Revoke { id, .. }
            } if id == "-generated-token-id"
        ));
    }
}
