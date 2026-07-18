#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Command-line entry point for the AegisProxy daemon.

mod admin_client;

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
    /// Manage hash-only administrative API tokens through the private socket.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
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
    /// Print private OpenMetrics exposition.
    Metrics {
        #[command(flatten)]
        admin: AdminConnection,
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
        #[arg(long, value_enum)]
        role: CliRole,
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
        id: String,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliRole {
    Viewer,
    Auditor,
    Operator,
    Admin,
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
    role: &'a str,
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    match run(Cli::parse()).await {
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
        } => {
            let cancel = CancellationToken::new();
            let signal = cancel.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.cancel();
            });
            if resume_last_known_good {
                let state_dir = state_dir.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--state-dir is required")
                })?;
                aegisproxy_core::run_last_known_good_with_control(
                    config, state_dir, cancel, run_admin,
                )
                .await?;
            } else {
                aegisproxy_core::run_managed_with_control(config, cancel, run_admin).await?;
            }
        }
        Command::Config { command } => {
            run_config_command(command).await?;
        }
        Command::Cert { command } => {
            run_certificate_command(command).await?;
        }
        Command::Token { command } => run_token_command(command).await?,
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
        Command::Metrics { admin } => {
            let response =
                admin_request(&admin, Method::GET, "/metrics", None, None, Vec::new()).await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
        }
    }
    Ok(())
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

async fn run_admin(control: aegisproxy_core::ManagedControl, shutdown: CancellationToken) {
    if let Err(error) = aegisproxy_admin::serve(control, shutdown).await {
        tracing::error!(%error, "administrative service stopped");
    }
}

async fn admin_request(
    admin: &AdminConnection,
    method: Method,
    path: &str,
    if_match: Option<String>,
    content_type: Option<&'static str>,
    body: Vec<u8>,
) -> Result<admin_client::AdminResponse, BoxError> {
    let bearer = load_admin_token(admin.token_ref.clone()).await?;
    admin_client::request(
        &admin.socket,
        admin_client::AdminRequest {
            method,
            path: path.to_owned(),
            if_match,
            content_type,
            bearer,
            body,
        },
    )
    .await
}

async fn load_admin_token(
    reference: Option<String>,
) -> Result<Option<Zeroizing<String>>, BoxError> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    tokio::task::spawn_blocking(move || {
        let secret = aegisproxy_secrets::SecretRef::parse(&reference)?.resolve(256)?;
        let value = std::str::from_utf8(secret.as_ref())?.trim_end_matches(['\r', '\n']);
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid API token").into());
        }
        Ok(Some(Zeroizing::new(value.to_owned())))
    })
    .await
    .map_err(|error| -> BoxError { Box::new(error) })?
}

fn require_admin_success(response: &admin_client::AdminResponse) -> Result<(), BoxError> {
    if response.status.is_success() {
        return Ok(());
    }
    let body = String::from_utf8_lossy(&response.body);
    Err(AdminHttpError {
        status: response.status,
        body: body.into_owned(),
    }
    .into())
}

async fn run_token_command(command: TokenCommand) -> Result<(), BoxError> {
    match command {
        TokenCommand::Create {
            admin,
            expect,
            role,
            ttl_secs,
        } => {
            if ttl_secs == 0 || ttl_secs > 365 * 24 * 60 * 60 {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid token TTL").into(),
                );
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let role = match role {
                CliRole::Viewer => "viewer",
                CliRole::Auditor => "auditor",
                CliRole::Operator => "operator",
                CliRole::Admin => "admin",
            };
            let body = serde_json::to_vec(&TokenCreateBody {
                role,
                expires_unix_secs: now.saturating_add(ttl_secs),
            })?;
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/tokens",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        TokenCommand::List { admin } => {
            let response =
                admin_request(&admin, Method::GET, "/v1/tokens", None, None, Vec::new()).await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        TokenCommand::Revoke { admin, expect, id } => {
            let response = admin_request(
                &admin,
                Method::POST,
                &format!("/v1/tokens/{id}/revoke"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
    }
    Ok(())
}

async fn run_backup_command(command: BackupCommand) -> Result<(), BoxError> {
    match command {
        BackupCommand::Create {
            admin,
            expect,
            output,
        } => {
            let output = output.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "backup path is not UTF-8")
            })?;
            let body = serde_json::to_vec(&BackupCreateBody { output })?;
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/backups",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
        BackupCommand::Verify { input, identity } => {
            let summary = tokio::task::spawn_blocking(move || {
                let identity =
                    aegisproxy_secrets::SecretRef::parse(&identity)?.resolve(4 * 1024)?;
                aegisproxy_admin::validate_backup(input, identity.as_ref())
                    .map_err(|error| -> BoxError { Box::new(error) })
            })
            .await
            .map_err(|error| -> BoxError { Box::new(error) })??;
            writeln!(io::stdout().lock(), "{}", serde_json::to_string(&summary)?)?;
        }
    }
    Ok(())
}

async fn run_restore_command(command: RestoreCommand) -> Result<(), BoxError> {
    match command {
        RestoreCommand::Validate {
            admin,
            expect,
            input,
            identity,
        } => {
            let input = input.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "backup path is not UTF-8")
            })?;
            let body = serde_json::to_vec(&RestoreValidateBody {
                input,
                identity: &identity,
            })?;
            let response = admin_request(
                &admin,
                Method::POST,
                "/v1/restore/validate",
                Some(expect),
                Some("application/json"),
                body,
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
    }
    Ok(())
}

async fn run_config_command(command: ConfigCommand) -> Result<(), BoxError> {
    match command {
        ConfigCommand::Revisions { state_dir } => {
            tokio::task::spawn_blocking(move || write_revisions(state_dir))
                .await
                .map_err(|error| -> BoxError { Box::new(error) })??;
        }
        ConfigCommand::Activate {
            admin,
            file,
            expect,
        } => {
            let config = load_config(file).await?;
            let body = toml::to_string_pretty(&config)?.into_bytes();
            let candidate = admin_request(
                &admin,
                Method::POST,
                "/v1/config/candidates",
                Some(expect.clone()),
                Some("application/toml"),
                body,
            )
            .await?;
            require_admin_success(&candidate)?;
            let candidate: CandidateResponse = serde_json::from_slice(&candidate.body)?;
            let activation = admin_request(
                &admin,
                Method::POST,
                &format!("/v1/config/candidates/{}/activate", candidate.id),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&activation)?;
            io::stdout().lock().write_all(&activation.body)?;
            writeln!(io::stdout().lock())?;
        }
        ConfigCommand::Rollback {
            admin,
            revision,
            expect,
        } => {
            let response = admin_request(
                &admin,
                Method::POST,
                &format!("/v1/config/revisions/{revision}/rollback"),
                Some(expect),
                None,
                Vec::new(),
            )
            .await?;
            require_admin_success(&response)?;
            io::stdout().lock().write_all(&response.body)?;
            writeln!(io::stdout().lock())?;
        }
    }
    Ok(())
}

fn write_revisions(state_dir: PathBuf) -> Result<(), BoxError> {
    let store = aegisproxy_config::revision::RevisionStore::open(state_dir)?;
    let active = store.active()?;
    let active_id = active.as_ref().map(|pointer| pointer.active.id.as_str());
    let previous_id = active
        .as_ref()
        .and_then(|pointer| pointer.previous.as_ref())
        .map(|previous| previous.id.as_str());
    let mut output = io::stdout().lock();
    for revision in store.list()? {
        let status = if Some(revision.id.as_str()) == active_id {
            "active"
        } else if Some(revision.id.as_str()) == previous_id {
            "previous"
        } else {
            "retained"
        };
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}",
            revision.id, revision.hash, revision.created_unix_secs, revision.source, status
        )?;
    }
    Ok(())
}

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
