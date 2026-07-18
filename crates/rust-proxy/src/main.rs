#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Command-line entry point for the AegisProxy daemon.

use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

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
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// List immutable revisions and active/previous status.
    Revisions {
        #[arg(long)]
        state_dir: PathBuf,
    },
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
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    match Cli::parse().command {
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
            tokio::task::spawn_blocking(move || run_config_command(command))
                .await
                .map_err(|error| -> BoxError { Box::new(error) })??;
        }
        Command::Cert { command } => {
            run_certificate_command(command).await?;
        }
    }
    Ok(())
}

async fn run_admin(control: aegisproxy_core::ManagedControl, shutdown: CancellationToken) {
    if let Err(error) = aegisproxy_admin::serve(control, shutdown).await {
        tracing::error!(%error, "administrative service stopped");
    }
}

fn run_config_command(command: ConfigCommand) -> Result<(), BoxError> {
    match command {
        ConfigCommand::Revisions { state_dir } => {
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
        }
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
