#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Command-line entry point for the AegisProxy daemon.

use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
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
    /// Run the data plane.
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Manage encrypted certificate generations offline.
    Cert {
        #[command(subcommand)]
        command: CertificateCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CertificateCommand {
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
            writeln!(io::stdout().lock(), "{}", toml::to_string_pretty(&config)?)?;
        }
        Command::Run { config } => {
            let config = Arc::new(load_config(config).await?);
            let cancel = CancellationToken::new();
            let signal = cancel.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.cancel();
            });
            aegisproxy_core::run(config, cancel).await?;
        }
        Command::Cert { command } => {
            tokio::task::spawn_blocking(move || run_certificate_command(command))
                .await
                .map_err(|error| -> BoxError { Box::new(error) })??;
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

fn run_certificate_command(command: CertificateCommand) -> Result<(), BoxError> {
    match command {
        CertificateCommand::Import {
            state_dir,
            id,
            hosts,
            certificate_chain,
            private_key,
            recipients,
        } => {
            let imported = aegisproxy_tls::import_certificate(
                &state_dir,
                &id,
                hosts,
                &certificate_chain,
                &private_key,
                &recipients,
            )?;
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
            let mut output = io::stdout().lock();
            for certificate in aegisproxy_tls::list_certificates(&state_dir)? {
                writeln!(
                    output,
                    "{}\t{}\t{}",
                    certificate.id, certificate.generation, certificate.not_after_unix_secs
                )?;
            }
        }
        CertificateCommand::Inspect { state_dir, id } => {
            write_certificate(&aegisproxy_tls::inspect_certificate(&state_dir, &id)?)?;
        }
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
