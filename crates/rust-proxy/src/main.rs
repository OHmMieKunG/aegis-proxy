#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, missing_docs)]
//! Command-line entry point for the AegisProxy daemon.

use std::{path::PathBuf, sync::Arc};

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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    match Cli::parse().command {
        Command::Validate { config } => {
            aegisproxy_config::load_file(config)?;
            println!("valid");
        }
        Command::Preview { config } => {
            let config = aegisproxy_config::load_file(config)?;
            println!("{}", toml::to_string_pretty(&config)?);
        }
        Command::Run { config } => {
            let config = Arc::new(aegisproxy_config::load_file(config)?);
            let cancel = CancellationToken::new();
            let signal = cancel.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                signal.cancel();
            });
            aegisproxy_core::run(config, cancel).await?;
        }
    }
    Ok(())
}
