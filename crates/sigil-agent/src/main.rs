//! `sigil-agent` — the Sigil EDR endpoint agent.
//!
//! An optional companion to the SIEM (excluded from the workspace default
//! build). It enrolls with a `sigil-edr` gateway, streams endpoint telemetry
//! (process / file / network / persistence), and executes response commands
//! (kill / quarantine / isolate / fetch). See `docs/EDR.md`.

mod collector;
mod config;
mod response;
mod transport;

use std::time::Duration;

use clap::{Parser, Subcommand};

use collector::{
    Collector, FileCollector, NetworkCollector, PersistenceCollector, ProcessCollector,
};
use config::{AgentConfig, AgentIdentity};

#[derive(Parser)]
#[command(name = "sigil-agent", version, about = "Sigil EDR endpoint agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll with a gateway and persist the granted identity.
    Enroll {
        #[arg(long, default_value = "agent.yaml")]
        config: String,
        /// Override the gateway URL (e.g. https://siem:50055).
        #[arg(long)]
        server: Option<String>,
        /// Override the enrollment token.
        #[arg(long)]
        token: Option<String>,
    },
    /// Run collectors + the control loop (requires prior enrollment).
    Run {
        #[arg(long, default_value = "agent.yaml")]
        config: String,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Enroll {
            config,
            server,
            token,
        } => enroll(config, server, token).await,
        Command::Run { config } => run(config).await,
    }
}

async fn enroll(config: String, server: Option<String>, token: Option<String>) {
    let mut cfg = AgentConfig::load(&config).unwrap_or_else(|_| {
        AgentConfig::minimal(
            server.clone().unwrap_or_default(),
            token.clone().unwrap_or_default(),
        )
    });
    if let Some(s) = server {
        cfg.server_url = s;
    }
    if let Some(t) = token {
        cfg.enrollment_token = t;
    }
    if cfg.server_url.is_empty() {
        eprintln!("error: no server URL (pass --server or set server_url in the config)");
        std::process::exit(1);
    }

    match transport::enroll(&cfg).await {
        Ok(identity) => {
            let path = cfg.state_path();
            if let Err(e) = identity.save(&path) {
                eprintln!(
                    "enrolled but failed to save identity to {}: {e}",
                    path.display()
                );
                std::process::exit(1);
            }
            println!(
                "enrolled as {} (identity saved to {})",
                identity.agent_id,
                path.display()
            );
        }
        Err(e) => {
            eprintln!("enroll failed: {e}");
            std::process::exit(1);
        }
    }
}

async fn run(config: String) {
    let cfg = match AgentConfig::load(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load {config}: {e}");
            std::process::exit(1);
        }
    };
    let identity = match AgentIdentity::load(cfg.state_path()) {
        Some(id) => id,
        None => {
            eprintln!("not enrolled; run `sigil-agent enroll` first");
            std::process::exit(1);
        }
    };

    // Build the enabled collectors.
    let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
    if cfg.collectors.process {
        collectors.push(Box::new(ProcessCollector::default()));
    }
    if cfg.collectors.file {
        match FileCollector::new(&cfg.watch_paths) {
            Ok(c) => collectors.push(Box::new(c)),
            Err(e) => tracing::warn!(error = %e, "file collector disabled"),
        }
    }
    if cfg.collectors.network {
        collectors.push(Box::new(NetworkCollector::default()));
    }
    if cfg.collectors.persistence {
        collectors.push(Box::new(PersistenceCollector::default()));
    }
    tracing::info!(
        collectors = collectors.len(),
        agent_id = %identity.agent_id,
        server = %cfg.server_url,
        "sigil-agent starting"
    );

    let (tx, rx) = tokio::sync::mpsc::channel(4096);
    collector::spawn(collectors, Duration::from_secs(cfg.poll_interval_secs), tx);
    transport::run(cfg, identity, rx).await;
}
