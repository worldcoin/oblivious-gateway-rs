use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;

use oblivious_gateway::config::FileConfig;
use oblivious_gateway::error::StartupError;
use oblivious_gateway::forward::Forwarder;
use oblivious_gateway::gateway::AppState;
use oblivious_gateway::keys::KeyRing;
use oblivious_gateway::{build_router, metrics, tls};

/// Standalone Rust Oblivious HTTP (RFC 9458) gateway.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "config/gateway.toml")]
    config: PathBuf,

    /// Disable target allowlisting and forward requests to any destination.
    /// Off by default: an allowlist is required unless this is set
    /// explicitly.
    #[arg(long)]
    allow_any_target: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    if let Err(err) = run().await {
        tracing::error!(error = %err, "startup failed");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), StartupError> {
    let cli = Cli::parse();
    let file_config = FileConfig::load(&cli.config)?;

    if cli.allow_any_target {
        tracing::warn!(
            "--allow-any-target is set: outbound requests are not restricted to an allowlist"
        );
    } else if file_config.forwarding.allowed_targets.is_empty() {
        return Err(StartupError::Config(
            "forwarding.allowed_targets is empty; pass --allow-any-target to explicitly allow \
             unrestricted destinations"
                .to_string(),
        ));
    }

    let key_ring = KeyRing::load(&file_config.generations)?;
    tracing::info!(
        loaded_keys = key_ring.loaded_key_count(),
        advertised_x25519 = key_ring.advertised_x25519_count(),
        advertised_xwing = key_ring.advertised_xwing_count(),
        "key ring loaded"
    );
    metrics::set_key_gauges(
        key_ring.loaded_key_count(),
        key_ring.advertised_x25519_count(),
        key_ring.advertised_xwing_count(),
    );

    let forwarder = Forwarder::new(&file_config.forwarding, cli.allow_any_target);
    let state = Arc::new(AppState {
        key_ring,
        forwarder,
    });
    let app = build_router(state, &file_config.server);

    if let Some(metrics_config) = &file_config.metrics {
        metrics::install(&metrics_config.listen_addr, &metrics_config.path)?;
    } else {
        tracing::warn!("no [metrics] section configured; Prometheus metrics are not exposed");
    }

    let addr: std::net::SocketAddr = file_config
        .server
        .listen_addr
        .parse()
        .map_err(|e| StartupError::Config(format!("invalid server.listen_addr: {e}")))?;

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let grace = Duration::from_secs(file_config.server.shutdown_grace_seconds);
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutdown signal received, draining connections");
        shutdown_handle.graceful_shutdown(Some(grace));
    });

    if let Some(tls_config) = &file_config.server.tls {
        let rustls_config = tls::build(tls_config).await?;
        tracing::info!(%addr, mtls = tls_config.client_ca_file.is_some(), "listening (TLS)");
        axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        tracing::info!(%addr, "listening (plaintext)");
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
