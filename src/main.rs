use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use eyre::{WrapErr, bail};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::prelude::*;

use oblivious_gateway::config::FileConfig;
use oblivious_gateway::forward::Forwarder;
use oblivious_gateway::gateway::AppState;
use oblivious_gateway::keys::KeyRing;
use oblivious_gateway::{build_router_with_concurrency_limit, metrics, tls};

/// Standalone Rust Oblivious HTTP (RFC 9458) gateway.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(
        long,
        env = "OBLIVIOUS_GATEWAY_CONFIG",
        default_value = "config/gateway.toml"
    )]
    config: PathBuf,

    /// Disable target allowlisting and forward requests to any destination.
    /// Off by default: an allowlist is required unless this is set
    /// explicitly.
    #[arg(
        long,
        env = "OBLIVIOUS_GATEWAY_ALLOW_ANY_TARGET",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    allow_any_target: bool,
}

#[tokio::main]
async fn main() {
    // `ohttp` logs derived response keys and nonces at trace level, so its
    // debug and trace output is dropped whatever `RUST_LOG` requests.
    let hide_ohttp_secrets = filter_fn(|metadata| {
        let target = metadata.target();
        *metadata.level() <= Level::INFO || !(target == "ohttp" || target.starts_with("ohttp::"))
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_filter(
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
                )
                .with_filter(hide_ohttp_secrets),
        )
        .init();

    if let Err(err) = run().await {
        tracing::error!(error = ?err, "startup failed");
        std::process::exit(1);
    }
}

async fn run() -> eyre::Result<()> {
    let cli = Cli::parse();
    let file_config = FileConfig::load(&cli.config)?;

    if cli.allow_any_target {
        tracing::warn!(
            "--allow-any-target is set: outbound requests are not restricted to an allowlist"
        );
    } else if file_config.forwarding.allowed_targets.is_empty() {
        bail!(
            "forwarding.allowed_targets is empty; pass --allow-any-target to explicitly allow \
             unrestricted destinations"
        );
    }

    let key_ring = KeyRing::load(&file_config.generations)?;
    tracing::info!(
        loaded_keys = key_ring.loaded_key_count(),
        advertised_x25519 = key_ring.advertised_x25519_count(),
        advertised_xwing = key_ring.advertised_xwing_count(),
        "key ring loaded"
    );
    if let Some(metrics_config) = &file_config.metrics {
        metrics::install(&metrics_config.listen_addr).await?;
        metrics::set_key_gauges(
            key_ring.loaded_key_count(),
            key_ring.advertised_x25519_count(),
            key_ring.advertised_xwing_count(),
        );
    } else {
        tracing::warn!("no [metrics] section configured; Prometheus metrics are not exposed");
    }

    let forwarder = Forwarder::new(&file_config.forwarding, cli.allow_any_target);
    let state = Arc::new(AppState {
        key_ring,
        forwarder,
    });
    let app = build_router_with_concurrency_limit(state, file_config.server.max_in_flight_requests);

    let addr: std::net::SocketAddr =
        file_config.server.listen_addr.parse().wrap_err_with(|| {
            format!(
                "invalid server.listen_addr {:?}",
                file_config.server.listen_addr
            )
        })?;

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let grace = Duration::from_secs(file_config.server.shutdown_grace_seconds);
    let delay = Duration::from_secs(file_config.server.shutdown_delay_seconds);
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!(delay_seconds = delay.as_secs(), "shutdown signal received");
        tokio::time::sleep(delay).await;
        tracing::info!("draining connections");
        shutdown_handle.graceful_shutdown(Some(grace));
    });

    if let Some(tls_config) = &file_config.server.tls {
        let rustls_config = tls::build(tls_config)?;
        tracing::info!(%addr, "listening (TLS)");
        axum_server::bind_rustls(addr, rustls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .wrap_err_with(|| format!("serving TLS on {addr}"))?;
    } else {
        tracing::info!(%addr, "listening (plaintext)");
        axum_server::bind(addr)
            .handle(handle)
            .serve(app.into_make_service())
            .await
            .wrap_err_with(|| format!("serving on {addr}"))?;
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
