//! The `reth-pulsechain-lc-server` binary.

use reth_pulsechain_lc_server::{config::Args, server};
use std::process::ExitCode;

fn main() -> ExitCode {
    server::init_logging();
    let cfg = match Args::try_parse_redacted(std::env::args_os())
        .unwrap_or_else(|err| err.exit())
        .into_config()
    {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("reth-pulsechain-lc-server: {err}");
            return ExitCode::FAILURE
        }
    };
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("reth-pulsechain-lc-server: cannot start the async runtime: {err}");
            return ExitCode::FAILURE
        }
    };
    rt.block_on(async move {
        if let Some(addr) = cfg.metrics_addr &&
            let Err(err) = server::install_metrics(addr)
        {
            eprintln!("reth-pulsechain-lc-server: cannot serve metrics on {addr}: {err}");
            return ExitCode::FAILURE
        }
        match server::run(&cfg, shutdown_signal()).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("reth-pulsechain-lc-server: {err}");
                ExitCode::FAILURE
            }
        }
    })
}

/// Resolves at the first SIGINT or SIGTERM. A signal that cannot be watched is logged, and the
/// other one still stops the server.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(%err, "cannot watch SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(err) => {
                tracing::warn!(%err, "cannot watch SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
