use super::ascii_art::print_exit_art;
use primitive_types::U256;
use rand::Rng;
use std::process::exit;
use tokio::signal;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

pub async fn handle_exit_signals() {
    #[cfg(unix)]
    {
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to create SIGTERM handler");
        tokio::select! {
            _ = sigterm.recv() => {}
            _ = signal::ctrl_c() => {}
        }
    }

    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
    }

    print_exit_art();
    exit(0);
}

pub fn generate_nonce() -> String {
    let mut rng = rand::thread_rng();
    let nonce: u32 = rng.gen();
    format!("{:08x}", nonce)
}
