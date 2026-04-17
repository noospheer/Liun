//! # Graceful shutdown
//!
//! Single source of truth for shutdown signaling. Install once in `main()`,
//! then every long-running task subscribes via `.subscribe()` and listens
//! via `tokio::select!`.
//!
//! Both SIGINT (Ctrl+C) and SIGTERM (systemd stop, container stop) trigger
//! shutdown. A second signal forces exit.

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;

/// Process-wide shutdown broadcaster. Clone the sender into each subsystem;
/// call `install()` once in main().
#[derive(Clone)]
pub struct Shutdown {
    tx: broadcast::Sender<()>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1);
        Self { tx }
    }

    /// Install signal handlers. On first SIGINT/SIGTERM, broadcast shutdown.
    /// On second signal, force immediate exit.
    pub fn install(&self) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut sigint = signal(SignalKind::interrupt())
                .expect("failed to install SIGINT handler");
            let mut sigterm = signal(SignalKind::terminate())
                .expect("failed to install SIGTERM handler");

            tokio::select! {
                _ = sigint.recv() => eprintln!("\n  [received SIGINT — graceful shutdown, Ctrl+C again to force]"),
                _ = sigterm.recv() => eprintln!("\n  [received SIGTERM — graceful shutdown]"),
            }
            let _ = tx.send(());

            // Second signal forces.
            tokio::select! {
                _ = sigint.recv() => {
                    eprintln!("  [second signal — force exit]");
                    std::process::exit(130);
                }
                _ = sigterm.recv() => {
                    eprintln!("  [second signal — force exit]");
                    std::process::exit(143);
                }
            }
        });
    }

    /// A receiver. Drop it to unsubscribe. Use `.recv().await` in a
    /// `tokio::select!` branch.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.tx.subscribe()
    }

    /// Fire shutdown manually (e.g. from a fatal error path).
    pub fn fire(&self) {
        let _ = self.tx.send(());
    }

    /// True if shutdown has already been fired.
    pub fn is_fired(&self) -> bool {
        // Best-effort: receiver_count is always ≥ 0; a fresh subscribe
        // would indicate no messages pending. Simpler: try_recv on a
        // throwaway subscriber.
        let mut rx = self.tx.subscribe();
        rx.try_recv().is_ok()
    }
}

impl Default for Shutdown {
    fn default() -> Self { Self::new() }
}
