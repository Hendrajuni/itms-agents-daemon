mod classifier;
mod config;
mod dns_etw;
mod flusher;
mod hardware;
mod service;
mod storage;
mod window_tracker;

use config::AgentConfig;
use dns_etw::DnsEtwSniffer;
use flusher::TelemetryFlusher;
use hardware::HardwareCollector;
use storage::TelemetryStorage;
use window_tracker::WindowTracker;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inisialisasi logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("run");

    match command {
        "install" => {
            service::install_service()?;
        }
        "uninstall" => {
            service::uninstall_service()?;
        }
        "start" => {
            service::start_service()?;
        }
        "stop" => {
            service::stop_service()?;
        }
        "service" => {
            // Dipanggil langsung oleh Windows Service Control Manager (SCM)
            service::run_as_service()?;
        }
        "run" => {
            // Mode interaktif/console (debug)
            println!("======================================================");
            println!("  ITMS Endpoint Agent Daemon (v{})", env!("CARGO_PKG_VERSION"));
            println!("  Mode: Interactive Console / Debug Mode");
            println!("======================================================");

            let stop_signal = Arc::new(AtomicBool::new(false));
            let stop_signal_ctrlc = stop_signal.clone();

            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    info!("Menerima Ctrl+C. Memulai proses graceful shutdown...");
                    stop_signal_ctrlc.store(true, Ordering::SeqCst);
                }
            });

            run_daemon_loops(stop_signal).await;
        }
        "--version" | "-v" => {
            println!("itms-agents-daemon v{}", env!("CARGO_PKG_VERSION"));
        }
        "--help" | "-h" | _ => {
            println!("ITMS Endpoint Agent Daemon v{}", env!("CARGO_PKG_VERSION"));
            println!("Penggunaan:");
            println!("  itms-agent run        Jalankan di foreground (interactive/debug)");
            println!("  itms-agent install    Daftarkan sebagai Windows Service (Automatic)");
            println!("  itms-agent uninstall  Hapus Windows Service");
            println!("  itms-agent start      Mulai Windows Service");
            println!("  itms-agent stop       Hentikan Windows Service");
            println!("  itms-agent --version  Tampilkan versi aplikasi");
        }
    }

    Ok(())
}

/// Menjalankan loop daemon utama (Window Tracker, DNS ETW, dan HTTP Flusher)
pub async fn run_daemon_loops(stop_signal: Arc<AtomicBool>) {
    let cfg = AgentConfig::load_or_default();
    info!("Konfigurasi berhasil dimuat. Target server: {}", cfg.server.url);

    let storage = match TelemetryStorage::new(&cfg.storage.db_path, cfg.storage.max_db_size_mb) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("Gagal menginisialisasi SQLite buffer: {}", e);
            return;
        }
    };
    info!("SQLite queue storage aktif pada: {}", cfg.storage.db_path);

    let mut hardware = HardwareCollector::new();
    let identity = hardware.get_identity();
    info!(
        "Identitas Endpoint: Hostname={}, IP={}, MAC={}, UUID={}",
        identity.hostname, identity.ip_address, identity.mac_address, identity.machine_uuid
    );

    // 1. Jalankan Foreground Window Tracker
    let window_tracker = WindowTracker::new(cfg.tracker.clone(), storage.clone());
    let stop_tracker = stop_signal.clone();
    let tracker_handle = tokio::spawn(async move {
        window_tracker.run(stop_tracker).await;
    });

    // 2. Jalankan DNS ETW Sniffer
    let dns_sniffer = DnsEtwSniffer::new(storage.clone());
    let stop_dns = stop_signal.clone();
    let dns_handle = tokio::spawn(async move {
        dns_sniffer.run(stop_dns).await;
    });

    // 3. Jalankan HTTP Batch Flusher Loop
    let flusher = TelemetryFlusher::new(cfg.server.clone(), storage.clone());
    let flusher_interval = Duration::from_secs(cfg.server.flusher_interval_secs);
    let stop_flusher = stop_signal.clone();

    let flusher_handle = tokio::spawn(async move {
        info!("Memulai HTTP Batch Flusher loop (interval: {:?})...", flusher_interval);
        while !stop_flusher.load(Ordering::Relaxed) {
            tokio::time::sleep(flusher_interval).await;
            if stop_flusher.load(Ordering::Relaxed) {
                break;
            }

            if let Err(e) = flusher.flush_once(&mut hardware).await {
                warn!("Gagal melakukan flush telemetri (akan dicoba lagi batch berikutnya): {}", e);
            }
        }
        info!("HTTP Batch Flusher loop dihentikan.");
    });

    // Tunggu hingga sinyal stop aktif
    while !stop_signal.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    info!("Menunggu worker tasks selesai menyimpan data...");
    let _ = tokio::join!(tracker_handle, dns_handle, flusher_handle);
    info!("ITMS Endpoint Agent Daemon sukses dimatikan.");
}
