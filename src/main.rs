mod classifier;
mod config;
mod dns_etw;
mod flusher;
mod hardware;
mod net_etw;
mod service;
mod software;
mod spec;
mod storage;
pub mod traffic;
mod window_tracker;

use classifier::is_ignored_network_process_or_domain;
use chrono::Utc;
use config::AgentConfig;
use dns_etw::DnsEtwSniffer;
use flusher::TelemetryFlusher;
use hardware::HardwareCollector;
use net_etw::NetEtwConsumer;
use storage::{ActivityRecord, TelemetryStorage};
use traffic::{DnsResolutionCache, TrafficAggregator};
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

/// Menjalankan loop daemon utama (Window Tracker, DNS ETW, TCPIP Traffic Engine, dan HTTP Flusher)
pub async fn run_daemon_loops(stop_signal: Arc<AtomicBool>) {
    info!("=======================================================");
    info!("  ITMS Endpoint Agent Daemon v{}", env!("CARGO_PKG_VERSION"));
    info!("=======================================================");
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
    let effective_ip = cfg.device.override_ip.as_deref().unwrap_or(&identity.ip_address);
    let effective_mac = cfg.device.override_mac.as_deref().unwrap_or(&identity.mac_address);
    let effective_hostname = cfg.device.override_hostname.as_deref().unwrap_or(&identity.hostname);
    info!(
        "Identitas Endpoint: Hostname={}, IP={}, MAC={}, UUID={}",
        effective_hostname, effective_ip, effective_mac, identity.machine_uuid
    );

    // Inisialisasi In-Memory DNS Cache & Traffic Aggregator
    let dns_cache = DnsResolutionCache::new(10000, 1800); // 10.000 entri, TTL 30 menit
    let traffic_aggregator = TrafficAggregator::new();
    let active_browser_domain = Arc::new(std::sync::RwLock::new(None));

    // 1. Jalankan Foreground Window Tracker (dengan korelasi real bytes)
    let window_tracker = WindowTracker::new(
        cfg.tracker.clone(),
        storage.clone(),
        traffic_aggregator.clone(),
        active_browser_domain.clone(),
    );
    let stop_tracker = stop_signal.clone();
    let tracker_handle = tokio::spawn(async move {
        window_tracker.run(stop_tracker).await;
    });

    // 2. Jalankan DNS ETW Sniffer (dengan feeding IP resolusi ke DNS Cache)
    let dns_sniffer = DnsEtwSniffer::new(storage.clone(), dns_cache.clone());
    let stop_dns = stop_signal.clone();
    let dns_handle = tokio::spawn(async move {
        dns_sniffer.run(stop_dns).await;
    });

    // 3. Jalankan TCPIP & UDP Network Traffic Accounting Engine
    let net_consumer = NetEtwConsumer::new(
        dns_cache.clone(),
        traffic_aggregator.clone(),
        active_browser_domain.clone(),
    );
    let stop_net = stop_signal.clone();
    let net_handle = tokio::spawn(async move {
        net_consumer.run(stop_net).await;
    });

    // 4. Background Traffic Drain & DNS Cache Pruner Loop (setiap 10 detik)
    let bg_aggregator = traffic_aggregator.clone();
    let bg_storage = storage.clone();
    let bg_dns_cache = dns_cache.clone();
    let stop_bg = stop_signal.clone();
    let bg_handle = tokio::spawn(async move {
        let mut loop_count: u32 = 0;
        while !stop_bg.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(10)).await;
            if stop_bg.load(Ordering::Relaxed) {
                break;
            }

            loop_count = loop_count.wrapping_add(1);

            // Bersihkan DNS cache yang expired setiap 5 menit (30 iterasi x 10s)
            if loop_count % 30 == 0 {
                bg_dns_cache.prune_expired();
            }

            // Kuras traffic background yang tidak terafiliasi dengan window foreground
            let deltas = bg_aggregator.drain_deltas();
            for delta in deltas {
                // Abaikan proses internal Windows (mpcmdrun, svchost, textinputhost, dll) dan pid_*.exe
                if is_ignored_network_process_or_domain(&delta.domain)
                    || is_ignored_network_process_or_domain(&delta.app_name)
                {
                    continue;
                }

                let record = ActivityRecord {
                    id: None,
                    domain: delta.domain,
                    app_name: delta.app_name,
                    category: delta.category,
                    duration_seconds: 0, // background network activity
                    total_bytes: delta.total_bytes,
                    source_type: "agent".to_string(),
                    recorded_at: Utc::now().to_rfc3339(),
                };
                let _ = bg_storage.upsert_or_accumulate_activity(&record);
            }
        }
    });

    // 5. Jalankan HTTP Batch Flusher Loop
    let flusher = TelemetryFlusher::new(cfg.server.clone(), cfg.device.clone(), storage.clone());
    let flusher_interval = Duration::from_secs(cfg.server.flusher_interval_secs);
    let stop_flusher = stop_signal.clone();

    let flusher_handle = tokio::spawn(async move {
        info!("Memulai HTTP Batch Flusher loop (interval: {:?})...", flusher_interval);

        // Pengiriman awal (Initial Sync) 2 detik setelah start untuk registrasi inventaris
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !stop_flusher.load(Ordering::Relaxed) {
            if let Err(e) = flusher.flush_once(&mut hardware).await {
                warn!("Initial Telemetry & Inventory Sync tertunda (akan dicoba lagi pada siklus berikutnya): {}", e);
            }
        }

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

    info!("Menunggu seluruh worker tasks selesai menyimpan data...");
    let _ = tokio::join!(tracker_handle, dns_handle, net_handle, bg_handle, flusher_handle);
    info!("ITMS Endpoint Agent Daemon sukses dimatikan.");
}
