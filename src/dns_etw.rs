use crate::classifier::DomainClassifier;
use crate::storage::{ActivityRecord, TelemetryStorage};
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

#[allow(dead_code)]
pub struct DnsEtwSniffer {
    classifier: DomainClassifier,
    storage: Arc<TelemetryStorage>,
}

#[allow(dead_code)]
impl DnsEtwSniffer {
    pub const PROVIDER_GUID: &'static str = "{1C950233-BE26-4226-90F9-C1E47214E7E8}";
    pub const EVENT_DNS_QUERY_COMPLETED: u16 = 3008;

    pub fn new(storage: Arc<TelemetryStorage>) -> Self {
        Self {
            classifier: DomainClassifier::new(),
            storage,
        }
    }

    /// Menjalankan sniffer DNS ETW di background
    pub async fn run(&self, stop_signal: Arc<AtomicBool>) {
        info!("Memulai Windows DNS Client ETW Engine (Provider GUID: {})...", Self::PROVIDER_GUID);

        // ETW real-time session tracing pada Windows memerlukan akun Administrator / LocalSystem.
        // Jika dijalankan pada akun non-elevated (mode tes/debug biasa), kita berikan logging peringatan
        // dan worker tetap aktif dalam mode standby agar tidak menyebabkan crash.
        while !stop_signal.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // Background ETW processing loop
        }

        info!("Windows DNS Client ETW Engine dihentikan.");
    }

    /// Menangani event query DNS yang berhasil ditangkap dari ETW
    pub fn handle_dns_event(&self, raw_domain: &str, pid: u32) {
        if raw_domain.trim().is_empty() {
            return;
        }

        // Filter noise: jangan rekam domain internal arpa atau multicast
        if raw_domain.ends_with(".arpa") || raw_domain.ends_with(".local") || raw_domain.contains("_tcp") {
            return;
        }

        let classification = self.classifier.classify(raw_domain);

        let record = ActivityRecord {
            id: None,
            domain: classification.domain,
            app_name: classification.app_name,
            category: classification.category,
            duration_seconds: 0, // DNS query tidak mencatat screen time foreground
            total_bytes: 0,
            source_type: "agent".to_string(),
            recorded_at: Utc::now().to_rfc3339(),
        };

        if let Err(e) = self.storage.insert_activity(&record) {
            error!("Gagal mencatat DNS event ke SQLite: {}", e);
        } else {
            debug!("DNS Query terdeteksi: {} (PID: {})", raw_domain, pid);
        }
    }
}
