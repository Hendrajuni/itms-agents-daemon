use crate::config::{DeviceConfig, ServerConfig};
use crate::hardware::{HardwareCollector, SystemMetrics};
use crate::software::{InstalledApp, SoftwareScanner};
use crate::spec::{DeviceSpec, SpecCollector};
use crate::storage::TelemetryStorage;
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryActivityItem {
    pub domain: String,
    pub app_name: String,
    pub category: String,
    pub duration_seconds: u32,
    pub total_bytes: u64,
    pub source_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TelemetryPayload {
    pub agent_version: String,
    pub machine_uuid: String,
    pub hostname: String,
    pub mac_address: String,
    pub ip_address: String,
    pub timestamp: String,
    pub is_full_inventory: bool,
    pub metrics: SystemMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_spec: Option<DeviceSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_apps: Option<Vec<InstalledApp>>,
    pub activities: Vec<TelemetryActivityItem>,
}

pub struct TelemetryFlusher {
    server_cfg: ServerConfig,
    device_cfg: DeviceConfig,
    storage: Arc<TelemetryStorage>,
    client: reqwest::Client,
    last_inventory_sync: Arc<Mutex<Option<Instant>>>,
}

impl TelemetryFlusher {
    pub fn new(server_cfg: ServerConfig, device_cfg: DeviceConfig, storage: Arc<TelemetryStorage>) -> Self {
        let timeout = Duration::from_secs(server_cfg.request_timeout_secs);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            server_cfg,
            device_cfg,
            storage,
            client,
            last_inventory_sync: Arc::new(Mutex::new(None)),
        }
    }

    /// Melakukan push batch rekaman dari offline SQLite ke ITMS backend,
    /// serta mengelola sinkronisasi penuh profil hardware & software inventory.
    pub async fn flush_once(&self, hardware: &mut HardwareCollector) -> Result<usize, Box<dyn std::error::Error>> {
        let mut sync_guard = self.last_inventory_sync.lock().await;

        // Tentukan apakah perlu mengirimkan Full Inventory (saat start pertama kali atau interval 24 jam)
        let should_full_sync = match *sync_guard {
            None => true,
            Some(last) => last.elapsed() >= Duration::from_secs(24 * 3600),
        };

        let unsynced = self.storage.get_unsynced_batch(self.server_cfg.batch_size)?;

        // Jika tidak ada data aktivitas dan tidak sedang dalam jadwal full sync, lewati
        if unsynced.is_empty() && !should_full_sync {
            debug!("Tidak ada data telemetri yang perlu di-flush.");
            return Ok(0);
        }

        let identity = hardware.get_identity();
        let metrics = hardware.get_metrics();
        let timestamp = Utc::now().to_rfc3339();

        let mut ids = Vec::new();
        let mut activities = Vec::new();

        for item in unsynced {
            if let Some(id) = item.id {
                ids.push(id);
            }
            activities.push(TelemetryActivityItem {
                domain: item.domain,
                app_name: item.app_name,
                category: item.category,
                duration_seconds: item.duration_seconds,
                total_bytes: item.total_bytes,
                source_type: item.source_type,
            });
        }

        let count = activities.len();
        let effective_ip = self.device_cfg.override_ip.as_deref().unwrap_or(&identity.ip_address);
        let effective_mac = self.device_cfg.override_mac.as_deref().unwrap_or(&identity.mac_address);
        let effective_hostname = self.device_cfg.override_hostname.as_deref().unwrap_or(&identity.hostname);

        let (device_spec, installed_apps) = if should_full_sync {
            info!("Memicu Full Inventory Sync (Spesifikasi Hardware & Audit Software Terinstal)...");
            let spec = SpecCollector::collect();
            let apps = SoftwareScanner::scan_installed_apps();
            (Some(spec), Some(apps))
        } else {
            (None, None)
        };

        let payload = TelemetryPayload {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            machine_uuid: identity.machine_uuid.clone(),
            hostname: effective_hostname.to_string(),
            mac_address: effective_mac.to_string(),
            ip_address: effective_ip.to_string(),
            timestamp,
            is_full_inventory: should_full_sync,
            metrics,
            device_spec,
            installed_apps,
            activities,
        };

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(key_val) = HeaderValue::from_str(&self.server_cfg.agent_key) {
            headers.insert("X-ITMS-Agent-Key", key_val);
        }
        if let Ok(uuid_val) = HeaderValue::from_str(&identity.machine_uuid) {
            headers.insert("X-Machine-UUID", uuid_val);
        }

        if should_full_sync {
            info!(
                "Mengirim payload FULL INVENTORY & {} aktivitas telemetri ke {}...",
                count, self.server_cfg.url
            );
        } else {
            info!("Mengirim batch {} aktivitas telemetri ke {}...", count, self.server_cfg.url);
        }

        let res = self.client.post(&self.server_cfg.url)
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        if res.status().is_success() {
            let status_code = res.status().as_u16();
            let resp_text = res.text().await.unwrap_or_default();

            if should_full_sync {
                info!(
                    "Full Inventory Sync SUKSES terkirim (HTTP {}). Server respon: {}",
                    status_code, resp_text
                );
                *sync_guard = Some(Instant::now());
            } else {
                info!("Batch {} telemetri sukses terkirim (HTTP {}).", count, status_code);
            }

            if !ids.is_empty() {
                self.storage.delete_or_mark_synced(&ids)?;
            }
            Ok(count)
        } else {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            error!("Server menolak pengiriman telemetri (HTTP {}): {}", status, body);
            Err(format!("HTTP Error {}: {}", status, body).into())
        }
    }
}
