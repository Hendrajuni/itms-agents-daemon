use crate::config::ServerConfig;
use crate::hardware::{HardwareCollector, SystemMetrics};
use crate::storage::TelemetryStorage;
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
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
    pub metrics: SystemMetrics,
    pub activities: Vec<TelemetryActivityItem>,
}

pub struct TelemetryFlusher {
    server_cfg: ServerConfig,
    storage: Arc<TelemetryStorage>,
    client: reqwest::Client,
}

impl TelemetryFlusher {
    pub fn new(server_cfg: ServerConfig, storage: Arc<TelemetryStorage>) -> Self {
        let timeout = Duration::from_secs(server_cfg.request_timeout_secs);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            server_cfg,
            storage,
            client,
        }
    }

    /// Melakukan push batch rekaman dari offline SQLite ke ITMS backend
    pub async fn flush_once(&self, hardware: &mut HardwareCollector) -> Result<usize, Box<dyn std::error::Error>> {
        let unsynced = self.storage.get_unsynced_batch(self.server_cfg.batch_size)?;
        if unsynced.is_empty() {
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
        let payload = TelemetryPayload {
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            machine_uuid: identity.machine_uuid.clone(),
            hostname: identity.hostname.clone(),
            mac_address: identity.mac_address.clone(),
            ip_address: identity.ip_address.clone(),
            timestamp,
            metrics,
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

        info!("Mengirim batch {} aktivitas telemetri ke {}...", count, self.server_cfg.url);
        let res = self.client.post(&self.server_cfg.url)
            .headers(headers)
            .json(&payload)
            .send()
            .await?;

        if res.status().is_success() {
            info!("Batch {} telemetri sukses terkirim (HTTP {}). Membersihkan antrean lokal...", count, res.status().as_u16());
            self.storage.delete_or_mark_synced(&ids)?;
            Ok(count)
        } else {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            error!("Server menolak pengiriman telemetri (HTTP {}): {}", status, body);
            Err(format!("HTTP Error {}: {}", status, body).into())
        }
    }
}
