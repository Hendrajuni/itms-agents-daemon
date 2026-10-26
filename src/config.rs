use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server: ServerConfig,
    pub tracker: TrackerConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub agent_key: String,
    #[serde(default = "default_flusher_interval")]
    pub flusher_interval_secs: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerConfig {
    #[serde(default = "default_window_sampling")]
    pub window_sampling_secs: u64,
    #[serde(default = "default_idle_threshold")]
    pub idle_threshold_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_db_path")]
    pub db_path: String,
    #[serde(default = "default_max_db_size")]
    pub max_db_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

fn default_flusher_interval() -> u64 { 60 }
fn default_batch_size() -> usize { 100 }
fn default_timeout() -> u64 { 15 }
fn default_window_sampling() -> u64 { 3 }
fn default_idle_threshold() -> u64 { 300 }
fn default_db_path() -> String { "C:\\ProgramData\\ITMS\\buffer\\telemetry_queue.db".to_string() }
fn default_max_db_size() -> u64 { 50 }
fn default_log_level() -> String { "info".to_string() }

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                url: "https://itms.domain.com/network/api/telemetry/push/".to_string(),
                agent_key: "sec-agent-token-xyz-123".to_string(),
                flusher_interval_secs: default_flusher_interval(),
                batch_size: default_batch_size(),
                request_timeout_secs: default_timeout(),
            },
            tracker: TrackerConfig {
                window_sampling_secs: default_window_sampling(),
                idle_threshold_secs: default_idle_threshold(),
            },
            storage: StorageConfig {
                db_path: default_db_path(),
                max_db_size_mb: default_max_db_size(),
            },
            logging: LoggingConfig {
                level: default_log_level(),
            },
        }
    }
}

impl AgentConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_or_default() -> Self {
        // Cek path konfigurasi berurutan:
        // 1. config/agent.toml (relative ke binary)
        // 2. %PROGRAMDATA%\ITMS\agent.toml
        let local_cfg = Path::new("config/agent.toml");
        if local_cfg.exists() {
            if let Ok(cfg) = Self::load_from_file(local_cfg) {
                return cfg;
            }
        }

        let progdata_cfg = Path::new(r"C:\ProgramData\ITMS\agent.toml");
        if progdata_cfg.exists() {
            if let Ok(cfg) = Self::load_from_file(progdata_cfg) {
                return cfg;
            }
        }

        Self::default()
    }
}
