use crate::config::ServerConfig;
use crate::service::SERVICE_NAME;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[derive(Debug, Deserialize)]
pub struct LatestReleaseResponse {
    #[serde(default)]
    pub has_release: bool,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub download_url: Option<String>,
}

/// Parsing SemVer "v0.4.1" / "0.4.1" menjadi tuple (major, minor, patch)
pub fn parse_semver(version: &str) -> (u64, u64, u64) {
    let cleaned = version
        .trim()
        .trim_start_matches('v')
        .trim_start_matches('V');
    let base = cleaned.split(&['-', '+'][..]).next().unwrap_or(cleaned);
    let mut parts = base.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch)
}

/// Mengembalikan true jika `latest` lebih baru dari `current` secara SemVer
pub fn is_newer_version(latest: &str, current: &str) -> bool {
    parse_semver(latest) > parse_semver(current)
}

/// Menghitung hash SHA-256 hex (lowercase) dari sebuah file
pub fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex_str = String::with_capacity(64);
    for b in digest {
        hex_str.push_str(&format!("{:02x}", b));
    }
    Ok(hex_str)
}

/// Menggabungkan URL relatif download (e.g. `/network/api/agent/download/0.4.1/`) dengan origin dari `server_url`
pub fn resolve_download_url(server_url: &str, download_url: &str) -> String {
    let trimmed = download_url.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return trimmed.to_string();
    }
    // Ambil origin (scheme://host[:port]) dari server_url
    if let Some(scheme_idx) = server_url.find("://") {
        let after_scheme = &server_url[scheme_idx + 3..];
        let origin_end = after_scheme
            .find('/')
            .map(|i| scheme_idx + 3 + i)
            .unwrap_or(server_url.len());
        let origin = &server_url[..origin_end];
        if trimmed.starts_with('/') {
            format!("{}{}", origin, trimmed)
        } else {
            format!("{}/{}", origin, trimmed)
        }
    } else {
        trimmed.to_string()
    }
}

/// Menghapus sisa file `.old` dan `.new` di sebelah binary saat daemon baru menyala
pub fn cleanup_old_binaries() {
    if let Ok(exe_path) = std::env::current_exe() {
        let old_path = append_extension(&exe_path, "old");
        if old_path.exists() {
            match fs::remove_file(&old_path) {
                Ok(_) => info!("OTA Cleanup: file binary lama {:?} berhasil dihapus.", old_path),
                Err(e) => warn!("OTA Cleanup: gagal menghapus {:?}: {}", old_path, e),
            }
        }
        let new_path = append_extension(&exe_path, "new");
        if new_path.exists() {
            let _ = fs::remove_file(&new_path);
        }
    }
}

fn append_extension(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".");
    s.push(suffix);
    PathBuf::from(s)
}

pub struct OtaUpdater {
    server_cfg: ServerConfig,
    machine_uuid: String,
    check_interval_secs: u64,
    client: reqwest::Client,
}

impl OtaUpdater {
    pub fn new(server_cfg: ServerConfig, machine_uuid: String, check_interval_secs: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            server_cfg,
            machine_uuid,
            check_interval_secs: check_interval_secs.max(300),
            client,
        }
    }

    pub async fn run(&self, stop_signal: Arc<AtomicBool>) {
        info!(
            "OTA Auto-Updater aktif (versi saat ini: v{}, interval cek: {}s).",
            env!("CARGO_PKG_VERSION"),
            self.check_interval_secs
        );

        // Tunggu 60 detik setelah startup sebelum cek OTA pertama kali
        for _ in 0..60 {
            if stop_signal.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        loop {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            match self.check_and_apply_update(&stop_signal).await {
                Ok(true) => {
                    info!("OTA Update diterapkan! Menunggu restart service...");
                    break;
                }
                Ok(false) => {
                    debug!("OTA Check: versi agent sudah paling baru.");
                }
                Err(e) => {
                    warn!("OTA Check/Update gagal (akan dicoba lagi pada siklus berikutnya): {}", e);
                }
            }

            let mut waited = 0u64;
            while waited < self.check_interval_secs && !stop_signal.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                waited += 1;
            }
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(key_val) = HeaderValue::from_str(&self.server_cfg.agent_key) {
            headers.insert("X-ITMS-Agent-Key", key_val.clone());
            headers.insert("X-ITMS-Agent-Token", key_val);
        }
        if let Ok(uuid_val) = HeaderValue::from_str(&self.machine_uuid) {
            headers.insert("X-Machine-UUID", uuid_val);
        }
        headers
    }

    /// Mengecek manifest terbaru; jika ada versi lebih baru, unduh, verifikasi SHA-256, smoke test,
    /// lakukan atomic rename swap, dan jadwalkan restart service bersih.
    async fn check_and_apply_update(
        &self,
        stop_signal: &Arc<AtomicBool>,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let manifest_url = self.server_cfg.get_latest_release_url();
        let res = self
            .client
            .get(&manifest_url)
            .headers(self.build_headers())
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(format!("Manifest HTTP {}", res.status()).into());
        }

        let manifest: LatestReleaseResponse = res.json().await?;
        if !manifest.has_release {
            return Ok(false);
        }

        let Some(latest_ver) = manifest.version.as_deref() else {
            return Ok(false);
        };
        let current_ver = env!("CARGO_PKG_VERSION");

        if !is_newer_version(latest_ver, current_ver) {
            return Ok(false);
        }

        let expected_sha = manifest
            .sha256
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if expected_sha.len() != 64 {
            return Err("SHA-256 manifest tidak valid (harus 64 karakter hex)".into());
        }

        let Some(raw_dl_url) = manifest.download_url.as_deref() else {
            return Err("Manifest tidak menyertakan download_url".into());
        };
        let full_dl_url = resolve_download_url(&self.server_cfg.url, raw_dl_url);

        info!(
            "OTA Update ditemukan: v{} -> v{}. Mengunduh binary dari {}...",
            current_ver, latest_ver, full_dl_url
        );

        let exe_path = std::env::current_exe()?;
        let new_path = append_extension(&exe_path, "new");
        let old_path = append_extension(&exe_path, "old");

        // 1. Download binary ke file sementara `.new`
        let dl_res = self
            .client
            .get(&full_dl_url)
            .headers(self.build_headers())
            .send()
            .await?;
        if !dl_res.status().is_success() {
            return Err(format!("Download binary gagal: HTTP {}", dl_res.status()).into());
        }
        let bytes = dl_res.bytes().await?;
        {
            let mut out = File::create(&new_path)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
        }

        // 2. Verifikasi integritas SHA-256
        let actual_sha = compute_file_sha256(&new_path)?;
        if actual_sha != expected_sha {
            let _ = fs::remove_file(&new_path);
            error!(
                "OTA ABORT: SHA-256 tidak cocok! Expected={}, Actual={}",
                expected_sha, actual_sha
            );
            return Err("SHA-256 mismatch".into());
        }
        info!("OTA SHA-256 terverifikasi cocok ({}).", &actual_sha[..12]);

        // 3. Smoke test binary baru dengan `--version`
        let smoke = Command::new(&new_path).arg("--version").output();
        match smoke {
            Ok(out) if out.status.success() => {
                let ver_out = String::from_utf8_lossy(&out.stdout);
                if !ver_out.contains("itms-agents-daemon") {
                    let _ = fs::remove_file(&new_path);
                    return Err(format!("Smoke test output tidak valid: {}", ver_out).into());
                }
                info!("OTA Smoke Test LULUS: {}", ver_out.trim());
            }
            Ok(out) => {
                let _ = fs::remove_file(&new_path);
                return Err(format!("Smoke test gagal (exit={:?})", out.status.code()).into());
            }
            Err(e) => {
                let _ = fs::remove_file(&new_path);
                return Err(format!("Gagal menjalankan smoke test: {}", e).into());
            }
        }

        // 4. Atomic Rename Swap (Windows mengizinkan rename file .exe yang sedang berjalan)
        if old_path.exists() {
            let _ = fs::remove_file(&old_path);
        }
        fs::rename(&exe_path, &old_path)?;
        if let Err(e) = fs::rename(&new_path, &exe_path) {
            // Rollback jika rename tahap 2 gagal
            error!("OTA Swap gagal pada rename tahap 2: {}. Melakukan rollback...", e);
            let _ = fs::rename(&old_path, &exe_path);
            let _ = fs::remove_file(&new_path);
            return Err(format!("Atomic swap gagal: {}", e).into());
        }

        info!(
            "OTA Atomic Swap BERHASIL (v{} -> v{}). Menjadwalkan restart Windows Service {}...",
            current_ver, latest_ver, SERVICE_NAME
        );

        // 5. Jadwalkan restart service secara terpisah lalu picu graceful shutdown
        let restart_cmd = format!(
            "timeout /t 2 /nobreak >nul & sc stop {} >nul 2>&1 & timeout /t 3 /nobreak >nul & sc start {} >nul 2>&1",
            SERVICE_NAME, SERVICE_NAME
        );
        let _ = Command::new("cmd.exe")
            .args(["/C", &restart_cmd])
            .spawn();

        stop_signal.store(true, Ordering::SeqCst);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_comparison() {
        assert!(is_newer_version("0.4.1", "0.4.0"));
        assert!(is_newer_version("v0.5.0", "0.4.9"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(!is_newer_version("0.4.0", "0.4.0"));
        assert!(!is_newer_version("0.3.9", "0.4.0"));
    }

    #[test]
    fn test_resolve_download_url() {
        assert_eq!(
            resolve_download_url(
                "https://itms.pmgcloud.my.id/network/api/telemetry/push/",
                "/network/api/agent/download/0.4.1/"
            ),
            "https://itms.pmgcloud.my.id/network/api/agent/download/0.4.1/"
        );
        assert_eq!(
            resolve_download_url(
                "http://127.0.0.1:8000/network/api/telemetry/push/",
                "https://cdn.example.com/agent.exe"
            ),
            "https://cdn.example.com/agent.exe"
        );
    }

    #[test]
    fn test_compute_file_sha256() {
        let tmp = std::env::temp_dir().join("itms_sha256_test.bin");
        fs::write(&tmp, b"abc").unwrap();
        let sha = compute_file_sha256(&tmp).unwrap();
        let _ = fs::remove_file(&tmp);
        // NIST standard test vector: sha256("abc")
        assert_eq!(sha.len(), 64);
        assert_eq!(
            sha,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
