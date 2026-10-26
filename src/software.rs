use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_date: String,
}

#[derive(Debug, Deserialize)]
struct RawAppItem {
    #[serde(rename = "DisplayName")]
    display_name: Option<String>,
    #[serde(rename = "DisplayVersion")]
    display_version: Option<String>,
    #[serde(rename = "Publisher")]
    publisher: Option<String>,
    #[serde(rename = "InstallDate")]
    install_date: Option<String>,
}

pub struct SoftwareScanner;

impl SoftwareScanner {
    /// Melakukan pemindaian seluruh registry Windows untuk aplikasi yang terinstal
    pub fn scan_installed_apps() -> Vec<InstalledApp> {
        info!("Memulai audit inventaris aplikasi desktop terinstal (Windows Registry)...");

        let script = r#"$apps = @(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate); ConvertTo-Json -InputObject @($apps) -Compress"#;

        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", script])
            .output();

        let raw_apps: Vec<RawAppItem> = match output {
            Ok(out) => {
                let stdout_str = String::from_utf8_lossy(&out.stdout);
                let trimmed = stdout_str.trim();
                if trimmed.is_empty() {
                    Vec::new()
                } else {
                    serde_json::from_str(trimmed).unwrap_or_else(|e| {
                        warn!("Gagal parsing JSON output aplikasi dari PowerShell: {}. Mencoba parsing single-object.", e);
                        // Coba parse jika hanya satu objek
                        if let Ok(single) = serde_json::from_str::<RawAppItem>(trimmed) {
                            vec![single]
                        } else {
                            Vec::new()
                        }
                    })
                }
            }
            Err(e) => {
                warn!("Gagal menjalankan scanner registry aplikasi: {}", e);
                Vec::new()
            }
        };

        Self::sanitize_and_deduplicate(raw_apps)
    }

    /// Membersihkan entri sistem/KB dan melakukan de-duplikasi nama aplikasi
    fn sanitize_and_deduplicate(raw_list: Vec<RawAppItem>) -> Vec<InstalledApp> {
        let mut app_map: HashMap<String, InstalledApp> = HashMap::new();

        for item in raw_list {
            let name = match item.display_name {
                Some(n) => n.trim().to_string(),
                None => continue,
            };

            if name.is_empty() {
                continue;
            }

            // Abaikan rollup hotfix Windows / KB updates
            if name.starts_with("KB") && name.chars().nth(2).map(|c| c.is_ascii_digit()).unwrap_or(false) {
                continue;
            }
            if name.starts_with("Security Update for") || name.starts_with("Update for Windows") {
                continue;
            }
            // Abaikan nama yang hanya berisi GUID installer {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
            if name.starts_with('{') && name.ends_with('}') && name.len() == 38 {
                continue;
            }

            let version = item.display_version
                .map(|v| v.trim().to_string())
                .unwrap_or_default();

            let publisher = item.publisher
                .map(|p| p.trim().to_string())
                .unwrap_or_default();

            let install_date = Self::format_install_date(item.install_date.as_deref());

            let normalized_key = name.to_lowercase();
            let new_app = InstalledApp {
                name,
                version,
                publisher,
                install_date,
            };

            // Jika aplikasi sudah ada, simpan yang memiliki versi lebih lengkap
            if let Some(existing) = app_map.get_mut(&normalized_key) {
                if existing.version.is_empty() && !new_app.version.is_empty() {
                    *existing = new_app;
                }
            } else {
                app_map.insert(normalized_key, new_app);
            }
        }

        let mut results: Vec<InstalledApp> = app_map.into_values().collect();
        results.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        info!("Audit aplikasi selesai: ditemukan {} aplikasi aktif.", results.len());
        results
    }

    /// Normalisasi format tanggal YYYYMMDD menjadi YYYY-MM-DD
    fn format_install_date(raw: Option<&str>) -> String {
        let s = match raw {
            Some(v) => v.trim(),
            None => return String::new(),
        };

        if s.len() == 8 && s.chars().all(|c| c.is_ascii_digit()) {
            format!("{}-{}-{}", &s[0..4], &s[4..6], &s[6..8])
        } else {
            s.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_install_date() {
        assert_eq!(SoftwareScanner::format_install_date(Some("20260710")), "2026-07-10");
        assert_eq!(SoftwareScanner::format_install_date(Some("2026-05-12")), "2026-05-12");
        assert_eq!(SoftwareScanner::format_install_date(None), "");
    }

    #[test]
    fn test_scan_installed_apps() {
        let apps = SoftwareScanner::scan_installed_apps();
        // Pada mesin Windows pengembangan harusnya terdeteksi setidaknya beberapa aplikasi
        assert!(!apps.is_empty());
        println!("Contoh aplikasi pertama yang terdeteksi: {:?}", apps.first());
    }
}
