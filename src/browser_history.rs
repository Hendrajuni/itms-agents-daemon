use crate::storage::{BrowserVisitRecord, TelemetryStorage};
use chrono::{DateTime, Local, TimeZone, Utc};
use rusqlite::{params, Connection, OpenFlags};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Selisih detik antara epoch Windows/WebKit (1601-01-01) dan epoch Unix (1970-01-01)
const WEBKIT_UNIX_EPOCH_DIFF_SECS: i64 = 11_644_473_600;

/// Konversi timestamp WebKit (microseconds sejak 1601-01-01 UTC) ke DateTime<Utc>
pub fn webkit_to_utc(webkit_us: i64) -> Option<DateTime<Utc>> {
    if webkit_us <= 0 {
        return None;
    }
    let unix_secs = (webkit_us / 1_000_000) - WEBKIT_UNIX_EPOCH_DIFF_SECS;
    let nanos = ((webkit_us % 1_000_000).unsigned_abs() as u32) * 1000;
    if unix_secs < 0 {
        return None;
    }
    Utc.timestamp_opt(unix_secs, nanos).single()
}

/// Konversi Unix seconds ke timestamp WebKit (microseconds sejak 1601-01-01 UTC)
pub fn unix_secs_to_webkit(unix_secs: i64) -> i64 {
    (unix_secs + WEBKIT_UNIX_EPOCH_DIFF_SECS).saturating_mul(1_000_000)
}

/// Mengambil batas awal hari ini (00:00:00 waktu lokal) dalam format WebKit microseconds.
/// Digunakan sebagai watermark awal saat profil browser pertama kali dipindai agar tidak membanjiri server dengan riwayat lama.
fn today_start_webkit_us() -> i64 {
    let now_local = Local::now();
    let today_naive = now_local.date_naive().and_hms_opt(0, 0, 0).unwrap();
    let today_utc_secs = Local
        .from_local_datetime(&today_naive)
        .single()
        .map(|dt| dt.with_timezone(&Utc).timestamp())
        .unwrap_or_else(|| Utc::now().timestamp() - 86400);
    unix_secs_to_webkit(today_utc_secs)
}

/// Mengekstrak domain bersih dari URL http/https. Mengembalikan None untuk scheme internal/lokal.
pub fn extract_domain_from_url(raw_url: &str) -> Option<String> {
    let trimmed = raw_url.trim();
    let rest = if let Some(r) = trimmed.strip_prefix("https://") {
        r
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        r
    } else {
        return None;
    };

    // Ambil bagian authority sebelum '/', '?', '#'
    let authority = rest.split(&['/', '?', '#'][..]).next()?;
    // Buang userinfo jika ada (user:pass@host)
    let host_port = authority.rsplit('@').next()?;
    // Abaikan IPv6 literal [::1]
    if host_port.starts_with('[') {
        return None;
    }
    // Buang port (:8080)
    let host = host_port.split(':').next()?.trim().to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_string();

    if host.is_empty()
        || !host.contains('.')
        || host == "localhost"
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return None;
    }

    Some(host)
}

struct BrowserProfile {
    browser_name: &'static str,
    profile_key: String,
    history_path: PathBuf,
}

/// Menemukan semua file SQLite `History` milik Chrome dan Edge di seluruh profil C:\Users\*
fn discover_browser_profiles() -> Vec<BrowserProfile> {
    let mut profiles = Vec::new();
    let users_dir = Path::new(r"C:\Users");
    let Ok(entries) = fs::read_dir(users_dir) else {
        return profiles;
    };

    let skip_users = ["public", "default", "default user", "all users"];

    for entry in entries.flatten() {
        let user_path = entry.path();
        if !user_path.is_dir() {
            continue;
        }
        let user_name = entry.file_name().to_string_lossy().to_string();
        if skip_users.contains(&user_name.to_lowercase().as_str()) {
            continue;
        }

        let targets: [(&'static str, PathBuf); 2] = [
            (
                "Chrome",
                user_path.join(r"AppData\Local\Google\Chrome\User Data"),
            ),
            (
                "Edge",
                user_path.join(r"AppData\Local\Microsoft\Edge\User Data"),
            ),
        ];

        for (browser_name, user_data_dir) in targets {
            if !user_data_dir.is_dir() {
                continue;
            }

            // Cek Default dan Profile *
            if let Ok(sub_entries) = fs::read_dir(&user_data_dir) {
                for sub in sub_entries.flatten() {
                    let sub_name = sub.file_name().to_string_lossy().to_string();
                    if sub_name == "Default" || sub_name.starts_with("Profile ") {
                        let hist_path = sub.path().join("History");
                        if hist_path.is_file() {
                            let profile_key = format!(
                                "{}|{}|{}",
                                user_name.to_lowercase(),
                                browser_name.to_lowercase(),
                                sub_name.to_lowercase()
                            );
                            profiles.push(BrowserProfile {
                                browser_name,
                                profile_key,
                                history_path: hist_path,
                            });
                        }
                    }
                }
            }
        }
    }

    profiles
}

pub struct BrowserHistoryScanner {
    storage: Arc<TelemetryStorage>,
    scan_interval_secs: u64,
}

impl BrowserHistoryScanner {
    pub fn new(storage: Arc<TelemetryStorage>, scan_interval_secs: u64) -> Self {
        Self {
            storage,
            scan_interval_secs: scan_interval_secs.max(30),
        }
    }

    pub async fn run(&self, stop_signal: Arc<AtomicBool>) {
        info!(
            "Memulai Browser History Scanner (Chrome/Edge, interval: {}s)...",
            self.scan_interval_secs
        );

        // Scan awal 15 detik setelah start agar service selesai inisialisasi dulu
        for _ in 0..15 {
            if stop_signal.load(Ordering::Relaxed) {
                return;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        loop {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            let storage_clone = self.storage.clone();
            let scan_res = tokio::task::spawn_blocking(move || scan_all_profiles(&storage_clone)).await;
            match scan_res {
                Ok(count) if count > 0 => {
                    info!("Browser History Scanner: {} domain kunjungan baru masuk antrean.", count);
                }
                Ok(_) => {
                    debug!("Browser History Scanner: tidak ada kunjungan browser baru.");
                }
                Err(e) => {
                    warn!("Browser History Scanner task error: {}", e);
                }
            }

            let mut waited = 0u64;
            while waited < self.scan_interval_secs && !stop_signal.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                waited += 1;
            }
        }

        info!("Browser History Scanner dihentikan.");
    }
}

/// Memindai semua profil Chrome/Edge secara aman (safe copy ke temp) dan memasukkan agregasi kunjungan baru ke SQLite queue
fn scan_all_profiles(storage: &TelemetryStorage) -> usize {
    let profiles = discover_browser_profiles();
    if profiles.is_empty() {
        return 0;
    }

    let mut total_queued = 0usize;
    let temp_dir = std::env::temp_dir();

    for (idx, prof) in profiles.iter().enumerate() {
        let existing_wm = storage.get_browser_watermark(&prof.profile_key).unwrap_or(0);
        let effective_wm = if existing_wm > 0 {
            existing_wm
        } else {
            today_start_webkit_us()
        };

        // Buat salinan aman ke temp agar tidak bentrok lock saat browser sedang aktif
        let stamp = Utc::now().timestamp_millis();
        let temp_db = temp_dir.join(format!("itms_hist_{}_{}.db", stamp, idx));
        let temp_wal = temp_dir.join(format!("itms_hist_{}_{}.db-wal", stamp, idx));
        let temp_shm = temp_dir.join(format!("itms_hist_{}_{}.db-shm", stamp, idx));

        if let Err(e) = fs::copy(&prof.history_path, &temp_db) {
            debug!("Lewati profil {} (gagal copy History): {}", prof.profile_key, e);
            continue;
        }

        // Ikut salin file -wal jika ada agar transaksi terbaru yang belum di-checkpoint terbaca
        let mut src_wal = prof.history_path.as_os_str().to_os_string();
        src_wal.push("-wal");
        let src_wal_path = PathBuf::from(src_wal);
        if src_wal_path.is_file() {
            let _ = fs::copy(&src_wal_path, &temp_wal);
        }

        let scan_result = read_history_snapshot(&temp_db, effective_wm, prof.browser_name);

        // Bersihkan file temp segera
        let _ = fs::remove_file(&temp_db);
        let _ = fs::remove_file(&temp_wal);
        let _ = fs::remove_file(&temp_shm);

        match scan_result {
            Ok((records, max_visit_time)) => {
                if !records.is_empty() {
                    match storage.insert_browser_visits(&records) {
                        Ok(n) => {
                            total_queued += n;
                            if max_visit_time > effective_wm {
                                let _ = storage.set_browser_watermark(&prof.profile_key, max_visit_time);
                            }
                        }
                        Err(e) => {
                            warn!("Gagal menyimpan browser_visits ke SQLite buffer: {}", e);
                        }
                    }
                } else if existing_wm == 0 {
                    // Simpan watermark awal hari ini agar iterasi berikutnya tetap inkremental
                    let _ = storage.set_browser_watermark(&prof.profile_key, effective_wm);
                }
            }
            Err(e) => {
                debug!("Gagal membaca snapshot SQLite profil {}: {}", prof.profile_key, e);
            }
        }
    }

    total_queued
}

fn read_history_snapshot(
    db_path: &Path,
    since_webkit_us: i64,
    browser_name: &str,
) -> Result<(Vec<BrowserVisitRecord>, i64), rusqlite::Error> {
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut stmt = conn.prepare(
        "SELECT u.url, u.title, v.visit_time
         FROM visits v
         INNER JOIN urls u ON v.url = u.id
         WHERE v.visit_time > ?1
         ORDER BY v.visit_time ASC
         LIMIT 2000;",
    )?;

    let rows = stmt.query_map(params![since_webkit_us], |row| {
        let url: String = row.get(0)?;
        let title: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        let visit_time: i64 = row.get(2)?;
        Ok((url, title, visit_time))
    })?;

    // Agregasi kunjungan baru per domain dalam jendela scan ini
    // Key: domain -> (latest_title, count, latest_visit_time_us)
    let mut agg: HashMap<String, (String, u32, i64)> = HashMap::new();
    let mut max_visit_time = since_webkit_us;

    for row_res in rows {
        let Ok((url, title, visit_time)) = row_res else {
            continue;
        };
        if visit_time > max_visit_time {
            max_visit_time = visit_time;
        }
        let Some(domain) = extract_domain_from_url(&url) else {
            continue;
        };

        let clean_title = title.trim().chars().take(280).collect::<String>();
        let entry = agg.entry(domain).or_insert_with(|| (String::new(), 0, visit_time));
        entry.1 = entry.1.saturating_add(1);
        if visit_time >= entry.2 {
            entry.2 = visit_time;
            if !clean_title.is_empty() {
                entry.0 = clean_title;
            }
        }
    }

    let mut records = Vec::with_capacity(agg.len());
    for (domain, (page_title, visit_count, latest_us)) in agg {
        let last_visited_at = webkit_to_utc(latest_us)
            .unwrap_or_else(Utc::now)
            .to_rfc3339();
        records.push(BrowserVisitRecord {
            id: None,
            domain,
            page_title,
            browser: browser_name.to_string(),
            visit_count,
            last_visited_at,
            source_type: "browser_history".to_string(),
        });
    }

    Ok((records, max_visit_time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(
            extract_domain_from_url("https://www.youtube.com/watch?v=123"),
            Some("youtube.com".to_string())
        );
        assert_eq!(
            extract_domain_from_url("https://djponline.pajak.go.id/account/login"),
            Some("djponline.pajak.go.id".to_string())
        );
        assert_eq!(
            extract_domain_from_url("http://erp.pmgcloud.my.id:8080/dashboard"),
            Some("erp.pmgcloud.my.id".to_string())
        );
        assert_eq!(extract_domain_from_url("chrome://settings/"), None);
        assert_eq!(extract_domain_from_url("edge://extensions/"), None);
        assert_eq!(extract_domain_from_url("http://127.0.0.1:8000/admin"), None);
        assert_eq!(extract_domain_from_url("http://localhost:3000/"), None);
        assert_eq!(extract_domain_from_url("file:///C:/Users/test.pdf"), None);
    }

    #[test]
    fn test_webkit_timestamp_conversion() {
        // 2026-11-20T00:00:00Z -> Unix 1795132800
        let unix = 1_795_132_800i64;
        let wk = unix_secs_to_webkit(unix);
        let dt = webkit_to_utc(wk).expect("WebKit conversion should succeed");
        assert_eq!(dt.timestamp(), unix);
    }
}
