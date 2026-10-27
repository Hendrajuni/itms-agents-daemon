use crate::classifier::DomainClassifier;
use crate::config::TrackerConfig;
use crate::storage::{ActivityRecord, TelemetryStorage};
use crate::traffic::TrafficAggregator;
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, error, info};
use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

pub struct WindowTracker {
    config: TrackerConfig,
    classifier: DomainClassifier,
    storage: Arc<TelemetryStorage>,
    traffic_aggregator: TrafficAggregator,
    active_browser_domain: Arc<RwLock<Option<String>>>,
}

#[derive(Debug, Clone)]
struct ActiveSample {
    domain: String,
    app_name: String,
    category: String,
    duration_seconds: u32,
}

impl WindowTracker {
    pub fn new(
        config: TrackerConfig,
        storage: Arc<TelemetryStorage>,
        traffic_aggregator: TrafficAggregator,
        active_browser_domain: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            config,
            classifier: DomainClassifier::new(),
            storage,
            traffic_aggregator,
            active_browser_domain,
        }
    }

    /// Menjalankan loop pelacakan foreground window
    pub async fn run(&self, stop_signal: Arc<AtomicBool>) {
        info!(
            "Memulai Window Tracker loop (sampling: {}s, idle threshold: {}s)...",
            self.config.window_sampling_secs, self.config.idle_threshold_secs
        );

        let mut current_active: Option<ActiveSample> = None;
        let sampling_duration = Duration::from_secs(self.config.window_sampling_secs);

        while !stop_signal.load(Ordering::Relaxed) {
            tokio::time::sleep(sampling_duration).await;

            // 1. Cek apakah user sedang idle (mouse & keyboard tidak bergerak)
            if self.is_user_idle() {
                debug!("User terdeteksi idle. Sampling durasi di-pause.");
                if let Ok(mut lock) = self.active_browser_domain.write() {
                    *lock = None;
                }
                if let Some(sample) = current_active.take() {
                    self.flush_sample_to_storage(sample);
                }
                continue;
            }

            // 2. Ambil window aktif dan executable pemanggil
            if let Some((title, _pid, exe_opt)) = Self::get_foreground_window_info() {
                if title.trim().is_empty() {
                    continue;
                }

                // 3. Klasifikasi: Jika desktop software (Excel, Slack, Code) langsung dipetakan.
                // Jika browser, parsing judul tab ke domain dan kategori.
                let (classification, is_browser) = if let Some(ref exe) = exe_opt {
                    if self.classifier.is_browser_process(exe) {
                        let parsed_domain = Self::extract_domain_or_app(&title);
                        (self.classifier.classify(&parsed_domain), true)
                    } else if let Some(app_class) = self.classifier.classify_by_exe(exe) {
                        (app_class, false)
                    } else {
                        let parsed_domain = Self::extract_domain_or_app(&title);
                        (self.classifier.classify(&parsed_domain), false)
                    }
                } else {
                    let parsed_domain = Self::extract_domain_or_app(&title);
                    (self.classifier.classify(&parsed_domain), false)
                };

                // Perbarui active_browser_domain secara real-time untuk korelasi TCPIP sniffer
                if let Ok(mut lock) = self.active_browser_domain.write() {
                    if is_browser {
                        *lock = Some(classification.domain.clone());
                    } else {
                        *lock = None;
                    }
                }

                match current_active {
                    Some(ref mut active) if active.domain == classification.domain => {
                        // User masih berada di aplikasi/domain yang sama
                        active.duration_seconds += self.config.window_sampling_secs as u32;
                        // Jika durasi akumulasi mencapai 60 detik, flush berkala ke database
                        if active.duration_seconds >= 60 {
                            let sample_to_flush = active.clone();
                            *active = ActiveSample {
                                domain: classification.domain,
                                app_name: classification.app_name,
                                category: classification.category,
                                duration_seconds: 0,
                            };
                            self.flush_sample_to_storage(sample_to_flush);
                        }
                    }
                    Some(prev_active) => {
                        // User berpindah jendela/aplikasi
                        self.flush_sample_to_storage(prev_active);
                        current_active = Some(ActiveSample {
                            domain: classification.domain,
                            app_name: classification.app_name,
                            category: classification.category,
                            duration_seconds: self.config.window_sampling_secs as u32,
                        });
                    }
                    None => {
                        current_active = Some(ActiveSample {
                            domain: classification.domain,
                            app_name: classification.app_name,
                            category: classification.category,
                            duration_seconds: self.config.window_sampling_secs as u32,
                        });
                    }
                }
            }
        }

        // Simpan sample terakhir sebelum shutdown
        if let Some(sample) = current_active {
            self.flush_sample_to_storage(sample);
        }
        info!("Window Tracker loop dihentikan.");
    }

    /// Menyimpan sampel aktivitas ke SQLite offline queue
    fn flush_sample_to_storage(&self, sample: ActiveSample) {
        if sample.duration_seconds == 0 {
            return;
        }

        // Ambil akumulasi delta byte yang terasosiasi dengan domain ini
        let bytes = self.traffic_aggregator.drain_bytes_for_domain(&sample.domain);

        let record = ActivityRecord {
            id: None,
            domain: sample.domain,
            app_name: sample.app_name,
            category: sample.category,
            duration_seconds: sample.duration_seconds,
            total_bytes: bytes,
            source_type: "agent".to_string(),
            recorded_at: Utc::now().to_rfc3339(),
        };

        if let Err(e) = self.storage.upsert_or_accumulate_activity(&record) {
            error!("Gagal menyimpan aktivitas ke SQLite: {}", e);
        }
    }

    /// Memeriksa status idle pengguna via Windows API GetLastInputInfo
    fn is_user_idle(&self) -> bool {
        unsafe {
            let mut last_input = LASTINPUTINFO {
                cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                dwTime: 0,
            };

            if GetLastInputInfo(&mut last_input).as_bool() {
                let current_tick = windows::Win32::System::SystemInformation::GetTickCount64();
                let idle_millis = current_tick.saturating_sub(last_input.dwTime as u64);
                let idle_secs = idle_millis / 1000;
                return idle_secs >= self.config.idle_threshold_secs;
            }
        }
        false
    }

    /// Membaca judul window aktif, Process ID, dan nama binary executable melalui Win32 API
    fn get_foreground_window_info() -> Option<(String, u32, Option<String>)> {
        unsafe {
            let hwnd: HWND = GetForegroundWindow();
            if hwnd.0 == 0 as _ {
                return None;
            }

            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));

            let mut buffer = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut buffer);
            if len > 0 {
                let title = String::from_utf16_lossy(&buffer[..len as usize]);
                let exe_name = Self::get_process_name_from_pid(pid);
                return Some((title, pid, exe_name));
            }
        }
        None
    }

    /// Mendapatkan nama executable (misal: "chrome.exe", "excel.exe") dari Process ID
    fn get_process_name_from_pid(pid: u32) -> Option<String> {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut path_buf = [0u16; 1024];
                let mut size = path_buf.len() as u32;
                let res = QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_FORMAT(0),
                    windows::core::PWSTR(path_buf.as_mut_ptr()),
                    &mut size,
                );
                let _ = CloseHandle(handle);

                if res.is_ok() && size > 0 {
                    let full_path = String::from_utf16_lossy(&path_buf[..size as usize]);
                    return std::path::Path::new(&full_path)
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string().to_lowercase());
                }
            }
        }
        None
    }

    /// Ekstraksi domain dari format judul window browser
    /// Misal:
    /// "ChatGPT - Google Chrome" -> "chatgpt.com"
    /// "(3) Facebook - Google Chrome" -> "facebook.com"
    /// "SAP GUI for Windows" -> "sap.com"
    pub fn extract_domain_or_app(title: &str) -> String {
        let clean = title.trim();

        // Bersihkan counter notifikasi di awal, misal "(2) Facebook..." -> "Facebook..."
        let clean = if clean.starts_with('(') {
            if let Some(idx) = clean.find(')') {
                clean[idx + 1..].trim()
            } else {
                clean
            }
        } else {
            clean
        };

        let lower = clean.to_lowercase();

        if lower.contains("chatgpt") {
            return "chatgpt.com".to_string();
        }
        if lower.contains("facebook") {
            return "facebook.com".to_string();
        }
        if lower.contains("youtube") {
            return "youtube.com".to_string();
        }
        if lower.contains("whatsapp") {
            return "web.whatsapp.com".to_string();
        }
        if lower.contains("telegram") {
            return "web.telegram.org".to_string();
        }
        if lower.contains("gmail") || lower.contains("google mail") {
            return "mail.google.com".to_string();
        }
        if lower.contains("erp") || lower.contains("sap") {
            return "erp.pmgcloud.my.id".to_string();
        }
        if lower.contains("github") {
            return "github.com".to_string();
        }

        // Jika judul memuat format domain langsung (misal "portal.kantor.com - Intranet")
        for word in clean.split_whitespace() {
            let w = word.to_lowercase();
            if w.contains('.') && !w.ends_with('.') && !w.starts_with('.') && w.len() > 3 {
                return w;
            }
        }

        // Pemisahan berdasarkan delimiter umum judul tab browser: " - " atau " — "
        let parts: Vec<&str> = clean.split(|c| c == '-' || c == '—' || c == '|').map(|s| s.trim()).collect();
        if !parts.is_empty() {
            return parts[0].to_lowercase();
        }

        lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_or_app() {
        assert_eq!(WindowTracker::extract_domain_or_app("ChatGPT - Google Chrome"), "chatgpt.com");
        assert_eq!(WindowTracker::extract_domain_or_app("(3) Facebook - Google Chrome"), "facebook.com");
        assert_eq!(WindowTracker::extract_domain_or_app("YouTube - Personal - Microsoft Edge"), "youtube.com");
        assert_eq!(WindowTracker::extract_domain_or_app("Inbox - user@gmail.com - Google Chrome"), "mail.google.com");
        assert_eq!(WindowTracker::extract_domain_or_app("SAP GUI for Windows"), "erp.pmgcloud.my.id");
        assert_eq!(WindowTracker::extract_domain_or_app("portal.kantor.com - Intranet"), "portal.kantor.com");
    }
}
