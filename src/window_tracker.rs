use crate::classifier::DomainClassifier;
use crate::config::TrackerConfig;
use crate::storage::{ActivityRecord, TelemetryStorage};
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
};

pub struct WindowTracker {
    config: TrackerConfig,
    classifier: DomainClassifier,
    storage: Arc<TelemetryStorage>,
}

#[derive(Debug, Clone)]
struct ActiveSample {
    domain: String,
    app_name: String,
    category: String,
    duration_seconds: u32,
}

impl WindowTracker {
    pub fn new(config: TrackerConfig, storage: Arc<TelemetryStorage>) -> Self {
        Self {
            config,
            classifier: DomainClassifier::new(),
            storage,
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
                if let Some(sample) = current_active.take() {
                    self.flush_sample_to_storage(sample);
                }
                continue;
            }

            // 2. Ambil window aktif saat ini
            if let Some((title, _pid)) = Self::get_foreground_window_info() {
                if title.trim().is_empty() {
                    continue;
                }

                let parsed_domain = Self::extract_domain_or_app(&title);
                let classification = self.classifier.classify(&parsed_domain);

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

        let record = ActivityRecord {
            id: None,
            domain: sample.domain,
            app_name: sample.app_name,
            category: sample.category,
            duration_seconds: sample.duration_seconds,
            total_bytes: 0, // Diupdate oleh sniffer jika tersedia
            source_type: "agent".to_string(),
            recorded_at: Utc::now().to_rfc3339(),
        };

        if let Err(e) = self.storage.insert_activity(&record) {
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

    /// Membaca judul window aktif dan Process ID melalui Win32 API
    fn get_foreground_window_info() -> Option<(String, u32)> {
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
                return Some((title, pid));
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

        // Pemisahan berdasarkan delimiter umum judul tab browser: " - " atau " — "
        let parts: Vec<&str> = clean.split(|c| c == '-' || c == '—' || c == '|').map(|s| s.trim()).collect();
        if parts.is_empty() {
            return clean.to_lowercase();
        }

        // Ambil bagian pertama (nama konten / tab)
        let first_part = parts[0].to_lowercase();

        if first_part.contains("chatgpt") {
            return "chatgpt.com".to_string();
        }
        if first_part.contains("facebook") {
            return "facebook.com".to_string();
        }
        if first_part.contains("youtube") {
            return "youtube.com".to_string();
        }
        if first_part.contains("whatsapp") {
            return "web.whatsapp.com".to_string();
        }
        if first_part.contains("telegram") {
            return "web.telegram.org".to_string();
        }
        if first_part.contains("gmail") || first_part.contains("google mail") {
            return "mail.google.com".to_string();
        }
        if first_part.contains("erp") || first_part.contains("sap") {
            return "erp.pmgcloud.my.id".to_string();
        }
        if first_part.contains("github") {
            return "github.com".to_string();
        }

        // Jika judul memuat format domain langsung (misal "sub.domain.com")
        for word in clean.split_whitespace() {
            let w = word.to_lowercase();
            if w.contains('.') && !w.ends_with('.') && !w.starts_with('.') && w.len() > 3 {
                return w;
            }
        }

        first_part
    }
}
