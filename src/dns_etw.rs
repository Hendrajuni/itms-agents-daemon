use crate::classifier::DomainClassifier;
use crate::storage::{ActivityRecord, TelemetryStorage};
use crate::traffic::DnsResolutionCache;
use chrono::Utc;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};

#[repr(C)]
struct TracePropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    session_name: [u16; 128],
}

unsafe impl Send for TracePropertiesBuffer {}
unsafe impl Sync for TracePropertiesBuffer {}

pub struct DnsEtwSniffer {
    classifier: DomainClassifier,
    storage: Arc<TelemetryStorage>,
    dns_cache: DnsResolutionCache,
}

unsafe extern "system" fn etw_event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    if rec.EventHeader.EventDescriptor.Id != DnsEtwSniffer::EVENT_DNS_QUERY_COMPLETED {
        return;
    }

    let pid = rec.EventHeader.ProcessId;
    if rec.UserData.is_null() || rec.UserDataLength < 2 {
        return;
    }

    let (domain_opt, ips) = parse_dns_query_and_ips(rec.UserData as *const u8, rec.UserDataLength as usize);
    if let Some(domain) = domain_opt {
        if !rec.UserContext.is_null() {
            let sniffer = &*(rec.UserContext as *const DnsEtwSniffer);
            sniffer.handle_dns_event(&domain, pid, ips);
        }
    }
}

/// Mengekstrak domain FQDN dan daftar IP hasil resolusi dari UserData Event 3008
pub fn parse_dns_query_and_ips(user_data: *const u8, length: usize) -> (Option<String>, Vec<IpAddr>) {
    let domain = parse_dns_query_name(user_data, length);
    let mut ips = Vec::new();

    if user_data.is_null() || length < 4 {
        return (domain, ips);
    }

    let max_u16 = length / 2;
    let slice = unsafe { std::slice::from_raw_parts(user_data as *const u16, max_u16) };

    // Bagi menjadi string-string UTF-16 yang dipisahkan oleh null terminator (\0)
    let mut start = 0;
    let mut string_idx = 0;
    for i in 0..max_u16 {
        if slice[i] == 0 {
            if i > start {
                let part = String::from_utf16_lossy(&slice[start..i]);
                // String index 0 adalah QueryName (domain)
                // String index 1 adalah ServerList (DNS nameserver IP, diabaikan)
                // String index >= 2 adalah QueryResults (daftar IP tujuan hasil resolusi domain)
                if string_idx >= 2 && (part.contains('.') || part.contains(':')) {
                    for token in part.split(';') {
                        let trimmed = token.trim();
                        if let Ok(ip) = trimmed.parse::<IpAddr>() {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
                string_idx += 1;
            }
            start = i + 1;
        }
    }

    (domain, ips)
}

pub fn parse_dns_query_name(user_data: *const u8, length: usize) -> Option<String> {
    if user_data.is_null() || length < 2 {
        return None;
    }
    let u16_ptr = user_data as *const u16;
    let max_chars = length / 2;
    let mut len = 0;
    while len < max_chars && unsafe { *u16_ptr.add(len) } != 0 {
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(u16_ptr, len) };
    let raw = String::from_utf16_lossy(slice);
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_lowercase())
}

impl DnsEtwSniffer {
    pub const PROVIDER_GUID: &'static str = "{1C950233-BE26-4226-90F9-C1E47214E7E8}";
    pub const EVENT_DNS_QUERY_COMPLETED: u16 = 3008;

    pub fn new(storage: Arc<TelemetryStorage>, dns_cache: DnsResolutionCache) -> Self {
        Self {
            classifier: DomainClassifier::new(),
            storage,
            dns_cache,
        }
    }

    /// Menjalankan sniffer DNS ETW di background
    pub async fn run(&self, stop_signal: Arc<AtomicBool>) {
        info!(
            "Memulai Windows DNS Client ETW Engine (Provider GUID: {})...",
            Self::PROVIDER_GUID
        );

        // Pra-populasikan DNS Cache dari tabel cache sistem operasi Windows
        let seed_cache = self.dns_cache.clone();
        tokio::task::spawn_blocking(move || {
            let classifier = DomainClassifier::new();
            seed_from_system_dns_cache(&seed_cache, &classifier);
        });

        let session_name_wide: Vec<u16> = "ITMS_DNS_Client_Trace\0".encode_utf16().collect();
        let prop_size = std::mem::size_of::<TracePropertiesBuffer>() as u32;

        let mut prop_buf = TracePropertiesBuffer {
            properties: unsafe { std::mem::zeroed() },
            session_name: [0u16; 128],
        };

        prop_buf.properties.Wnode.BufferSize = prop_size;
        prop_buf.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        prop_buf.properties.Wnode.ClientContext = 1;
        prop_buf.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        prop_buf.properties.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        // Bersihkan sesi lama dengan nama yang sama jika ada sesi tertinggal
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                PCWSTR(session_name_wide.as_ptr()),
                &mut prop_buf.properties,
                EVENT_TRACE_CONTROL_STOP,
            );
        }

        // Reset buffer size setelah ControlTrace
        prop_buf.properties.Wnode.BufferSize = prop_size;

        let mut session_handle = CONTROLTRACE_HANDLE { Value: 0 };
        let start_status = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name_wide.as_ptr()),
                &mut prop_buf.properties,
            )
        };

        if start_status != WIN32_ERROR(0) {
            warn!(
                "ETW DNS Sniffer: StartTraceW gagal (Win32 Error: {:?}). Sesi ETW memerlukan hak Administrator atau LocalSystem.",
                start_status
            );
            info!("Mode DNS Sniffer dialihkan ke standby loop non-intrusif.");

            while !stop_signal.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }

            info!("Windows DNS Client ETW Engine (standby) dihentikan.");
            return;
        }

        info!("ETW Trace Session berhasil diaktifkan. Session Handle: {:?}", session_handle);

        // Aktifkan Provider Microsoft-Windows-DNS-Client {1C950233-BE26-4226-90F9-C1E47214E7E8}
        let dns_guid = GUID::from_values(
            0x1C950233,
            0xBE26,
            0x4226,
            [0x90, 0xF9, 0xC1, 0xE4, 0x72, 0x14, 0xE7, 0xE8],
        );

        let enable_status = unsafe {
            EnableTraceEx2(
                session_handle,
                &dns_guid,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                4, // TRACE_LEVEL_INFORMATION
                0,
                0,
                0,
                None,
            )
        };

        if enable_status != WIN32_ERROR(0) {
            warn!("EnableTraceEx2 DNS-Client provider warning: {:?}", enable_status);
        }

        // Buka trace consumer real-time
        let trace_handle = {
            let mut logfile = EVENT_TRACE_LOGFILEW::default();
            logfile.LoggerName = PWSTR(session_name_wide.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);
            logfile.Context = self as *const DnsEtwSniffer as *mut std::ffi::c_void;

            unsafe { OpenTraceW(&mut logfile) }
        };

        if trace_handle.Value == u64::MAX || trace_handle.Value == 0 {
            warn!("OpenTraceW gagal membuka stream real-time. Menutup trace session.");
            prop_buf.properties.Wnode.BufferSize = prop_size;
            unsafe {
                let _ = ControlTraceW(
                    session_handle,
                    PCWSTR(session_name_wide.as_ptr()),
                    &mut prop_buf.properties,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return;
        }

        // ProcessTrace memblokir thread saat membaca event secara sinkron, jalankan di OS thread
        let proc_thread = std::thread::spawn(move || {
            let mut handles = [trace_handle];
            unsafe {
                let _ = ProcessTrace(&mut handles, None, None);
            }
        });

        info!("ETW DNS Sniffer aktif memproses event real-time.");

        // Loop monitoring hingga stop_signal diterima
        while !stop_signal.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("Menghentikan ETW DNS Sniffer dan melepaskan session...");
        unsafe {
            let _ = CloseTrace(trace_handle);
        }
        let _ = proc_thread.join();

        prop_buf.properties.Wnode.BufferSize = prop_size;
        unsafe {
            let _ = ControlTraceW(
                session_handle,
                PCWSTR(session_name_wide.as_ptr()),
                &mut prop_buf.properties,
                EVENT_TRACE_CONTROL_STOP,
            );
        }

        info!("Windows DNS Client ETW Engine berhasil dimatikan secara bersih.");
    }

    /// Menangani event query DNS yang berhasil ditangkap dari ETW
    pub fn handle_dns_event(&self, raw_domain: &str, pid: u32, ips: Vec<IpAddr>) {
        if raw_domain.trim().is_empty() {
            return;
        }

        let lower = raw_domain.to_lowercase();

        // Filter noise: jangan rekam domain internal arpa, multicast, local, atau internal DNS service
        if lower.ends_with(".arpa")
            || lower.ends_with(".local")
            || lower.ends_with(".lan")
            || lower.ends_with(".home")
            || lower.ends_with(".corp")
            || lower.contains("_tcp")
            || lower.contains("_udp")
            || lower.contains("_dns")
            || lower.contains("wpad")
        {
            return;
        }

        let classification = self.classifier.classify(&lower);

        // Daftarkan seluruh IP hasil resolusi ke dalam In-Memory DNS Resolution Cache
        for ip in &ips {
            self.dns_cache.insert(
                *ip,
                classification.domain.clone(),
                classification.app_name.clone(),
                classification.category.clone(),
                Some(1800), // TTL default 30 menit
            );
        }

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
            debug!(
                "DNS Query terdeteksi: {} (PID: {}, resolved IPs: {})",
                raw_domain, pid, ips.len()
            );
        }
    }
}

#[derive(serde::Deserialize)]
struct DnsCacheEntryJson {
    #[serde(rename = "Entry")]
    entry: Option<String>,
    #[serde(rename = "Data")]
    data: Option<String>,
}

/// Mengambil tabel DNS cache aktif langsung dari sistem operasi Windows (Get-DnsClientCache)
pub fn seed_from_system_dns_cache(dns_cache: &DnsResolutionCache, classifier: &DomainClassifier) {
    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-DnsClientCache | Select-Object Entry, Data | ConvertTo-Json -Compress"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let json_str = String::from_utf8_lossy(&out.stdout);
            let parsed_entries: Vec<DnsCacheEntryJson> = if let Ok(arr) = serde_json::from_str::<Vec<DnsCacheEntryJson>>(&json_str) {
                arr
            } else if let Ok(single) = serde_json::from_str::<DnsCacheEntryJson>(&json_str) {
                vec![single]
            } else {
                Vec::new()
            };

            let mut count = 0;
            for item in parsed_entries {
                if let (Some(domain_raw), Some(ip_str)) = (item.entry, item.data) {
                    if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                        let class = classifier.classify(&domain_raw);
                        dns_cache.insert(
                            ip,
                            class.domain,
                            class.app_name,
                            class.category,
                            Some(1800),
                        );
                        count += 1;
                    }
                }
            }
            info!("DNS Cache berhasil di-seed dari sistem operasi Windows ({} pemetaan IP aktif).", count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query_name() {
        let sample: Vec<u16> = "api.github.com.\0extra".encode_utf16().collect();
        let name = parse_dns_query_name(sample.as_ptr() as *const u8, sample.len() * 2);
        assert_eq!(name, Some("api.github.com".to_string()));

        let empty: Vec<u16> = "\0".encode_utf16().collect();
        let name_empty = parse_dns_query_name(empty.as_ptr() as *const u8, empty.len() * 2);
        assert_eq!(name_empty, None);
    }

    #[test]
    fn test_parse_dns_query_and_ips() {
        // Mock UserData layout: "youtube.com\0server\0142.250.190.46;142.250.190.47;\0"
        let sample: Vec<u16> = "youtube.com\01.1.1.1\0142.250.190.46;142.250.190.47;\0".encode_utf16().collect();
        let (domain, ips) = parse_dns_query_and_ips(sample.as_ptr() as *const u8, sample.len() * 2);

        assert_eq!(domain, Some("youtube.com".to_string()));
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "142.250.190.46".parse::<IpAddr>().unwrap());
        assert_eq!(ips[1], "142.250.190.47".parse::<IpAddr>().unwrap());
    }
}
