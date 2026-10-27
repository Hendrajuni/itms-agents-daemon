use crate::classifier::DomainClassifier;
use crate::traffic::{is_internal_or_noise_ip, DnsResolutionCache, TrafficAggregator};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tracing::{info, warn};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[repr(C)]
struct TracePropertiesBuffer {
    properties: EVENT_TRACE_PROPERTIES,
    session_name: [u16; 128],
}

unsafe impl Send for TracePropertiesBuffer {}
unsafe impl Sync for TracePropertiesBuffer {}

pub struct NetEtwConsumer {
    dns_cache: DnsResolutionCache,
    traffic_aggregator: TrafficAggregator,
    active_browser_domain: Arc<RwLock<Option<String>>>,
    classifier: DomainClassifier,
    pid_cache: Arc<Mutex<HashMap<u32, (String, String, String)>>>,
}

unsafe extern "system" fn tcpip_event_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    let event_id = rec.EventHeader.EventDescriptor.Id;

    // Filter event transfer TCP dan UDP riil Windows:
    // 1073 / 1153 / 1332: TcpDataTransferSend (TCP outbound bytes)
    // 1074 / 1154:        TcpDataTransferReceive (TCP inbound bytes)
    // 1169:               UdpEndpointSendMessages (QUIC / HTTP3 outbound bytes)
    // 1170:               UdpEndpointReceiveMessages (QUIC / HTTP3 inbound bytes)
    let is_send = matches!(event_id, 1073 | 1153 | 1169 | 1332 | 1333 | 1042 | 1043 | 1058 | 1059);
    let is_recv = matches!(event_id, 1074 | 1154 | 1170 | 1044 | 1045 | 1060 | 1061);

    if !is_send && !is_recv {
        return;
    }

    if rec.UserData.is_null() || rec.UserDataLength < 12 {
        return;
    }

    let pid = rec.EventHeader.ProcessId;

    if let Some((dest_ip_opt, bytes)) = parse_tcpip_event_payload(rec.UserData as *const u8, rec.UserDataLength as usize, event_id) {
        if bytes == 0 {
            return;
        }

        if !rec.UserContext.is_null() {
            let consumer = &*(rec.UserContext as *const NetEtwConsumer);
            let send_bytes = if is_send { bytes } else { 0 };
            let recv_bytes = if is_recv { bytes } else { 0 };
            consumer.handle_packet_transfer(pid, dest_ip_opt, send_bytes, recv_bytes);
        }
    }
}

/// Zero-Allocation parser untuk mengekstrak Destination IP dan Jumlah Byte dari payload biner ETW TCPIP
pub fn parse_tcpip_event_payload(user_data: *const u8, length: usize, event_id: u16) -> Option<(Option<IpAddr>, u64)> {
    if user_data.is_null() || length < 12 {
        return None;
    }

    let slice = unsafe { std::slice::from_raw_parts(user_data, length) };

    let mut num_bytes = 0u64;
    let mut dest_ip: Option<IpAddr> = None;

    match event_id {
        1074 | 1154 => {
            // TcpDataTransferReceive:
            // Tcb: Pointer (8 bytes, 0..8)
            // NumBytes: u32 (offset 8..12)
            if length >= 12 {
                num_bytes = u32::from_ne_bytes([slice[8], slice[9], slice[10], slice[11]]) as u64;
            }
        }
        1073 | 1153 | 1332 | 1333 => {
            // TcpDataTransferSend / TcpCtcpSend / TcpSendSeq:
            // NumBytes berada di offset 20..24
            if length >= 24 {
                num_bytes = u32::from_ne_bytes([slice[20], slice[21], slice[22], slice[23]]) as u64;
            } else if length >= 12 {
                num_bytes = u32::from_ne_bytes([slice[8], slice[9], slice[10], slice[11]]) as u64;
            }
        }
        1169 | 1170 => {
            // UdpEndpointSendMessages / UdpEndpointReceiveMessages (QUIC HTTP/3):
            // Endpoint: Pointer (8 bytes, 0..8)
            // NumMessages: u32 (offset 8..12)
            // NumBytes: u32 (offset 12..16)
            // LocalSockAddrLength: u32 (offset 16..20)
            if length >= 16 {
                num_bytes = u32::from_ne_bytes([slice[12], slice[13], slice[14], slice[15]]) as u64;
            }
            if length >= 20 {
                let local_len = u32::from_ne_bytes([slice[16], slice[17], slice[18], slice[19]]) as usize;
                let remote_len_offset = 20 + local_len;
                if remote_len_offset + 4 <= length {
                    let remote_len = u32::from_ne_bytes([
                        slice[remote_len_offset],
                        slice[remote_len_offset + 1],
                        slice[remote_len_offset + 2],
                        slice[remote_len_offset + 3],
                    ]) as usize;
                    let remote_addr_offset = remote_len_offset + 4;
                    if remote_addr_offset + remote_len <= length && remote_len >= 8 {
                        let family = u16::from_ne_bytes([slice[remote_addr_offset], slice[remote_addr_offset + 1]]);
                        if family == 2 && remote_addr_offset + 8 <= length {
                            // AF_INET IPv4: sin_port (2 bytes), sin_addr (4 bytes)
                            let ip_bytes = [
                                slice[remote_addr_offset + 4],
                                slice[remote_addr_offset + 5],
                                slice[remote_addr_offset + 6],
                                slice[remote_addr_offset + 7],
                            ];
                            dest_ip = Some(IpAddr::V4(Ipv4Addr::from(ip_bytes)));
                        } else if family == 23 && remote_addr_offset + 24 <= length {
                            // AF_INET6 IPv6
                            let mut ip6_bytes = [0u8; 16];
                            ip6_bytes.copy_from_slice(&slice[remote_addr_offset + 8..remote_addr_offset + 24]);
                            dest_ip = Some(IpAddr::V6(Ipv6Addr::from(ip6_bytes)));
                        }
                    }
                }
            }
        }
        _ => {
            // Fallback generic scanner
            if length >= 12 {
                let b = u32::from_ne_bytes([slice[8], slice[9], slice[10], slice[11]]) as u64;
                if b > 0 && b < 100_000_000 {
                    num_bytes = b;
                }
            }
            // Scan sockaddr_in jika ada
            let mut offset = 12;
            while offset + 16 <= length {
                let family = u16::from_ne_bytes([slice[offset], slice[offset + 1]]);
                if family == 2 {
                    let ip_bytes = [slice[offset + 4], slice[offset + 5], slice[offset + 6], slice[offset + 7]];
                    let ip = IpAddr::V4(Ipv4Addr::from(ip_bytes));
                    if !is_internal_or_noise_ip(&ip) {
                        dest_ip = Some(ip);
                        break;
                    }
                } else if family == 23 && offset + 28 <= length {
                    let mut ip6_bytes = [0u8; 16];
                    ip6_bytes.copy_from_slice(&slice[offset + 8..offset + 24]);
                    let ip = IpAddr::V6(Ipv6Addr::from(ip6_bytes));
                    if !is_internal_or_noise_ip(&ip) {
                        dest_ip = Some(ip);
                        break;
                    }
                }
                offset += 2;
            }
        }
    }

    if num_bytes == 0 && dest_ip.is_some() {
        num_bytes = 1460; // Estimasi 1 MTU jika field byte tidak terbaca
    }

    if num_bytes > 0 && num_bytes < 100_000_000 {
        Some((dest_ip, num_bytes))
    } else {
        None
    }
}

impl NetEtwConsumer {
    pub const PROVIDER_GUID: &'static str = "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}";

    pub fn new(
        dns_cache: DnsResolutionCache,
        traffic_aggregator: TrafficAggregator,
        active_browser_domain: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            dns_cache,
            traffic_aggregator,
            active_browser_domain,
            classifier: DomainClassifier::new(),
            pid_cache: Arc::new(Mutex::new(HashMap::with_capacity(256))),
        }
    }

    /// Menjalankan loop TCPIP Network Sniffer ETW di background
    pub async fn run(&self, stop_signal: Arc<AtomicBool>) {
        info!(
            "Memulai Windows TCPIP Network Traffic Accounting Engine (Provider GUID: {})...",
            Self::PROVIDER_GUID
        );

        let session_name_wide: Vec<u16> = "ITMS_TCPIP_Network_Trace\0".encode_utf16().collect();
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
                "ETW TCPIP Consumer: StartTraceW gagal (Win32 Error: {:?}). Diperlukan hak Administrator / Service LocalSystem.",
                start_status
            );
            info!("Mode TCPIP Network Traffic Accounting dialihkan ke standby loop non-intrusif.");

            while !stop_signal.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }

            info!("Windows TCPIP Network Traffic Accounting (standby) dihentikan.");
            return;
        }

        info!("ETW TCPIP Trace Session aktif. Session Handle: {:?}", session_handle);

        // Aktifkan Provider Microsoft-Windows-TCPIP {2F07E2EE-15DB-40F1-90EF-9D7BA282188A}
        let tcpip_guid = GUID::from_values(
            0x2F07E2EE,
            0x15DB,
            0x40F1,
            [0x90, 0xEF, 0x9D, 0x7B, 0xA2, 0x82, 0x18, 0x8A],
        );

        // Keyword: 0x0000000000000100 (ut:Transfer) | 0x0000000100000000 (ut:SendPath) | 0x0000000200000000 (ut:ReceivePath) | 0x0000040000000000 (ut:Packet)
        let match_any_keyword = 0x0000040300000100u64;

        let enable_status = unsafe {
            EnableTraceEx2(
                session_handle,
                &tcpip_guid,
                1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
                5, // TRACE_LEVEL_VERBOSE (Wajib level 5 agar event data transfer dipancarkan kernel)
                match_any_keyword,
                0,
                0,
                None,
            )
        };

        if enable_status != WIN32_ERROR(0) {
            warn!("EnableTraceEx2 TCPIP provider warning: {:?}", enable_status);
        }

        // Buka trace consumer real-time
        let trace_handle = {
            let mut logfile = EVENT_TRACE_LOGFILEW::default();
            logfile.LoggerName = PWSTR(session_name_wide.as_ptr() as *mut u16);
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.Anonymous2.EventRecordCallback = Some(tcpip_event_callback);
            logfile.Context = self as *const NetEtwConsumer as *mut std::ffi::c_void;

            unsafe { OpenTraceW(&mut logfile) }
        };

        if trace_handle.Value == u64::MAX || trace_handle.Value == 0 {
            warn!("OpenTraceW gagal membuka TCPIP stream real-time. Menutup trace session.");
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

        let proc_thread = std::thread::spawn(move || {
            let mut handles = [trace_handle];
            unsafe {
                let _ = ProcessTrace(&mut handles, None, None);
            }
        });

        info!("ETW TCPIP Traffic Accounting Engine aktif memproses event real-time.");

        while !stop_signal.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        info!("Menghentikan ETW TCPIP Traffic Engine dan melepaskan session...");
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

        info!("Windows TCPIP Network Traffic Accounting Engine berhasil dimatikan secara bersih.");
    }

    /// Korelasi paket transfer ke domain web atau proses aplikasi
    pub fn handle_packet_transfer(&self, pid: u32, dest_ip_opt: Option<IpAddr>, send_bytes: u64, recv_bytes: u64) {
        // 1. Cek apakah DestIP ada di DNS Resolution Cache
        if let Some(ref dest_ip) = dest_ip_opt {
            if is_internal_or_noise_ip(dest_ip) {
                return;
            }
            if let Some(entry) = self.dns_cache.lookup(dest_ip) {
                self.traffic_aggregator.record_traffic(
                    &entry.domain,
                    &entry.app_name,
                    &entry.category,
                    send_bytes,
                    recv_bytes,
                );
                return;
            }
        }

        // 2. Fallback: IP tidak ada di DNS (direct IP / persistent connection / pre-cached)
        // Jika proses pengirim/penerima adalah web browser (msedge, chrome, firefox, dll)
        // dan ada tab browser yang sedang aktif di foreground, atribusikan langsung ke tab tersebut!
        if let Some(exe) = Self::get_process_name(pid) {
            if self.classifier.is_browser_process(&exe) {
                if let Ok(lock) = self.active_browser_domain.read() {
                    if let Some(ref active_domain) = *lock {
                        let class = self.classifier.classify(active_domain);
                        self.traffic_aggregator.record_traffic(
                            &class.domain,
                            &class.app_name,
                            &class.category,
                            send_bytes,
                            recv_bytes,
                        );
                        return;
                    }
                }
            }
        }

        // 3. Fallback: Petakan ke nama proses (PID)
        let (domain, app_name, category) = self.resolve_pid_to_app(pid);
        self.traffic_aggregator.record_traffic(
            &domain,
            &app_name,
            &category,
            send_bytes,
            recv_bytes,
        );
    }

    /// Resolusi Process ID ke Nama Aplikasi / Domain fallback
    fn resolve_pid_to_app(&self, pid: u32) -> (String, String, String) {
        if pid == 0 || pid == 4 {
            return ("system.local".to_string(), "System Network Services".to_string(), "system".to_string());
        }

        if let Ok(lock) = self.pid_cache.lock() {
            if let Some(cached) = lock.get(&pid) {
                return cached.clone();
            }
        }

        let exe_opt = Self::get_process_name(pid);
        let exe = exe_opt.unwrap_or_else(|| format!("pid_{}.exe", pid));

        let classification = if let Some(app_class) = self.classifier.classify_by_exe(&exe) {
            (app_class.domain, app_class.app_name, app_class.category)
        } else {
            (exe.clone(), exe.clone(), "general_network".to_string())
        };

        if let Ok(mut lock) = self.pid_cache.lock() {
            if lock.len() >= 512 {
                lock.clear();
            }
            lock.insert(pid, classification.clone());
        }

        classification
    }

    fn get_process_name(pid: u32) -> Option<String> {
        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                let mut path_buf = [0u16; 1024];
                let mut size = path_buf.len() as u32;
                let res = QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_FORMAT(0),
                    PWSTR(path_buf.as_mut_ptr()),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcpip_event_ipv4() {
        // Mock payload binary:
        // offset 0..8: Tcb pointer
        // offset 8..12: NumBytes = 65400 (0x0000FF78)
        // offset 12..14: sin_family = 2 (AF_INET)
        // offset 14..16: sin_port = 443
        // offset 16..20: sin_addr = 142.250.190.46
        let mut buffer = vec![0u8; 32];
        let bytes: u32 = 65400;
        buffer[8..12].copy_from_slice(&bytes.to_ne_bytes());
        buffer[12..14].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
        buffer[14..16].copy_from_slice(&443u16.to_be_bytes()); // Port 443
        buffer[16..20].copy_from_slice(&[142, 250, 190, 46]);

        let res = parse_tcpip_event_payload(buffer.as_ptr(), buffer.len(), 0);
        assert!(res.is_some());
        let (ip_opt, size) = res.unwrap();
        assert_eq!(ip_opt, Some(IpAddr::V4(Ipv4Addr::new(142, 250, 190, 46))));
        assert_eq!(size, 65400);

        // Test Event 1074 (pure TCP receive)
        let mut tcp_buf = vec![0u8; 16];
        let recv_bytes: u32 = 1460;
        tcp_buf[8..12].copy_from_slice(&recv_bytes.to_ne_bytes());
        let res_tcp = parse_tcpip_event_payload(tcp_buf.as_ptr(), tcp_buf.len(), 1074);
        assert!(res_tcp.is_some());
        let (tcp_ip_opt, tcp_size) = res_tcp.unwrap();
        assert_eq!(tcp_ip_opt, None);
        assert_eq!(tcp_size, 1460);
    }
}
