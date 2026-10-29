use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, error, info, warn};

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::EventLog::{
    EvtClose, EvtRender, EvtSubscribe, EvtRenderEventXml, EvtSubscribeActionDeliver,
    EvtSubscribeToFutureEvents, EVT_HANDLE, EVT_SUBSCRIBE_NOTIFY_ACTION,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEventLog {
    pub timestamp: String,
    pub hostname: String,
    pub event_id: u32,
    pub channel: String,
    pub severity: String,
    pub provider: String,
    pub message: String,
    pub details: serde_json::Value,
}

/// Context pembawa sender Tokio MPSC yang dioperasikan pada Windows EventLog callback
struct SubscriptionContext {
    sender: UnboundedSender<String>,
}

unsafe extern "system" fn evt_subscribe_callback(
    action: EVT_SUBSCRIBE_NOTIFY_ACTION,
    pcontext: *const c_void,
    hevent: EVT_HANDLE,
) -> u32 {
    if action == EvtSubscribeActionDeliver {
        if pcontext.is_null() {
            return ERROR_SUCCESS.0;
        }

        let ctx = &*(pcontext as *const SubscriptionContext);

        // Alokasikan buffer stack/heap u16 (4096 u16 = 8192 bytes)
        let mut buffer: Vec<u16> = vec![0u16; 4096];
        let mut buffused: u32 = 0;
        let mut propcount: u32 = 0;

        let res = EvtRender(
            None,
            hevent,
            EvtRenderEventXml.0 as u32,
            (buffer.len() * 2) as u32,
            Some(buffer.as_mut_ptr() as *mut _),
            &mut buffused,
            &mut propcount,
        );

        if res.is_ok() {
            let char_len = (buffused as usize) / 2;
            let slice = if char_len > 0 && buffer[char_len - 1] == 0 {
                &buffer[..char_len - 1]
            } else {
                &buffer[..char_len]
            };
            let xml_str = String::from_utf16_lossy(slice);
            let _ = ctx.sender.send(xml_str);
        } else if buffused > (buffer.len() * 2) as u32 {
            // Buffer awal kurang besar, re-alokasi buffer sesuai ukuran buffused
            let needed_chars = ((buffused as usize) / 2) + 2;
            let mut large_buffer: Vec<u16> = vec![0u16; needed_chars];
            let res2 = EvtRender(
                None,
                hevent,
                EvtRenderEventXml.0 as u32,
                (large_buffer.len() * 2) as u32,
                Some(large_buffer.as_mut_ptr() as *mut _),
                &mut buffused,
                &mut propcount,
            );

            if res2.is_ok() {
                let char_len = (buffused as usize) / 2;
                let slice = if char_len > 0 && large_buffer[char_len - 1] == 0 {
                    &large_buffer[..char_len - 1]
                } else {
                    &large_buffer[..char_len]
                };
                let xml_str = String::from_utf16_lossy(slice);
                let _ = ctx.sender.send(xml_str);
            }
        }
    }

    ERROR_SUCCESS.0
}

pub struct EventLogWatcher {
    system_handle: Option<EVT_HANDLE>,
    security_handle: Option<EVT_HANDLE>,
    context_system: *mut SubscriptionContext,
    context_security: *mut SubscriptionContext,
    _stop_signal: Arc<AtomicBool>,
}

unsafe impl Send for EventLogWatcher {}
unsafe impl Sync for EventLogWatcher {}

impl EventLogWatcher {
    pub fn new(stop_signal: Arc<AtomicBool>) -> (Self, UnboundedReceiver<ParsedEventLog>) {
        let (raw_sender, mut raw_receiver) = unbounded_channel::<String>();
        let (parsed_sender, parsed_receiver) = unbounded_channel::<ParsedEventLog>();

        // Background worker untuk memparsing XML secara asinkron tanpa membebani callback OS
        let stop_clone = stop_signal.clone();
        tokio::spawn(async move {
            while !stop_clone.load(Ordering::SeqCst) {
                match tokio::time::timeout(std::time::Duration::from_millis(500), raw_receiver.recv()).await {
                    Ok(Some(xml)) => {
                        if let Some(parsed) = parse_event_xml(&xml) {
                            debug!("EventLog tertangkap: ID={} Provider={}", parsed.event_id, parsed.provider);
                            if let Err(e) = parsed_sender.send(parsed) {
                                error!("Gagal meneruskan event log ke consumer channel: {}", e);
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        // Timeout tick, lanjut loop
                    }
                }
            }
            debug!("EventLog XML parser worker dihentikan.");
        });

        // Setup subscription context
        let ctx_sys = Box::into_raw(Box::new(SubscriptionContext {
            sender: raw_sender.clone(),
        }));
        let ctx_sec = Box::into_raw(Box::new(SubscriptionContext {
            sender: raw_sender,
        }));

        let mut watcher = Self {
            system_handle: None,
            security_handle: None,
            context_system: ctx_sys,
            context_security: ctx_sec,
            _stop_signal: stop_signal,
        };

        watcher.subscribe_channels();
        (watcher, parsed_receiver)
    }

    fn subscribe_channels(&mut self) {
        // 1. Channel System: 7034, 7036, 55, 98, 1074, 41
        let sys_channel = HSTRING::from("System");
        let sys_query = HSTRING::from(
            "*[System[(EventID=7034 or EventID=7036 or EventID=55 or EventID=98 or EventID=1074 or EventID=41)]]"
        );

        unsafe {
            match EvtSubscribe(
                None,
                None,
                PCWSTR(sys_channel.as_ptr()),
                PCWSTR(sys_query.as_ptr()),
                None,
                Some(self.context_system as *const c_void),
                Some(evt_subscribe_callback),
                EvtSubscribeToFutureEvents.0,
            ) {
                Ok(h) => {
                    info!("Subscription Windows EventLog untuk Channel 'System' berhasil diaktifkan.");
                    self.system_handle = Some(h);
                }
                Err(e) => {
                    error!("Gagal mengaktifkan subscription EventLog Channel 'System': {}", e);
                }
            }
        }

        // 2. Channel Security: 4625, 4720, 4726, 4740
        let sec_channel = HSTRING::from("Security");
        let sec_query = HSTRING::from(
            "*[System[(EventID=4625 or EventID=4720 or EventID=4726 or EventID=4740)]]"
        );

        unsafe {
            match EvtSubscribe(
                None,
                None,
                PCWSTR(sec_channel.as_ptr()),
                PCWSTR(sec_query.as_ptr()),
                None,
                Some(self.context_security as *const c_void),
                Some(evt_subscribe_callback),
                EvtSubscribeToFutureEvents.0,
            ) {
                Ok(h) => {
                    info!("Subscription Windows EventLog untuk Channel 'Security' berhasil diaktifkan.");
                    self.security_handle = Some(h);
                }
                Err(e) => {
                    warn!(
                        "Peringatan: Gagal mengaktifkan subscription EventLog Channel 'Security' ({}). \
                        Akses channel Security memerlukan hak Administrator / LocalSystem. Melanjutkan dengan Channel System.",
                        e
                    );
                }
            }
        }
    }
}

impl Drop for EventLogWatcher {
    fn drop(&mut self) {
        unsafe {
            if let Some(h) = self.system_handle.take() {
                let _ = EvtClose(h);
                debug!("EventLog System subscription ditutup.");
            }
            if let Some(h) = self.security_handle.take() {
                let _ = EvtClose(h);
                debug!("EventLog Security subscription ditutup.");
            }

            if !self.context_system.is_null() {
                let _ = Box::from_raw(self.context_system);
                self.context_system = std::ptr::null_mut();
            }
            if !self.context_security.is_null() {
                let _ = Box::from_raw(self.context_security);
                self.context_security = std::ptr::null_mut();
            }
        }
    }
}

// ============================================================================
// XML PARSER & ANTI-LOCALIZATION MESSAGE SYNTHESIS ENGINE
// ============================================================================

/// Helper ekstraksi teks dalam simpul XML: `<Tag>isi</Tag>`
fn extract_tag_text(xml: &str, tag: &str) -> Option<String> {
    let open_tag = format!("<{}>", tag);
    let close_tag = format!("</{}>", tag);

    let start = xml.find(&open_tag)? + open_tag.len();
    let end = xml[start..].find(&close_tag)? + start;
    Some(xml[start..end].trim().to_string())
}

/// Helper ekstraksi nilai atribut XML: `<Tag Attr="isi" ...>` atau `<Tag Attr='isi' ...>`
fn extract_attr_value(xml: &str, tag: &str, attr: &str) -> Option<String> {
    let tag_pos = xml.find(&format!("<{}", tag))?;
    let tag_slice = &xml[tag_pos..];
    let tag_end = tag_slice.find('>')?;
    let tag_content = &tag_slice[..tag_end];

    // Coba petik dua: attr="value"
    let pattern_double = format!("{}=\"", attr);
    if let Some(pos) = tag_content.find(&pattern_double) {
        let val_start = pos + pattern_double.len();
        if let Some(val_end) = tag_content[val_start..].find('"') {
            return Some(tag_content[val_start..val_start + val_end].to_string());
        }
    }

    // Coba petik tunggal: attr='value'
    let pattern_single = format!("{}='", attr);
    if let Some(pos) = tag_content.find(&pattern_single) {
        let val_start = pos + pattern_single.len();
        if let Some(val_end) = tag_content[val_start..].find('\'') {
            return Some(tag_content[val_start..val_start + val_end].to_string());
        }
    }

    None
}

/// Membedah data murni `<EventData>` ke dalam HashMap (mendukung `Name="xyz"` dan `paramN`)
fn extract_event_data_map(xml: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    let start_tag = "<EventData";
    let end_tag = "</EventData>";

    let start_idx = match xml.find(start_tag) {
        Some(pos) => pos,
        None => return map,
    };
    let end_idx = match xml[start_idx..].find(end_tag) {
        Some(pos) => start_idx + pos,
        None => return map,
    };

    let data_section = &xml[start_idx..end_idx];
    let mut search_from = 0;
    let mut param_counter = 1;

    while let Some(data_pos) = data_section[search_from..].find("<Data") {
        let abs_pos = search_from + data_pos;
        let close_pos = match data_section[abs_pos..].find('>') {
            Some(p) => abs_pos + p,
            None => break,
        };
        let tag_header = &data_section[abs_pos..=close_pos];

        let content_end = match data_section[close_pos + 1..].find("</Data>") {
            Some(p) => close_pos + 1 + p,
            None => break,
        };
        let value = data_section[close_pos + 1..content_end].trim().to_string();

        // Cari atribut Name='...' atau Name="..."
        let name_opt = if let Some(p) = tag_header.find("Name=\"") {
            let s = p + 6;
            tag_header[s..].find('"').map(|e| tag_header[s..s + e].to_string())
        } else if let Some(p) = tag_header.find("Name='") {
            let s = p + 6;
            tag_header[s..].find('\'').map(|e| tag_header[s..s + e].to_string())
        } else {
            None
        };

        if let Some(name) = name_opt {
            map.insert(name, value.clone());
        }

        // Simpan juga sebagai param1, param2, dst untuk kompatibilitas
        map.insert(format!("param{}", param_counter), value);
        param_counter += 1;

        search_from = content_end + 7;
    }

    map
}

/// Membedah XML mentah event Windows menjadi objek ParsedEventLog dengan format terstruktur
pub fn parse_event_xml(xml: &str) -> Option<ParsedEventLog> {
    let event_id_str = extract_tag_text(xml, "EventID")?;
    let event_id: u32 = event_id_str.parse().ok()?;

    let channel = extract_tag_text(xml, "Channel").unwrap_or_else(|| "Unknown".to_string());
    let computer = extract_tag_text(xml, "Computer").unwrap_or_else(|| {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".to_string())
    });

    let timestamp = extract_attr_value(xml, "TimeCreated", "SystemTime")
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let provider = extract_attr_value(xml, "Provider", "Name")
        .unwrap_or_else(|| "Microsoft-Windows".to_string());

    let data = extract_event_data_map(xml);

    let (severity, message, details) = match event_id {
        // ---------------------------------------------------------------------
        // SECURITY EVENTS
        // ---------------------------------------------------------------------
        4625 => {
            let target_user = data.get("TargetUserName").cloned().unwrap_or_default();
            let workstation = data.get("WorkstationName").cloned().unwrap_or_default();
            let source_ip = data.get("IpAddress").cloned().unwrap_or_default();
            let status = data.get("Status").cloned().unwrap_or_else(|| "0xC000006D".to_string());
            let sub_status = data.get("SubStatus").cloned().unwrap_or_default();

            let msg = format!(
                "An account failed to log on. TargetUser: {}, Workstation: {}, SourceIP: {}, Status: {}",
                target_user, workstation, source_ip, status
            );

            let details_json = serde_json::json!({
                "target_user": target_user,
                "workstation": workstation,
                "source_ip": source_ip,
                "status_code": status,
                "sub_status_code": sub_status,
            });

            ("WARNING", msg, details_json)
        }
        4720 => {
            let target_user = data.get("TargetUserName").cloned().unwrap_or_default();
            let subject_user = data.get("SubjectUserName").cloned().unwrap_or_default();

            let msg = format!(
                "A user account was created. TargetUser: {}, CreatedBy: {}",
                target_user, subject_user
            );

            let details_json = serde_json::json!({
                "target_user": target_user,
                "created_by": subject_user,
            });

            ("INFO", msg, details_json)
        }
        4726 => {
            let target_user = data.get("TargetUserName").cloned().unwrap_or_default();
            let subject_user = data.get("SubjectUserName").cloned().unwrap_or_default();

            let msg = format!(
                "A user account was deleted. TargetUser: {}, DeletedBy: {}",
                target_user, subject_user
            );

            let details_json = serde_json::json!({
                "target_user": target_user,
                "deleted_by": subject_user,
            });

            ("WARNING", msg, details_json)
        }
        4740 => {
            let target_user = data.get("TargetUserName").cloned().unwrap_or_default();
            let caller = data.get("CallerComputerName").cloned().unwrap_or_default();

            let msg = format!(
                "A user account was locked out. TargetUser: {}, CallerWorkstation: {}",
                target_user, caller
            );

            let details_json = serde_json::json!({
                "target_user": target_user,
                "caller_workstation": caller,
            });

            ("CRITICAL", msg, details_json)
        }

        // ---------------------------------------------------------------------
        // SYSTEM EVENTS
        // ---------------------------------------------------------------------
        7034 => {
            let svc_name = data.get("param1").or_else(|| data.get("ServiceName")).cloned().unwrap_or_default();
            let crash_code = data.get("param2").or_else(|| data.get("CrashCount")).cloned().unwrap_or_else(|| "1".to_string());

            let msg = format!(
                "The {} service terminated unexpectedly (crash count: {}).",
                svc_name, crash_code
            );

            let details_json = serde_json::json!({
                "service_name": svc_name,
                "crash_code": crash_code,
            });

            ("CRITICAL", msg, details_json)
        }
        7036 => {
            let svc_name = data.get("param1").or_else(|| data.get("ServiceName")).cloned().unwrap_or_default();
            let state = data.get("param2").or_else(|| data.get("State")).cloned().unwrap_or_default();

            // Filter kebisingan (Noise Filter): Hanya rekam jika statusnya "stopped" / bukan running
            let state_lower = state.to_lowercase();
            if !state_lower.contains("stop") {
                return None; // Abaikan transisi rutin running/started
            }

            let msg = format!("The {} service entered the {} state.", svc_name, state);

            let details_json = serde_json::json!({
                "service_name": svc_name,
                "state": state,
            });

            ("INFO", msg, details_json)
        }
        55 => {
            let drive = data.get("DriveName")
                .or_else(|| data.get("Description"))
                .or_else(|| data.get("param1"))
                .cloned()
                .unwrap_or_else(|| "System Drive".to_string());

            let msg = format!(
                "A corruption was discovered in the file system structure on volume {}.",
                drive
            );

            let details_json = serde_json::json!({
                "drive_name": drive,
            });

            ("CRITICAL", msg, details_json)
        }
        98 => {
            let volume = data.get("VolumeGuid")
                .or_else(|| data.get("VolumeName"))
                .or_else(|| data.get("param1"))
                .cloned()
                .unwrap_or_else(|| "System Volume".to_string());

            let msg = format!(
                "Volume {} health state reported corruption or unreadable data blocks.",
                volume
            );

            let details_json = serde_json::json!({
                "volume": volume,
            });

            ("CRITICAL", msg, details_json)
        }
        1074 => {
            let process = data.get("param1").cloned().unwrap_or_default();
            let computer_name = data.get("param2").cloned().unwrap_or_default();
            let reason = data.get("param3").or_else(|| data.get("param5")).cloned().unwrap_or_default();
            let user = data.get("param7").cloned().unwrap_or_default();

            let msg = format!(
                "System restart/shutdown was initiated by {} via {}. Reason: {}.",
                user, process, reason
            );

            let details_json = serde_json::json!({
                "user": user,
                "process": process,
                "computer": computer_name,
                "reason": reason,
            });

            ("INFO", msg, details_json)
        }
        41 => {
            let bugcheck_code = data.get("BugcheckCode").cloned().unwrap_or_else(|| "0".to_string());
            let p1 = data.get("BugcheckParameter1").cloned().unwrap_or_default();
            let power_btn = data.get("PowerButtonTimestamp").cloned().unwrap_or_else(|| "0".to_string());

            let msg = format!(
                "The system has rebooted without cleanly shutting down first (BSOD/power failure). BugcheckCode: {}.",
                bugcheck_code
            );

            let details_json = serde_json::json!({
                "bugcheck_code": bugcheck_code,
                "bugcheck_parameter1": p1,
                "power_button_timestamp": power_btn,
            });

            ("CRITICAL", msg, details_json)
        }
        _ => return None,
    };

    Some(ParsedEventLog {
        timestamp,
        hostname: computer,
        event_id,
        channel,
        severity: severity.to_string(),
        provider,
        message,
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_event_4625_logon_failed() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4625</EventID>
                <TimeCreated SystemTime="2026-10-29T13:30:00Z"/>
                <Channel>Security</Channel>
                <Computer>SRV-DC01</Computer>
            </System>
            <EventData>
                <Data Name="TargetUserName">Administrator</Data>
                <Data Name="WorkstationName">WS-01</Data>
                <Data Name="IpAddress">192.168.1.88</Data>
                <Data Name="Status">0xC000006D</Data>
            </EventData>
        </Event>"#;

        let parsed = parse_event_xml(xml).expect("Gagal memparsing Event 4625");
        assert_eq!(parsed.event_id, 4625);
        assert_eq!(parsed.severity, "WARNING");
        assert_eq!(parsed.channel, "Security");
        assert_eq!(parsed.hostname, "SRV-DC01");
        assert_eq!(parsed.details["target_user"], "Administrator");
        assert_eq!(parsed.details["source_ip"], "192.168.1.88");
        assert!(parsed.message.contains("Administrator"));
    }

    #[test]
    fn test_parse_event_7034_service_crash() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Service Control Manager"/>
                <EventID>7034</EventID>
                <TimeCreated SystemTime="2026-10-29T13:32:15Z"/>
                <Channel>System</Channel>
                <Computer>SRV-DC01</Computer>
            </System>
            <EventData>
                <Data Name="param1">Print Spooler</Data>
                <Data Name="param2">1</Data>
            </EventData>
        </Event>"#;

        let parsed = parse_event_xml(xml).expect("Gagal memparsing Event 7034");
        assert_eq!(parsed.event_id, 7034);
        assert_eq!(parsed.severity, "CRITICAL");
        assert_eq!(parsed.details["service_name"], "Print Spooler");
        assert_eq!(parsed.details["crash_code"], "1");
    }

    #[test]
    fn test_parse_event_7036_filter_running() {
        let xml_running = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Service Control Manager"/>
                <EventID>7036</EventID>
                <Channel>System</Channel>
            </System>
            <EventData>
                <Data Name="param1">Windows Update</Data>
                <Data Name="param2">running</Data>
            </EventData>
        </Event>"#;

        assert!(parse_event_xml(xml_running).is_none(), "Event 7036 'running' harus diabaikan!");

        let xml_stopped = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Service Control Manager"/>
                <EventID>7036</EventID>
                <Channel>System</Channel>
            </System>
            <EventData>
                <Data Name="param1">Windows Update</Data>
                <Data Name="param2">stopped</Data>
            </EventData>
        </Event>"#;

        let parsed = parse_event_xml(xml_stopped).expect("Event 7036 'stopped' harus ditangkap");
        assert_eq!(parsed.severity, "INFO");
        assert_eq!(parsed.details["state"], "stopped");
    }

    #[test]
    fn test_parse_event_41_dirty_reboot() {
        let xml = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
            <System>
                <Provider Name="Microsoft-Windows-Kernel-Power"/>
                <EventID>41</EventID>
                <Channel>System</Channel>
            </System>
            <EventData>
                <Data Name="BugcheckCode">159</Data>
                <Data Name="BugcheckParameter1">0x3</Data>
                <Data Name="PowerButtonTimestamp">0</Data>
            </EventData>
        </Event>"#;

        let parsed = parse_event_xml(xml).expect("Gagal memparsing Event 41");
        assert_eq!(parsed.event_id, 41);
        assert_eq!(parsed.severity, "CRITICAL");
        assert_eq!(parsed.details["bugcheck_code"], "159");
    }
}
