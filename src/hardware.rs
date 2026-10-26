use serde::{Deserialize, Serialize};
use std::net::UdpSocket;
use sysinfo::System;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_pct: f32,
    pub memory_used_mb: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointIdentity {
    pub machine_uuid: String,
    pub hostname: String,
    pub mac_address: String,
    pub ip_address: String,
}

pub struct HardwareCollector {
    sys: System,
    cached_identity: Option<EndpointIdentity>,
}

impl HardwareCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys,
            cached_identity: None,
        }
    }

    /// Mendapatkan identitas endpoint (Machine UUID, Hostname, MAC, IP)
    pub fn get_identity(&mut self) -> EndpointIdentity {
        if let Some(ref id) = self.cached_identity {
            return id.clone();
        }

        let machine_uuid = Self::fetch_smbios_uuid();
        let hostname = Self::fetch_hostname();
        let mac_address = Self::fetch_primary_mac();
        let ip_address = Self::fetch_local_ip();

        let identity = EndpointIdentity {
            machine_uuid,
            hostname,
            mac_address,
            ip_address,
        };

        self.cached_identity = Some(identity.clone());
        identity
    }

    /// Mengambil metrik performa sistem terkini (CPU, Memori, Uptime)
    pub fn get_metrics(&mut self) -> SystemMetrics {
        self.sys.refresh_cpu_usage();
        self.sys.refresh_memory();

        let cpu_usage_pct = self.sys.global_cpu_info().cpu_usage();
        let memory_used_mb = self.sys.used_memory() / (1024 * 1024);
        let uptime_seconds = System::uptime();

        SystemMetrics {
            cpu_usage_pct,
            memory_used_mb,
            uptime_seconds,
        }
    }

    /// Mengambil UUID unik mesin via SMBIOS / WMI / Registry fallback
    fn fetch_smbios_uuid() -> String {
        // Coba via WMI / PowerShell perintah cepat
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"])
            .output();

        if let Ok(out) = output {
            let res = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !res.is_empty() && res.len() > 10 {
                return res;
            }
        }

        // Fallback: Registry MachineGuid
        let reg_output = std::process::Command::new("reg")
            .args(["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"])
            .output();

        if let Ok(out) = reg_output {
            let res = String::from_utf8_lossy(&out.stdout);
            for line in res.lines() {
                if line.contains("MachineGuid") {
                    if let Some(val) = line.split_whitespace().last() {
                        return val.trim().to_string();
                    }
                }
            }
        }

        warn!("Gagal mendapatkan SMBIOS UUID, menggunakan default fallback.");
        "00000000-0000-0000-0000-000000000000".to_string()
    }

    /// Mengambil hostname komputer
    fn fetch_hostname() -> String {
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "UNKNOWN-HOST".to_string())
    }

    /// Mengambil Primary MAC Address
    fn fetch_primary_mac() -> String {
        match mac_address::get_mac_address() {
            Ok(Some(ma)) => ma.to_string().to_uppercase(),
            _ => "00:00:00:00:00:00".to_string(),
        }
    }

    /// Mengambil Local IP address aktif yang mengarah ke gateway default
    fn fetch_local_ip() -> String {
        // Melakukan bind UDP socket dummy ke rute publik (tidak mengirimkan paket sesungguhnya)
        // untuk mengetahui interface IP lokal yang dipilih OS
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            if socket.connect("8.8.8.8:80").is_ok() {
                if let Ok(local_addr) = socket.local_addr() {
                    return local_addr.ip().to_string();
                }
            }
        }
        "127.0.0.1".to_string()
    }
}
