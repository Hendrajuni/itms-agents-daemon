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
        let ip_address = Self::fetch_local_ip();
        let mac_address = Self::fetch_primary_mac(&ip_address);

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

    /// Mengambil Primary MAC Address yang sesuai dengan adapter IP lokal aktif
    fn fetch_primary_mac(target_ip: &str) -> String {
        #[cfg(windows)]
        {
            if let Some(mac) = Self::fetch_windows_mac_for_ip(target_ip) {
                return mac;
            }
        }

        // Fallback jika API Windows tidak menemukan adapter yang cocok
        match mac_address::get_mac_address() {
            Ok(Some(ma)) => ma.to_string().to_uppercase(),
            _ => "00:00:00:00:00:00".to_string(),
        }
    }

    #[cfg(windows)]
    fn fetch_windows_mac_for_ip(target_ip: &str) -> Option<String> {
        use std::net::Ipv4Addr;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_IN};

        let mut buf_len = 15000u32;
        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS(0);

        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buf_len,
            )
        };

        if ret == 111 { // ERROR_BUFFER_OVERFLOW
            buffer.resize(buf_len as usize, 0);
            let ret2 = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    flags,
                    None,
                    Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                    &mut buf_len,
                )
            };
            if ret2 != 0 {
                return None;
            }
        } else if ret != 0 {
            return None;
        }

        let mut first_active_physical_mac = None;
        let mut curr_ptr = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !curr_ptr.is_null() {
            let adapter = unsafe { &*curr_ptr };
            let is_up = adapter.OperStatus.0 == 1; // IfOperStatusUp
            let if_type = adapter.IfType; // 6 = Ethernet, 71 = Wi-Fi (IEEE 802.11)
            let mac_len = adapter.PhysicalAddressLength as usize;

            let mac_str = if mac_len == 6 {
                let p = adapter.PhysicalAddress;
                let s = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", p[0], p[1], p[2], p[3], p[4], p[5]);
                if s != "00:00:00:00:00:00" {
                    Some(s)
                } else {
                    None
                }
            } else {
                None
            };

            // Kumpulkan IPv4 dari adapter ini
            let mut matched_target_ip = false;
            let mut u_ptr = adapter.FirstUnicastAddress;
            while !u_ptr.is_null() {
                let u = unsafe { &*u_ptr };
                let sa = unsafe { &*u.Address.lpSockaddr };
                if sa.sa_family == AF_INET {
                    let sin = unsafe { &*(u.Address.lpSockaddr as *const SOCKADDR_IN) };
                    let ip = Ipv4Addr::from(u32::from_be(unsafe { sin.sin_addr.S_un.S_addr })).to_string();
                    if !target_ip.is_empty() && target_ip != "127.0.0.1" && ip == target_ip {
                        matched_target_ip = true;
                        break;
                    }
                }
                u_ptr = u.Next;
            }

            // Prioritas 1: Adapter yang IP-nya sama persis dengan target_ip (outbound IP)
            if matched_target_ip {
                if let Some(ref m) = mac_str {
                    return Some(m.clone());
                }
            }

            // Simpan kandidat terbaik untuk fallback jika IP matching gagal:
            // Harus adapter Up, tipe Ethernet/Wi-Fi, dan bukan virtual VPN/TAP
            if first_active_physical_mac.is_none() && is_up && (if_type == 6 || if_type == 71) {
                let desc = unsafe { adapter.Description.to_string().unwrap_or_default().to_lowercase() };
                let name = unsafe { adapter.FriendlyName.to_string().unwrap_or_default().to_lowercase() };
                let is_virtual = desc.contains("tap")
                    || desc.contains("vpn")
                    || desc.contains("virtual")
                    || desc.contains("tailscale")
                    || desc.contains("zerotier")
                    || name.contains("vpn")
                    || name.contains("tap");

                if !is_virtual && mac_str.is_some() {
                    first_active_physical_mac = mac_str;
                }
            }

            curr_ptr = adapter.Next;
        }

        first_active_physical_mac
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_identity() {
        let mut collector = HardwareCollector::new();
        let identity = collector.get_identity();
        assert!(!identity.hostname.is_empty());
        assert!(!identity.ip_address.is_empty());
        assert_eq!(identity.mac_address.len(), 17);
        assert_ne!(identity.mac_address, "00:00:00:00:00:00");
    }
}
