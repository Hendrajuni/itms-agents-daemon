use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSpec {
    pub drive: String,
    pub total_gb: u64,
    pub free_gb: u64,
    pub fs_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSpec {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub os_name: String,
    pub os_version: String,
    pub os_arch: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub cpu_threads: usize,
    pub ram_total_mb: u64,
    pub gpu_model: String,
    pub disks: Vec<DiskSpec>,
}

pub struct SpecCollector;

impl SpecCollector {
    /// Mengumpulkan seluruh informasi spesifikasi hardware dan sistem operasi
    pub fn collect() -> DeviceSpec {
        info!("Mengumpulkan profil spesifikasi perangkat keras & OS (Device Spec)...");

        // 1. Ambil identitas hardware (Manufacturer, Model, Serial Number)
        let (manufacturer, model, serial_number) = Self::fetch_system_identity();

        // 2. Ambil informasi OS
        let (os_name, os_version, os_arch) = Self::fetch_os_info();

        // 3. Ambil informasi CPU dan RAM via sysinfo
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_model = sys.cpus().first()
            .map(|c| c.brand().trim().to_string())
            .unwrap_or_else(|| "Unknown CPU".to_string());
        let cpu_cores = sys.physical_core_count().unwrap_or(sys.cpus().len());
        let cpu_threads = sys.cpus().len();
        let ram_total_mb = sys.total_memory() / (1024 * 1024);

        // 4. Ambil informasi GPU
        let gpu_model = Self::fetch_gpu_model();

        // 5. Ambil informasi Disk Partisi
        let disks = Self::fetch_disks();

        DeviceSpec {
            manufacturer,
            model,
            serial_number,
            os_name,
            os_version,
            os_arch,
            cpu_model,
            cpu_cores,
            cpu_threads,
            ram_total_mb,
            gpu_model,
            disks,
        }
    }

    /// Ekstraksi identitas sistem via CIM / Registry BIOS
    fn fetch_system_identity() -> (String, String, String) {
        // Coba via PowerShell CIM query
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                r#"$p = Get-CimInstance Win32_ComputerSystemProduct; $b = Get-CimInstance Win32_BIOS; @{ Vendor = $p.Vendor; Name = $p.Name; Serial = if ($b.SerialNumber) { $b.SerialNumber } else { $p.IdentifyingNumber } } | ConvertTo-Json -Compress"#
            ])
            .output();

        if let Ok(out) = output {
            if let Ok(text) = std::str::from_utf8(&out.stdout) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim()) {
                    let vendor = v.get("Vendor").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                    let name = v.get("Name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
                    let serial = v.get("Serial").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();

                    if !vendor.is_empty() || !name.is_empty() || !serial.is_empty() {
                        return (
                            if vendor.is_empty() { "Generic".to_string() } else { vendor },
                            if name.is_empty() { "PC/Desktop".to_string() } else { name },
                            if serial.is_empty() { "UNKNOWN".to_string() } else { serial },
                        );
                    }
                }
            }
        }

        // Fallback: Registry BIOS
        let reg_out = std::process::Command::new("reg")
            .args(["query", r#"HKLM\HARDWARE\DESCRIPTION\System\BIOS"#])
            .output();

        let mut manufacturer = "Generic".to_string();
        let mut model = "Desktop".to_string();

        if let Ok(out) = reg_out {
            let res = String::from_utf8_lossy(&out.stdout);
            for line in res.lines() {
                if line.contains("SystemManufacturer") {
                    if let Some(val) = line.split("REG_SZ").nth(1) {
                        manufacturer = val.trim().to_string();
                    }
                } else if line.contains("SystemProductName") {
                    if let Some(val) = line.split("REG_SZ").nth(1) {
                        model = val.trim().to_string();
                    }
                }
            }
        }

        (manufacturer, model, "UNKNOWN".to_string())
    }

    /// Ekstraksi detail versi OS
    fn fetch_os_info() -> (String, String, String) {
        let os_arch = std::env::consts::ARCH.to_string();

        let mut os_name = System::name().unwrap_or_else(|| "Windows".to_string());
        let mut os_version = System::os_version().unwrap_or_else(|| "10.0".to_string());

        let reg_out = std::process::Command::new("reg")
            .args(["query", r#"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"#])
            .output();

        if let Ok(out) = reg_out {
            let res = String::from_utf8_lossy(&out.stdout);
            let mut prod_name = String::new();
            let mut display_ver = String::new();
            let mut current_build = String::new();

            for line in res.lines() {
                if line.contains("ProductName") && !line.contains("@") {
                    if let Some(val) = line.split("REG_SZ").nth(1) {
                        prod_name = val.trim().to_string();
                    }
                } else if line.contains("DisplayVersion") {
                    if let Some(val) = line.split("REG_SZ").nth(1) {
                        display_ver = val.trim().to_string();
                    }
                } else if line.contains("CurrentBuild") && !line.contains("CurrentBuildNumber") {
                    if let Some(val) = line.split("REG_SZ").nth(1) {
                        current_build = val.trim().to_string();
                    }
                }
            }

            if !prod_name.is_empty() {
                os_name = prod_name;
            }
            if !current_build.is_empty() {
                if !display_ver.is_empty() {
                    os_version = format!("{} (Build {})", display_ver, current_build);
                } else {
                    os_version = current_build;
                }
            }
        }

        (os_name, os_version, os_arch)
    }

    /// Ekstraksi kartu grafis (GPU)
    fn fetch_gpu_model() -> String {
        // Cek registry Video Controller Class 0000
        let reg_out = std::process::Command::new("reg")
            .args([
                "query",
                r#"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"#,
                "/v",
                "DriverDesc",
            ])
            .output();

        if let Ok(out) = reg_out {
            let res = String::from_utf8_lossy(&out.stdout);
            for line in res.lines() {
                if line.contains("DriverDesc") {
                    if let Some(val) = line.split("REG_SZ").nth(1) {
                        let gpu = val.trim().to_string();
                        if !gpu.is_empty() {
                            return gpu;
                        }
                    }
                }
            }
        }

        // Fallback CIM query
        let output = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-CimInstance Win32_VideoController).Name"])
            .output();

        if let Ok(out) = output {
            let res = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !res.is_empty() {
                return res.lines().next().unwrap_or("Generic Display Adapter").trim().to_string();
            }
        }

        "Standard VGA Adapter".to_string()
    }

    /// Mengambil daftar drive storage aktif menggunakan sysinfo
    fn fetch_disks() -> Vec<DiskSpec> {
        let mut list = Vec::new();
        let disks = Disks::new_with_refreshed_list();

        for disk in &disks {
            let raw_mount = disk.mount_point().to_string_lossy().to_string();
            let drive = raw_mount.trim_end_matches('\\').to_string();
            let total_gb = disk.total_space() / (1024 * 1024 * 1024);
            let free_gb = disk.available_space() / (1024 * 1024 * 1024);
            let fs_type = disk.file_system().to_string_lossy().to_string();

            // Saring hanya partisi disk fisik (memiliki kapasitas > 0)
            if total_gb > 0 {
                list.push(DiskSpec {
                    drive,
                    total_gb,
                    free_gb,
                    fs_type: if fs_type.is_empty() { "NTFS".to_string() } else { fs_type },
                });
            }
        }

        if list.is_empty() {
            // Default fallback
            list.push(DiskSpec {
                drive: "C:".to_string(),
                total_gb: 256,
                free_gb: 50,
                fs_type: "NTFS".to_string(),
            });
        }

        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_device_spec() {
        let spec = SpecCollector::collect();
        assert!(!spec.manufacturer.is_empty());
        assert!(!spec.model.is_empty());
        assert!(!spec.cpu_model.is_empty());
        assert!(spec.cpu_cores > 0);
        assert!(spec.ram_total_mb > 0);
        assert!(!spec.disks.is_empty());
    }
}
