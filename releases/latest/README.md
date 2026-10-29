# ITMS Endpoint Agent Daemon (Windows)

[![Rust Version](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/)
[![Target Platform](https://img.shields.io/badge/platform-Windows%20x86__64-blue.svg)](https://microsoft.com/windows)
[![Release Version](https://img.shields.io/badge/release-v0.3.0-brightgreen.svg)](releases/v0.3.0/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ITMS Endpoint Agent Daemon** adalah background service Windows mandiri (*standalone single executable*) berbasis **Rust** yang dirancang untuk mengumpulkan telemetri aktivitas aplikasi, domain web, volume trafik data jaringan riil, pengawasan Windows Event Log keamanan & crash sistem, spesifikasi perangkat keras, dan audit inventaris software secara 100% presisi (*ground truth*), lalu menyinkronkannya ke server pusat **ITMS-Pro** (Django).

---

## 🌟 Fitur Utama

* **🛡️ Windows EventLog Real-Time Push Ingestion (v0.3.0):** Modul background subscriber pengawas Windows Event Log (`eventlog_watcher`) yang berjalan murni secara *event-driven* (**0% CPU idle**) via Win32 `EvtSubscribe` (`EvtSubscribeToFutureEvents`).
  * **Insiden Keamanan (Security Channel):** Menangkap Brute-Force Logon Failed (Event 4625), User Account Created (4720), User Deleted (4726), dan Account Lockout (4740).
  * **Kesehatan Sistem & Stabilitas (System Channel):** Menangkap Service Crash (7034), Service Stopped (7036 dengan filter kebisingan), File System NTFS Corrupt (55), Volume Disk Corrupt (98), Planned Restart/Shutdown (1074), dan Kernel-Power Dirty Reboot / BSOD / Mati Lampu (41).
  * **Prinsip Anti-Lokalisasi & Deterministik:** Deskripsi pesan dirangkai deterministik dalam Bahasa Inggris standar dari data mentah `<EventData>`, bebas kendala perbedaan bahasa sistem operasi.
  * **Ketahanan Offline (SQLite Buffer):** Disimpan ke tabel `event_log_queue` di `%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db` (kuota 20 MB FIFO drop) dan otomatis di-drain secara bertahap (batch 50 entri) via endpoint `POST /network/api/logs/ingest/` dengan header ganda `X-ITMS-Agent-Key`, `X-ITMS-Agent-Token`, dan `X-Machine-UUID`.
* **🎯 Native IP Helper MAC Binding & Physical Interface Detection (v0.2.4):** Deteksi identitas antarmuka jaringan fisik (Wi-Fi / Ethernet) menggunakan Windows Native IP Helper API (`GetAdaptersAddresses`), mengorelasikan MAC address fisik secara akurat dengan rute IP outbound lokal aktif, serta memfilter adapter virtual yang tidak relevan (TAP, OpenVPN, Wi-Fi Direct Virtual Adapter, VPN tunnel) agar terhindar dari duplikasi entri IPAM.
* **🏷️ Device Identity Override Support (v0.2.4):** Mendukung konfigurasi *override* IP, MAC address, dan Hostname melalui seksi `[device]` pada `agent.toml`, memudahkan pengujian di luar jaringan kantor (WFH / remote) agar telemetri tetap terpetakan ke entri endpoint kantor yang tepat.
* **🛡️ Windows Internal Process Filtering & Noise Suppression (v0.2.3):** Mengabaikan koneksi proses sistem Windows internal (`mpcmdrun.exe`, `svchost.exe`, `textinputhost.exe`, `msmpeng.exe`, `searchhost.exe`, `smartscreen.exe`, PID 0, PID 4, dll.) dan mencegah pengiriman proses yang gagal di-resolve namanya (`pid_*.exe`), menjaga database ITMS-Pro tetap bersih.
* **🔧 Robust Windows Service Installer (v0.2.3+):** Skrip `install-service.bat` dan wrapper Service Control Manager native menggunakan sintaks parameter `sc.exe` yang tepat dengan evaluasi errorlevel aman, memastikan instalasi dan *auto-start* service berjalan mulus.
* **⚡ Two-Way Command Queue & On-Demand Audit (v0.2.2):** Menerima instruksi instan `TRIGGER_FULL_SCAN` dari dashboard web ITMS-Pro (Django) saat admin mengklik tombol `[⚡ Sinkronkan]`, langsung memicu audit hardware & inventaris software secara *real-time* tanpa menunggu siklus 24 jam.
* **📊 Windows Native TCPIP Traffic Accounting Engine (v0.2.1+):** Menangkap byte riil TCP/UDP data transfer via kernel Windows *Event Tracing for Windows* (ETW Provider: `Microsoft-Windows-TCPIP`) tanpa driver pihak ketiga (*zero Npcap/WinPcap*), mengagregasikan volume traffic fisik per domain dan proses aplikasi.
* **🌐 Windows DNS ETW Sniffer Engine:** Menangkap query DNS via ETW (`Microsoft-Windows-DNS-Client`, Event ID 3008) beserta Process ID (PID) pemanggil, bahkan pada mode *Incognito* / *DoH*.
* **🕒 Active Window & Screen Time Tracker:** Pelacakan durasi aktif jendela aplikasi dan judul situs browser dengan deteksi otomatis status *User Idle* (> 5 menit tidak ada input mouse/keyboard).
* **💻 Hardware & OS Specification Extractor:** Ekstraksi otomatis Manufacturer, Model, BIOS Serial Number / Service Tag, OS Edition & Build, CPU (Cores/Threads), Total RAM (MB), GPU Display Adapter, dan partisi drive storage (`C:`, `D:`, free space).
* **📦 Installed Software Inventory Audit Scanner:** Pemindaian seluruh aplikasi terinstal di Windows Registry (HKLM 64-bit, WOW6432Node, HKCU per-user) dengan sinkronisasi otomatis ke database pusat.
* **💾 Offline-First FIFO Storage Buffer:** Menyimpan antrean telemetri ke database lokal SQLite (`%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db`) saat koneksi terputus dan otomatis di-drain saat kembali online.
* **🛡️ Kinerja Ringan & Aman (Non-Intrusive):**
  * Ukuran binary tunggal: **~3.2 MB** (*zero external DLL*).
  * Penggunaan memori: **< 15 MB RAM**, beban CPU idle: **< 0.1%**.
  * Tidak menggunakan driver packet capture pihak ketiga (tanpa WinPcap/Npcap), tanpa screen capture, tanpa keylogger, dan 100% patuh Microsoft Defender & UU PDP.

---

## 🚀 Panduan Instalasi Cepat

### 1. Unduh Berkas Rilis
Unduh paket rilis terbaru di tab [**Releases**](https://github.com/Hendrajuni/itms-agents-daemon/releases/latest) atau gunakan folder [`releases/v0.3.0/`](releases/v0.3.0/) / [`releases/latest/`](releases/latest/).

### 2. Konfigurasi `agent.toml`
Salin template `agent.toml.example` menjadi `agent.toml` pada folder instalasi atau ke `%PROGRAMDATA%\ITMS\agent.toml`:
```toml
[server]
# Gunakan domain publik atau IP VPS ITMS
url = "https://itms.pmgcloud.my.id/network/api/telemetry/push/"
# Sesuaikan dengan AGENT_SECRET_KEY pada file .env server ITMS
agent_key = "django-insecure-itms-pmgcloud-2026-safe-key"
flusher_interval_secs = 60
batch_size = 100
request_timeout_secs = 15

[tracker]
window_sampling_secs = 3
idle_threshold_secs = 300

[storage]
db_path = "C:\\ProgramData\\ITMS\\buffer\\telemetry_queue.db"
max_db_size_mb = 50

[logging]
level = "info"

[device]
# Opsional: Override IP, MAC, atau Hostname untuk simulasi / environment pengujian khusus (misal WFH)
# override_ip = "192.168.1.155"
# override_mac = "D0:39:57:7C:BB:67"
# override_hostname = "DESKTOP-SM73UFF"
```

### 3. Jalankan Agent

#### Opsi A: Daftarkan sebagai Windows Service (Permanen di Background)
Klik kanan file **`install-service.bat`** lalu pilih **"Run as Administrator"**.  
Service akan terdaftar sebagai `ITMSAgentService` dengan tipe startup `Automatic` (berjalan terus di background).

* Untuk menyalakan: Jalankan `start-service.bat` atau via PowerShell: `Start-Service ITMSAgentService`
* Untuk mematikan: Jalankan `stop-service.bat` atau via PowerShell: `Stop-Service ITMSAgentService`
* Untuk mencabut service: Klik kanan `uninstall-service.bat` -> **"Run as Administrator"**.

#### Opsi B: Mode Interaktif / Debug (Konsol Foreground)
Jalankan file **`run-interactive.bat`** atau melalui terminal:
```powershell
.\itms-agents-daemon.exe run
```
Tekan `Ctrl + C` untuk keluar secara aman.

---

## 🏗️ Struktur Proyek

```text
itms-agents-daemon/
├── config/                     # Template konfigurasi agent (agent.toml.example)
├── releases/                   # Bundel rilis binary & script instalasi
│   ├── v0.3.0/                 # Arsip rilis v0.3.0 (ZIP, EXE, batch scripts, checksum)
│   └── latest/                 # Salinan rilis terbaru (v0.3.0)
├── src/                        # Kode sumber Rust
│   ├── classifier.rs           # Domain normalizer & FQDN classifier
│   ├── config.rs               # TOML configuration loader & device overrides
│   ├── dns_etw.rs              # Event Tracing for Windows DNS sniffer
│   ├── eventlog_watcher.rs     # Windows EventLog push-subscriber (Security & System)
│   ├── flusher.rs              # HTTP batch flusher, 2-way command queue & log flusher
│   ├── hardware.rs             # Endpoint identity (IP Helper API MAC & UUID) & system metrics
│   ├── main.rs                 # CLI entry point & worker coordinator
│   ├── net_etw.rs              # Kernel TCPIP event stream accounting (ETW)
│   ├── service.rs              # Windows Service Control Manager wrapper
│   ├── software.rs             # Windows Registry software audit scanner
│   ├── spec.rs                 # Hardware & OS specification extractor
│   ├── storage.rs              # SQLite FIFO queue & offline storage
│   ├── traffic.rs              # Network traffic & DNS resolution aggregator
│   └── window_tracker.rs       # Foreground window title & user idle tracker
├── Cargo.toml                  # Rust dependencies & LTO profile configuration
└── README.md                   # Dokumentasi repositori
```

---

## 📄 Lisensi
Didistribusikan di bawah lisensi MIT. Lihat berkas `LICENSE` untuk informasi lebih lanjut.
