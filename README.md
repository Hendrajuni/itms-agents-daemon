# ITMS Endpoint Agent Daemon (Windows)

[![Rust Version](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/)
[![Target Platform](https://img.shields.io/badge/platform-Windows%20x86__64-blue.svg)](https://microsoft.com/windows)
[![Release Version](https://img.shields.io/badge/release-v0.2.3-brightgreen.svg)](releases/v0.2.3/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**ITMS Endpoint Agent Daemon** adalah background service Windows mandiri (*standalone single executable*) berbasis **Rust** yang dirancang untuk mengumpulkan telemetri aktivitas aplikasi, domain web, volume trafik data jaringan riil, spesifikasi perangkat keras, dan audit inventaris software secara 100% presisi (*ground truth*), lalu menyinkronkannya ke server pusat **ITMS-Pro** (Django).

---

## 🌟 Fitur Utama

* **🛡️ Windows Internal Process Filtering & Noise Suppression (v0.2.3):** Mengabaikan koneksi proses sistem Windows internal (`mpcmdrun.exe`, `svchost.exe`, `textinputhost.exe`, `msmpeng.exe`, `searchhost.exe`, `smartscreen.exe`, PID 0, PID 4, dll.) dan mencegah pengiriman proses yang gagal di-resolve namanya (`pid_*.exe`), menjaga database ITMS-Pro tetap bersih.
* **⚡ Two-Way Command Queue & On-Demand Audit (v0.2.2):** Menerima instruksi instan `TRIGGER_FULL_SCAN` dari dashboard web ITMS-Pro (Django) saat admin mengklik tombol `[⚡ Sinkronkan]`, langsung memicu audit hardware & inventaris software secara *real-time* tanpa menunggu siklus 24 jam.
* **📊 Windows Native TCPIP Traffic Accounting Engine (v0.2.1+):** Menangkap byte riil TCP/UDP data transfer via kernel Windows *Event Tracing for Windows* (ETW Provider: `Microsoft-Windows-TCPIP`) tanpa driver pihak ketiga (*zero Npcap/WinPcap*), mengagregasikan volume traffic fisik per domain dan proses aplikasi.
* **🌐 Windows DNS ETW Sniffer Engine:** Menangkap query DNS via ETW (`Microsoft-Windows-DNS-Client`, Event ID 3008) beserta Process ID (PID) pemanggil, bahkan pada mode *Incognito* / *DoH*.
* **🕒 Active Window & Screen Time Tracker:** Pelacakan durasi aktif jendela aplikasi dan judul situs browser dengan deteksi otomatis status *User Idle* (> 5 menit tidak ada input mouse/keyboard).
* **💻 Hardware & OS Specification Extractor:** Ekstraksi otomatis Manufacturer, Model, BIOS Serial Number / Service Tag, OS Edition & Build, CPU (Cores/Threads), Total RAM (MB), GPU Display Adapter, dan partisi drive storage (`C:`, `D:`, free space).
* **📦 Installed Software Inventory Audit Scanner:** Pemindaian seluruh aplikasi terinstal di Windows Registry (HKLM 64-bit, WOW6432Node, HKCU per-user) dengan sinkronisasi otomatis ke database pusat.
* **💾 Offline-First FIFO Storage Buffer:** Menyimpan antrean telemetri ke database lokal SQLite (`%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db`) saat koneksi terputus dan otomatis di-drain saat kembali online.
* **🛡️ Kinerja Ringan & Aman (Non-Intrusive):**
  * Ukuran binary tunggal: **~3.21 MB** (*zero external DLL*).
  * Penggunaan memori: **< 15 MB RAM**, beban CPU idle: **< 0.1%**.
  * Tidak menggunakan driver packet capture pihak ketiga (tanpa WinPcap/Npcap), tanpa screen capture, tanpa keylogger, dan 100% patuh Microsoft Defender & UU PDP.

---

## 🚀 Panduan Instalasi Cepat

### 1. Unduh Berkas Rilis
Unduh paket rilis terbaru di tab [**Releases**](https://github.com/Hendrajuni/itms-agents-daemon/releases/latest) atau gunakan folder [`releases/v0.2.3/`](releases/v0.2.3/).

### 2. Konfigurasi `agent.toml`
Salin template `agent.toml.example` menjadi `agent.toml` pada folder instalasi:
```toml
[server]
url = "http://<IP-SERVER-ITMS-PRO>:8000/network/api/telemetry/push/"
agent_key = "sec-agent-token-xyz-123"
flusher_interval_secs = 60
batch_size = 100

[tracker]
window_sampling_secs = 3
idle_threshold_secs = 300

[storage]
db_path = "C:\\ProgramData\\ITMS\\buffer\\telemetry_queue.db"
max_db_size_mb = 50
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
├── config/                     # Template konfigurasi agent
├── releases/                   # Bundel rilis binary & script instalasi
│   ├── v0.2.3/                 # Arsip rilis v0.2.3 (ZIP, EXE, batch scripts, checksum)
│   └── latest/                 # Salinan rilis terbaru (v0.2.3)
├── src/                        # Kode sumber Rust
│   ├── classifier.rs           # Domain normalizer & FQDN classifier
│   ├── config.rs               # TOML configuration loader
│   ├── dns_etw.rs              # Event Tracing for Windows DNS sniffer
│   ├── flusher.rs              # HTTP batch flusher, 2-way command queue & inventory scheduler
│   ├── hardware.rs             # Endpoint identity & system metrics
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
