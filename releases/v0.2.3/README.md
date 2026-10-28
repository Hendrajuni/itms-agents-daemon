# ITMS Endpoint Agent Daemon - Release v0.2.3 (Windows x86_64)

> **Versi Rilis:** `v0.2.3`  
> **Arsitektur:** Windows 64-bit (`x86_64-pc-windows-gnu`)  
> **Target OS:** Windows 10 / Windows 11 / Windows Server 2016+  
> **Bahasa:** Rust (Edition 2021)  
> **Ukuran Binary:** ~3.21 MB (Single standalone executable, zero external DLL)

---

## 🌟 Fitur Utama v0.2.3 (Traffic Filter & Noise Suppression)

1. **🛡️ Windows Internal Process Filtering (Baru di v0.2.3):**
   * Mengabaikan koneksi socket dan transfer data dari proses sistem latar belakang internal Windows (seperti `mpcmdrun.exe`, `svchost.exe`, `textinputhost.exe`, `msmpeng.exe`, `searchhost.exe`, `taskhostw.exe`, `runtimebroker.exe`, `smartscreen.exe`, `ctfmon.exe`, dll.).
   * Mengabaikan PID 0 dan PID 4 (`system` / `system.local`).
2. **🚫 Unresolved Process Name Suppression (Baru di v0.2.3):**
   * Menghentikan pengiriman dan pencatatan nama proses yang gagal di-resolve oleh Windows API (`pid_*.exe`), menjaga kebersihan antrean SQLite dan database server ITMS-Pro.
   * Strategi multi-layer defense pada ETW TCPIP consumer, in-memory traffic aggregator, background traffic drain loop, dan HTTP pusher batch queue.
3. **⚡ Two-Way Command Queue & On-Demand Audit (v0.2.2):**
   * Menerima payload perintah `TRIGGER_FULL_SCAN` dari dashboard web ITMS-Pro (Django) saat admin mengklik tombol `[⚡ Sinkronkan]`.
   * Langsung mengeksekusi pemindaian hardware & audit software seketika (*real-time*) pada siklus berikutnya tanpa menunggu interval 24 jam.
4. **📊 Windows Native TCPIP Traffic Accounting Engine (v0.2.1+):**
   * Mengukur volume data jaringan (download/upload byte) menggunakan kernel ETW provider `Microsoft-Windows-TCPIP` (Events 1074, 1073, 1170, 1169).
   * Merekam byte fisik jaringan per proses dan per domain tanpa instalasi driver pihak ketiga (tanpa WinPcap / Npcap).
5. **Active Window & Screen Time Tracker (`src/window_tracker.rs`):**
   * Pelacakan judul aplikasi dan tab browser yang sedang aktif secara presisi (*ground truth*).
   * Deteksi *User Idle State* (otomatis pause saat pengguna tidak aktif > 5 menit).
6. **DNS Query Sniffer Engine (`src/dns_etw.rs`):**
   * Konsumsi Event Tracing for Windows (ETW) provider `Microsoft-Windows-DNS-Client` (Event ID 3008).
   * Mengetahui domain web dan Process ID (PID) pemanggil bahkan saat pengguna memakai mode Incognito / DoH.
7. **Hardware & OS Specification Extractor (`src/spec.rs`):**
   * Ekstraksi identitas perangkat: Pabrikan (Manufacturer), Model, dan Serial Number / Service Tag via SMBIOS BIOS.
   * Spesifikasi OS lengkap: Windows Edition, Display Version, Build Number, dan Arsitektur OS.
   * Spesifikasi Jeroan: Processor (CPU Model, Cores, Threads), Total RAM Fisik (MB/GB), GPU Display Adapter, dan rincian partisi drive storage (`C:`, `D:`, kapasitas total, dan free space).
8. **Installed Software Inventory Audit Scanner (`src/software.rs`):**
   * Audit seluruh aplikasi desktop yang terpasang di komputer pengguna melalui scanning Registry Windows (HKLM 64-bit, WOW6432Node, HKCU per-user).
   * Auto-purge & auto-sync dengan backend ITMS-Pro.
9. **Offline SQLite Queue Buffer (`src/storage.rs`):**
   * Penyimpanan lokal transaksional SQLite (`%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db`) saat koneksi jaringan terputus (offline-first).
10. **Keamanan & Kepatuhan Non-Intrusive:**
    * 100% patuh UU PDP & Windows Defender: Zero packet capture driver, zero DLL injection, no keylogger, no screen capture.
    * Penggunaan memori < 15 MB dan CPU idle < 0.1%.

---

## 📁 Struktur Berkas Rilis

* **`itms-agents-daemon-v0.2.3-windows-x64.exe`** : Binary release dengan nama berversi lengkap untuk arsip GitHub Releases.
* **`itms-agents-daemon.exe`** : Binary release standar yang digunakan oleh Windows Service wrapper.
* **`itms-agents-daemon-v0.2.3-windows-x64.zip`** : Paket arsip ZIP rilis v0.2.3.
* **`itms-agents-daemon-latest-windows-x64.zip`** : Alias paket ZIP untuk automasi download rilis terbaru.
* **`agent.toml.example`** : Template konfigurasi agent (URL backend ITMS-Pro, Agent Key, dll).
* **`install-service.bat`** : Skrip batch 1-klik untuk mendaftarkan dan menyalakan agent sebagai Windows Background Service (`LocalSystem`).
* **`uninstall-service.bat`** : Skrip batch untuk menghentikan dan mencabut Windows Service.
* **`start-service.bat`** / **`stop-service.bat`** : Skrip kontrol service.
* **`run-interactive.bat`** : Menjalankan agent di jendela konsol (mode debug interaktif).

---

## 🚀 Panduan Pemasangan Cepat

1. Salin `agent.toml.example` menjadi `agent.toml`:
   ```cmd
   copy agent.toml.example agent.toml
   ```
2. Buka `agent.toml` dengan text editor, lalu masukkan URL ITMS-Pro backend dan Agent Key Anda:
   ```toml
   [server]
   url = "http://192.168.0.2:8000/network/api/telemetry/push/"
   agent_key = "token-rahasia-anda"
   ```
3. Klik kanan pada **`install-service.bat`**, lalu pilih **"Run as administrator"**.
4. Verifikasi status service melalui PowerShell atau Services console (`services.msc`):
   ```powershell
   Get-Service -Name ITMSAgentService
   ```

