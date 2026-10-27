# ITMS Endpoint Agent Daemon - Release v0.2.2 (Windows x86_64)

> **Versi Rilis:** `v0.2.2`  
> **Arsitektur:** Windows 64-bit (`x86_64-pc-windows-gnu`)  
> **Target OS:** Windows 10 / Windows 11 / Windows Server 2016+  
> **Bahasa:** Rust (Edition 2021)  
> **Ukuran Binary:** ~3.21 MB (Single standalone executable, zero external DLL)

---

## 🌟 Fitur Utama v0.2.2 (Enterprise Endpoint Edition)

1. **⚡ Two-Way Command Queue & On-Demand Audit (Baru di v0.2.2):**
   * Menerima payload perintah `TRIGGER_FULL_SCAN` dari dashboard web ITMS-Pro (Django) saat admin mengklik tombol `[⚡ Sinkronkan]`.
   * Langsung mengeksekusi pemindaian hardware & audit software seketika (*real-time*) pada siklus berikutnya tanpa menunggu interval 24 jam.
2. **📊 Windows Native TCPIP Traffic Accounting Engine (v0.2.1+):**
   * Mengukur volume data jaringan (download/upload byte) menggunakan kernel ETW provider `Microsoft-Windows-TCPIP` (Events 1074, 1073, 1170, 1169).
   * Merekam byte fisik jaringan per proses dan per domain tanpa instalasi driver pihak ketiga (tanpa WinPcap / Npcap).
3. **Active Window & Screen Time Tracker (`src/window_tracker.rs`):**
   * Pelacakan judul aplikasi dan tab browser yang sedang aktif secara presisi (*ground truth*).
   * Deteksi *User Idle State* (otomatis pause saat pengguna tidak aktif > 5 menit).
4. **DNS Query Sniffer Engine (`src/dns_etw.rs`):**
   * Konsumsi Event Tracing for Windows (ETW) provider `Microsoft-Windows-DNS-Client` (Event ID 3008).
   * Mengetahui domain web dan Process ID (PID) pemanggil bahkan saat pengguna memakai mode Incognito / DoH.
5. **Hardware & OS Specification Extractor (`src/spec.rs`):**
   * Ekstraksi identitas perangkat: Pabrikan (Manufacturer), Model, dan Serial Number / Service Tag via SMBIOS BIOS.
   * Spesifikasi OS lengkap: Windows Edition, Display Version, Build Number, dan Arsitektur OS.
   * Spesifikasi Jeroan: Processor (CPU Model, Cores, Threads), Total RAM Fisik (MB/GB), GPU Display Adapter, dan rincian partisi drive storage (`C:`, `D:`, kapasitas total, dan free space).
6. **Installed Software Inventory Audit Scanner (`src/software.rs`):**
   * Audit seluruh aplikasi desktop yang terpasang di komputer pengguna melalui scanning Registry Windows (HKLM 64-bit, WOW6432Node, HKCU per-user).
   * Auto-purge & auto-sync dengan backend ITMS-Pro.
7. **Offline SQLite Queue Buffer (`src/storage.rs`):**
   * Penyimpanan lokal transaksional SQLite (`%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db`) saat koneksi jaringan terputus (offline-first).
8. **Keamanan & Kepatuhan Non-Intrusive:**
   * 100% patuh UU PDP & Windows Defender: Zero packet capture driver, zero DLL injection, no keylogger, no screen capture.
   * Penggunaan memori < 15 MB dan CPU idle < 0.1%.

---

## 📁 Struktur Berkas Rilis

* **`itms-agents-daemon-v0.2.2-windows-x64.exe`** : Binary release dengan nama berversi lengkap untuk arsip GitHub Releases.
* **`itms-agents-daemon.exe`** : Binary release standar yang digunakan oleh Windows Service wrapper.
* **`itms-agents-daemon-v0.2.2-windows-x64.zip`** : Paket arsip ZIP rilis v0.2.2.
* **`itms-agents-daemon-latest-windows-x64.zip`** : Alias paket ZIP untuk automasi download rilis terbaru.
* **`agent.toml.example`** : Template konfigurasi agent (URL backend ITMS-Pro, Agent Key, dll).
* **`install-service.bat`** : Skrip batch 1-klik untuk mendaftarkan dan menyalakan agent sebagai Windows Background Service (`LocalSystem`).
* **`uninstall-service.bat`** : Skrip batch untuk menghentikan dan mencabut Windows Service.
* **`start-service.bat`** / **`stop-service.bat`** : Skrip kontrol service.
* **`run-interactive.bat`** : Menjalankan agent di jendela konsol (mode debug interaktif).
* **`SHA256SUMS.txt`** : Hash integritas kriptografis berkas rilis.

---

## 🚀 Panduan Instalasi Cepat

### Metode 1: Instalasi sebagai Windows Background Service (Direkomendasikan untuk Kantor)

1. Salin seluruh isi folder ini ke direktori permanen di komputer klien, misalnya:
   `C:\Program Files\ITMS Agent\`
2. Gandakan file `agent.toml.example` menjadi `agent.toml`.
3. Buka `agent.toml` dengan Notepad dan sesuaikan konfigurasi:
   ```toml
   [server]
   url = "http://192.168.1.155:8000/network/api/telemetry/push/"
   agent_key = "sec-agent-token-xyz-123"
   flusher_interval_secs = 60
   ```
4. Klik kanan berkas **`install-service.bat`** lalu pilih **"Run as Administrator"**.
5. Service akan otomatis terdaftar sebagai `ITMSAgentService` dengan tipe startup `Automatic` (selalu berjalan di background bahkan sebelum pengguna login).

### Metode 2: Menjalankan Langsung di Konsol (Interactive / Debug)

1. Pastikan file `agent.toml` sudah disesuaikan.
2. Klik dua kali berkas **`run-interactive.bat`** atau jalankan via PowerShell:
   ```powershell
   .\itms-agents-daemon.exe run
   ```
3. Tekan `Ctrl + C` untuk keluar secara aman.

---

## 🔒 Verifikasi Integritas SHA-256

Untuk memverifikasi keaslian berkas yang diunduh:
```powershell
Get-FileHash itms-agents-daemon-v0.2.2-windows-x64.exe -Algorithm SHA256
```
Cocokkan nilai hash dengan berkas `SHA256SUMS.txt`.
