# ITMS Endpoint Agent Daemon (Rust) - Architecture & Technical Specification

> **Dokumen Spesifikasi Teknis Resmi**  
> Proyek: **ITMS Endpoint Agent Daemon**  
> Bahasa: **Rust (Edition 2021)**  
> Target OS: **Windows 10 / Windows 11 / Windows Server (x86_64)**  
> Mode Operasi: **Windows Background Service (`LocalSystem`)**  
> Integrasi Server: **ITMS-Pro Central Backend (Django / REST API)**  

---

## 1. Latar Belakang & Tujuan (Executive Summary)

Dalam arsitektur pemantauan jaringan ITMS-Pro:
1. **MikroTik Router API** mencatat metrik level jaringan: bandwidth throughput harian (RX/TX), peak rate, dan liveness ARP/Hotspot per IP. Namun router tidak dapat mencatat riwayat web per individu secara akurat karena DNS cache router bersifat global (*router-wide*).
2. **ITMS Endpoint Agent** adalah daemon ringan berbasis **Rust** yang berjalan di background laptop/PC kantor untuk memberikan telemetri aktivitas aplikasi dan domain web secara 100% akurat, tahan terhadap mode *Incognito* maupun penggunaan VPN pribadi, serta tetap dapat merekam saat laptop dibawa dinas luar/WFH melalui *offline buffer*.

### Target Performa & Kepatuhan
* **Resource Footprint:** Konsumsi RAM < 15 MB, CPU < 0.1% saat idle, ukuran binary single `.exe` < 10 MB.
* **Non-Intrusive:** Tidak menggunakan teknik injeksi memori (*no DLL injection*), tidak merekam ketikan tombol (*no keylogger*), dan tidak memotret layar. 100% patuh terhadap Microsoft Windows Defender dan UU Pelindungan Data Pribadi.
* **Offline Resilient:** Telemetri tetap disimpan di local buffer (SQLite) saat laptop offline dan otomatis dikirim begitu tersambung internet.

---

## 2. Arsitektur Komponen Daemon (Modular Design)

```
                       +---------------------------------------------+
                       |        Windows Operating System             |
                       +---------------------------------------------+
                                      |                   |
            [DNS Query: DnsClient ETW]                     [Active Window: Win32 API]
                                      |                   |
                                      v                   v
+------------------------------------------------------------------------------------+
|                         ITMS-AGENTS-DAEMON (RUST)                                  |
|                                                                                    |
|   +---------------------+   +--------------------------+   +-------------------+   |
|   |  DNS Sniffer Engine |   | Active Window & Duration |   | Network Usage     |   |
|   | (ETW Event Consumer)|   | (Foreground Window API)  |   | (Socket / PID)    |   |
|   +---------------------+   +--------------------------+   +-------------------+   |
|             \                            |                            /            |
|              +---------------------------+---------------------------+             |
|                                          |                                         |
|                                          v                                         |
|                           +------------------------------+                         |
|                           |  Telemetry Aggregator & FQDN |                         |
|                           |      Domain Classifier       |                         |
|                           +------------------------------+                         |
|                                          |                                         |
|                                          v                                         |
|                           +------------------------------+                         |
|                           | Local Buffer Storage (SQLite)|                         |
|                           |  %PROGRAMDATA%\ITMS\queue.db |                         |
|                           +------------------------------+                         |
|                                          |                                         |
|                             (HTTP Post Batch Flusher)                              |
|                                          v                                         |
+------------------------------------------------------------------------------------+
                                           |
                                  HTTPS (Port 443)
                                           v
+------------------------------------------------------------------------------------+
|                     ITMS-PRO CENTRAL BACKEND (DJANGO)                              |
|         POST /network/api/telemetry/push/  --> Ingest ke IPAppActivityLog           |
+------------------------------------------------------------------------------------+
```

---

## 3. Spesifikasi Modul Teknis

### Modul 1: Windows DNS Event Tracing (ETW Sniffer)
* **Tujuan:** Menangkap semua domain/FQDN yang diminta oleh aplikasi pengguna (`facebook.com`, `chatgpt.com`, `youtube.com`, `situs-dewasa.com`) secara real-time.
* **Mekanisme:** Subscribe ke Windows ETW Provider:
  - **Provider Name:** `Microsoft-Windows-DNS-Client`
  - **Provider GUID:** `{1C950233-BE26-4226-90F9-C1E47214E7E8}`
  - **Event ID 3008:** DNS Query Completed (`QueryName`, `QueryType`, `QueryStatus`, `PID`).
* **Kelebihan:** 
  - Tidak terpengaruh mode *Incognito* / *Private Browsing*.
  - Mengetahui *Process ID* (`PID`) dan nama aplikasi yang meminta domain tersebut (misal `chrome.exe`, `msedge.exe`, `curl.exe`).
  - Zero-packet inspection (tanpa perlu install WinPcap/Npcap driver).

### Modul 2: Active Window & Screen Time Tracker
* **Tujuan:** Mengukur durasi aktif pengguna pada situs atau software bisnis tertentu (*Foreground User Engagement*).
* **Mekanisme:**
  - Menggunakan API Windows `GetForegroundWindow()` dan `GetWindowTextW()`.
  - Mengambil judul window aktif setiap interval sampling (misal setiap 3-5 detik).
  - Menggunakan `GetLastInputInfo()` untuk mendeteksi *User Idle State* (jika mouse & keyboard tidak disentuh > 5 menit, timer otomatis di-pause).
* **Contoh Ekstraksi:**
  - `ChatGPT - Google Chrome` -> Domain: `chatgpt.com`, App: `ChatGPT`, Kategori: `Work/Productivity`.
  - `(3) Facebook - Google Chrome` -> Domain: `facebook.com`, App: `Facebook`, Kategori: `Social Media`.
  - `Document1 - Microsoft Word` -> App: `Microsoft Word`, Kategori: `Work/Productivity`.

### Modul 3: Local Offline Queue Buffer
* **Tujuan:** Mencegah hilangnya data saat laptop dibawa keluar kantor, WFH, atau koneksi terputus.
* **Penyimpanan:** SQLite database lokal pada path:
  `C:\ProgramData\ITMS\buffer\telemetry_queue.db` (dibatasi maksimal 50 MB, otomatis rolling/FIFO).
* **Mekanisme Drain:**
  - Setiap 60 detik (dapat diatur via config), daemon memeriksa koneksi internet.
  - Jika server ITMS-Pro dapat dihubungi, daemon mengirimkan batch 100 entri dan menghapus data yang sudah terkonfirmasi sukses dari buffer SQLite.

### Modul 4: Windows Service Controller
* **Tujuan:** Berjalan sebagai *background service* resmi Windows.
* **Nama Service:** `ITMSAgentService`
* **Display Name:** `ITMS Endpoint Telemetry Daemon`
* **Startup Type:** `Automatic`
* **Security Context:** Berjalan di bawah akun `NT AUTHORITY\LocalSystem` sehingga tidak dapat dihentikan oleh user non-administrator dari Task Manager biasa.

---

## 4. Kontrak Payload JSON (API Schema)

Daemon mengirimkan telemetri ke server ITMS-Pro melalui endpoint HTTPS:
`POST https://itms.domain.com/network/api/telemetry/push/`

### Format Header
```http
POST /network/api/telemetry/push/ HTTP/1.1
Host: itms.pmgcloud.my.id
Content-Type: application/json
X-ITMS-Agent-Key: sec-agent-token-xyz-123
X-Machine-UUID: 4C4C4544-004B-4D10-8043-B2C04F323533
```

### Format Body JSON
```json
{
  "agent_version": "1.0.0",
  "machine_uuid": "4C4C4544-004B-4D10-8043-B2C04F323533",
  "hostname": "LAPTOP-EDELIX",
  "mac_address": "D0:37:45:3E:E9:E8",
  "ip_address": "192.168.0.67",
  "timestamp": "2026-10-25T14:30:00Z",
  "metrics": {
    "cpu_usage_pct": 12.5,
    "memory_used_mb": 6240,
    "uptime_seconds": 184500
  },
  "activities": [
    {
      "domain": "chatgpt.com",
      "app_name": "ChatGPT AI Assistant",
      "category": "work_productivity",
      "duration_seconds": 1840,
      "total_bytes": 1420500,
      "source_type": "agent"
    },
    {
      "domain": "facebook.com",
      "app_name": "Facebook",
      "category": "social",
      "duration_seconds": 450,
      "total_bytes": 850000,
      "source_type": "agent"
    },
    {
      "domain": "erp.pmgcloud.my.id",
      "app_name": "Internal SAP / ERP",
      "category": "work_productivity",
      "duration_seconds": 3600,
      "total_bytes": 4520000,
      "source_type": "agent"
    }
  ]
}
```

---

## 5. Rekomendasi Crate Rust (`Cargo.toml`)

Berikut daftar pustaka resmi Rust yang disarankan untuk proyek ini:

```toml
[package]
name = "itms-agents-daemon"
version = "0.1.0"
edition = "2021"
authors = ["ITMS Engineering Team"]

[dependencies]
# Async Runtime & Networking
tokio = { version = "1.38", features = ["full"] }
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Windows Native APIs & Service Wrapper
windows-service = "0.7"
windows = { version = "0.58", features = [
    "Win32_Foundation",
    "Win32_UI_WindowsAndMessaging",
    "Win32_UI_Input_KeyboardAndMouse",
    "Win32_System_Diagnostics_Etw",
    "Win32_NetworkManagement_IpHelper",
    "Win32_System_SystemInformation"
]}

# Local Storage / Offline Buffer
rusqlite = { version = "0.31", features = ["bundled"] }

# System Telemetry & Utilities
sysinfo = "0.30"
mac_address = "1.1"
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

---

## 6. Checklist Implementasi (Tahapan Pengerjaan)

1. **Inisialisasi Project:** `cargo init --bin itms-agents-daemon`
2. **Phase 1: Hardware & Identitas Endpoint**
   - Ambil Hardware UUID via WMI / SMBIOS (`Win32_ComputerSystemProduct.UUID`).
   - Ambil Primary MAC Address dan Local IP Address.
3. **Phase 2: Foreground Window Tracker**
   - Polling loop setiap 3 detik mengecek active window handle.
   - Ekstrak title window, parse nama domain/aplikasi.
   - Filter durasi berdasarkan input aktif pengguna (`GetLastInputInfo`).
4. **Phase 3: Windows DNS ETW Consumer**
   - Buka sesi ETW dan tangkap event domain DNS query.
5. **Phase 4: SQLite Offline Store & HTTP Client**
   - Skema tabel `queue` di SQLite lokal.
   - Worker async yang melakukan *drain & push* ke backend ITMS-Pro.
6. **Phase 5: Windows Service Wrapper & Installer**
   - Daftarkan service handler (`windows-service`).
   - Perintah CLI pendukung: `itms-agent.exe install`, `itms-agent.exe start`, `itms-agent.exe uninstall`.

---

*Dokumen ini dapat langsung dibaca dan diacu oleh Agent Antigravity pada percakapan baru untuk memulai penulisan kode Rust.*
