# Deployment Plan - ITMS Endpoint Agent Daemon (Rust)

> **File Panduan Utama & Cetak Biru Arsitektur (*Source of Truth*)**  
> Proyek: **ITMS Endpoint Agent Daemon**  
> Bahasa Pemrograman: **Rust (Edition 2021)**  
> Target Platform: **Windows 10 / Windows 11 / Windows Server (x86_64)**  
> Mode Operasi: **Windows Background Service (`LocalSystem`) & Interactive CLI**  
> Integrasi Server: **ITMS-Pro Central Backend (Django REST API / Network IPAM Milestone 8)**  
> Dokumen Spesifikasi Asli: [`deployment/AGENT_SPEC.md`](file:///d:/webdev/itms-agents-daemon/deployment/AGENT_SPEC.md)

---

## 1. Latar Belakang & Visi Produk

### Kebutuhan Bisnis (Business & Operational Context)
Pada sistem monitoring jaringan **ITMS-Pro**:
1. **Limitasi Router-Level Monitoring:**  
   MikroTik Router API mencatat throughput bandwidth harian (RX/TX), peak rate, dan liveness ARP/Hotspot per IP. Namun router tidak dapat mencatat riwayat web per individu secara akurat karena DNS cache router bersifat global (*router-wide*), terenkripsi (DoH/DoT), atau tertutup saat pengguna menggunakan personal VPN / mode Incognito.
2. **Peran ITMS Endpoint Agent Daemon:**  
   Daemon ringan berbasis **Rust** yang berjalan di background laptop/PC kantor untuk memberikan telemetri aktivitas aplikasi dan domain web secara 100% presisi (*ground truth*), mengetahui *Process ID* dan software pemanggil domain, serta tetap dapat merekam saat laptop dibawa dinas luar/WFH melalui *local offline buffer*.

### Target Kinerja & Kepatuhan (*Non-Functional Requirements*)
* **Resource Footprint:** Konsumsi RAM **< 15 MB**, beban CPU idle **< 0.1%**, ukuran binary single `.exe` **< 10 MB**.
* **Non-Intrusive & Compliance:**  
  * Tidak menggunakan injeksi memori (*no DLL injection*).
  * Tidak merekam pengetikan tombol (*no keylogger*).
  * Tidak mengambil tangkapan layar (*no screen capture*).
  * Tidak memerlukan driver packet capture pihak ketiga (zero-packet inspection / tanpa WinPcap/Npcap).
  * 100% patuh terhadap Microsoft Windows Defender dan UU Pelindungan Data Pribadi (UU PDP).
* **Offline Resilient:** Telemetri disimpan dalam local FIFO queue (SQLite) saat koneksi terputus dan otomatis di-drain saat tersambung kembali.

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
|   |  DNS Sniffer Engine |   | Active Window & Duration |   | Hardware Identity |   |
|   | (ETW Event Consumer)|   | (Foreground Window API)  |   | (UUID, MAC, IP)   |   |
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
|                           | %PROGRAMDATA%\ITMS\queue.db  |                         |
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

## 3. Rincian Modul Teknis

### Modul 1: Hardware & System Identifier (`hardware.rs`)
* **Hardware UUID:** Mengambil SMBIOS/System UUID unik melalui WMI atau Win32 API (`Win32_ComputerSystemProduct.UUID`).
* **Network Identity:**
  * Hostname sistem via Win32 `GetComputerNameW`.
  * Primary MAC Address (adapter jaringan yang aktif).
  * Local IP Address yang digunakan untuk koneksi rute default.
* **System Metrics:**
  * Pengambilan metrik CPU usage (persentase total), RAM used (MB), dan uptime sistem (detik) menggunakan crate `sysinfo`.

### Modul 2: Active Window & Screen Time Tracker (`window_tracker.rs`)
* **Sampling Loop:** Polling handle foreground window setiap 3–5 detik.
* **Win32 API:**
  * `GetForegroundWindow()` untuk memperoleh `HWND`.
  * `GetWindowTextW()` untuk membaca judul jendela (*window title*).
  * `GetWindowThreadProcessId()` untuk mengetahui PID aplikasi terkait.
* **Idle State Detection:**
  * Memeriksa `GetLastInputInfo()` untuk mengetahui durasi tidak ada aktivitas mouse/keyboard.
  * Jika idle > 300 detik (5 menit), status timer di-pause agar tidak mencatat durasi palsu saat pengguna meninggalkan meja kerja.
* **Domain/App Parser:**
  * Ekstraksi judul window umum browser (Chrome, Edge, Firefox, Brave) untuk mengenali domain situs yang sedang aktif.

### Modul 3: DNS Query Sniffer Engine (`dns_etw.rs`)
* **Event Tracing for Windows (ETW):**
  * Provider: `Microsoft-Windows-DNS-Client` (`{1C950233-BE26-4226-90F9-C1E47214E7E8}`).
  * Event ID `3008`: DNS Query Completed.
  * Atribut: `QueryName` (FQDN), `QueryType`, `QueryStatus`, `PID`.
* **Keunggulan:**
  * Tidak terpengaruh mode Incognito / Private Browsing.
  * Langsung mengaitkan query DNS dengan Process ID (`PID`) dan binary executable peminta.
  * Berjalan murni di user space tanpa memerlukan kernel packet driver tambahan.

### Modul 4: Local Storage & Offline Buffer (`storage.rs`)
* **Lokasi Database:** `%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db`.
* **Engine:** SQLite (`rusqlite` bundled).
* **Karakteristik:**
  * Skema tabel queue untuk aktivitas aplikasi dan event telemetri.
  * Batas ukuran maksimum 50 MB dengan kebijakan FIFO rolling (hapus rekaman tertua jika batas tercapai).
  * Transaksi ACID aman terhadap crash atau shutdown mendadak.

### Modul 5: HTTP Batch Flusher & Ingestion Client (`flusher.rs`)
* **Transport:** HTTPS via `reqwest` (TLS menggunakan `rustls`).
* **Endpoint Tujuan:** `POST https://<server-domain>/network/api/telemetry/push/`.
* **Headers:**
  * `Content-Type: application/json`
  * `X-ITMS-Agent-Key: <agent_api_key>`
  * `X-Machine-UUID: <uuid>`
* **Mekanisme Drain:**
  * Interval drain berkala (default: 60 detik).
  * Mengambil hingga 100 entri per batch pengiriman.
  * Menghapus entri yang terkonfirmasi sukses (HTTP 200/201) dari queue database SQLite.

### Modul 6: Windows Service Manager & CLI Runner (`service.rs`)
* **Crate:** `windows-service`.
* **Konfigurasi Service:**
  * Nama Service: `ITMSAgentService`
  * Display Name: `ITMS Endpoint Telemetry Daemon`
  * Akun: `NT AUTHORITY\LocalSystem`
  * Startup Type: `Automatic`
* **Subcommand CLI:**
  * `itms-agent.exe install` : Daftarkan service ke Windows Service Control Manager (SCM).
  * `itms-agent.exe uninstall` : Hapus service dari SCM.
  * `itms-agent.exe start` : Mulai service.
  * `itms-agent.exe stop` : Hentikan service.
  * `itms-agent.exe run` : Jalankan daemon di foreground console (mode debug/interaktif).

---

## 4. Struktur Direktori Kode (Rust Architecture)

```
itms-agents-daemon/
├── .agents/                    # Custom agent rules & workflows
├── deployment/                 # Rencana deployment, spesifikasi, dan checklist
│   ├── AGENT_SPEC.md           # Spesifikasi teknis asli
│   ├── plan.md                 # Cetak biru arsitektur dan panduan pengerjaan
│   └── checklist.md            # Tracker progress dan milestone
├── config/
│   └── agent.toml.example      # Template konfigurasi lokal (URL server, token, polling interval)
├── src/
│   ├── main.rs                 # Entry point, argument parsing (CLI), service entry
│   ├── config.rs               # Struktur konfigurasi agent (TOML parser)
│   ├── hardware.rs             # Hardware UUID, MAC, IP, System Metrics collector
│   ├── window_tracker.rs       # Active window title, process ID & user idle tracker
│   ├── dns_etw.rs              # ETW consumer provider Microsoft-Windows-DNS-Client
│   ├── classifier.rs           # Normalisasi FQDN domain & kategorisasi aplikasi
│   ├── storage.rs              # SQLite buffer repository & FIFO queue manager
│   ├── flusher.rs              # HTTP batch exporter ke ITMS-Pro backend
│   └── service.rs              # Windows Service Control Manager wrapper
├── Cargo.toml                  # Deklarasi dependencies & build flags
└── Cargo.lock
```

---

## 5. Kontrak Payload JSON

```json
{
  "agent_version": "1.0.0",
  "machine_uuid": "4C4C4544-004B-4D10-8043-B2C04F323533",
  "hostname": "LAPTOP-OFFICE-01",
  "mac_address": "D0:37:45:3E:E9:E8",
  "ip_address": "192.168.0.67",
  "timestamp": "2026-10-26T09:00:00Z",
  "metrics": {
    "cpu_usage_pct": 8.4,
    "memory_used_mb": 5120,
    "uptime_seconds": 94200
  },
  "activities": [
    {
      "domain": "erp.pmgcloud.my.id",
      "app_name": "Internal SAP / ERP",
      "category": "work_productivity",
      "duration_seconds": 1800,
      "total_bytes": 3400000,
      "source_type": "agent"
    },
    {
      "domain": "chatgpt.com",
      "app_name": "ChatGPT AI Assistant",
      "category": "work_productivity",
      "duration_seconds": 900,
      "total_bytes": 820000,
      "source_type": "agent"
    },
    {
      "domain": "youtube.com",
      "app_name": "YouTube",
      "category": "entertainment",
      "duration_seconds": 300,
      "total_bytes": 12500000,
      "source_type": "agent"
    }
  ]
}
```

---

## 6. Integrasi dengan Backend ITMS-Pro

Endpoint backend Django:
`POST /network/api/telemetry/push/`
1. Memvalidasi header `X-ITMS-Agent-Key` terhadap model konfigurasi ITMS.
2. Memetakan `ip_address` dan `mac_address` ke entitas `IPAddress` di modul IPAM.
3. Menyimpan rincian aktivitas ke tabel `IPAppActivityLog` dengan `source_type='agent'` (sehingga muncul badge *Verified by Agent* di dashboard IPAM).
4. Memperbarui status online/last seen laptop/endpoint secara otomatis.
