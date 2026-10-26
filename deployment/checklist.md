# ITMS Endpoint Agent Daemon (Rust) - Checklist & Milestone Tracker

> **Modul:** `deployment/`  
> **Target Eksekusi:** Standalone Windows Service (`ITMSAgentService`) & CLI Binary (`itms-agent.exe`)  
> **Dokumen Arsitektur Lengkap:** [`deployment/plan.md`](file:///d:/webdev/itms-agents-daemon/deployment/plan.md)  
> **Spesifikasi Teknis:** [`deployment/AGENT_SPEC.md`](file:///d:/webdev/itms-agents-daemon/deployment/AGENT_SPEC.md)  
> **Terakhir Diperbarui:** 26 Oktober 2026  
> **Status Operasional:** ⏳ **PERSIAPAN AWAL & MILESTONE 0 (Rust Setup & Project Init)**  

---

## 📊 Ringkasan Status Roadmap

| No | Milestone / Item Pekerjaan | Target Mulai | Target Selesai | Status | Verifikasi & Bukti |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **0** | **Inisialisasi Proyek & Toolchain Rust** | 2026-10-26 | 2026-10-26 | ⏳ **SEDANG BERJALAN** | Verifikasi toolchain `rustc`/`cargo`, `Cargo.toml`, dan struktur source directory. |
| **1** | **Hardware & Endpoint Identifier** | 2026-10-26 | 2026-10-27 | ⏹️ **MENUNGGU** | Ekstraksi SMBIOS UUID, Hostname, MAC Address, IP lokal, dan metrik sistem (CPU, RAM). |
| **2** | **Active Window & Screen Time Tracker** | 2026-10-27 | 2026-10-28 | ⏹️ **MENUNGGU** | Polling `GetForegroundWindow`, ekstraksi judul window browser, pendeteksi idle `GetLastInputInfo`. |
| **3** | **Windows DNS ETW Sniffer Engine** | 2026-10-28 | 2026-10-29 | ⏹️ **MENUNGGU** | Subscribe ETW `Microsoft-Windows-DNS-Client` Event 3008, tangkap FQDN query & PID. |
| **4** | **SQLite Offline Store & FIFO Buffer** | 2026-10-29 | 2026-10-30 | ⏹️ **MENUNGGU** | Skema SQLite lokal `%PROGRAMDATA%\ITMS\buffer\`, rolling FIFO maks 50 MB. |
| **5** | **HTTP Batch Flusher ke ITMS Backend** | 2026-10-30 | 2026-10-31 | ⏹️ **MENUNGGU** | POST batch ke `/network/api/telemetry/push/` dengan header `X-ITMS-Agent-Key` & `X-Machine-UUID`. |
| **6** | **Windows Service Wrapper & CLI Runner** | 2026-10-31 | 2026-11-01 | ⏹️ **MENUNGGU** | Handler `windows-service`, subcommands `install`, `uninstall`, `start`, `stop`, `run`. |
| **7** | **End-to-End Test, Defender & Packaging** | 2026-11-01 | 2026-11-02 | ⏹️ **MENUNGGU** | Verifikasi footprint (<15MB RAM, <0.1% CPU), uji Defender/SmartScreen, build release single binary. |

---

## 📝 Rincian Item Pengerjaan (Milestone Details)

### Milestone 0: Inisialisasi Proyek & Toolchain Rust
- [ ] Verifikasi ketersediaan Rust (`rustc` & `cargo`) pada environment host Windows.
- [ ] Buat file manifest [`Cargo.toml`](file:///d:/webdev/itms-agents-daemon/Cargo.toml) dengan crate dependencies resmi:
  - `tokio`, `reqwest`, `serde`, `serde_json`
  - `windows`, `windows-service`
  - `rusqlite`, `sysinfo`, `mac_address`, `chrono`, `tracing`, `tracing-subscriber`
- [ ] Siapkan struktur direktori modul (`src/main.rs`, `src/config.rs`, `src/hardware.rs`, dll).
- [ ] Siapkan template file konfigurasi default: `config/agent.toml.example`.

### Milestone 1: Hardware & Endpoint Identifier (`src/hardware.rs`)
- [ ] Ekstraksi Machine UUID unik melalui SMBIOS / WMI (`Win32_ComputerSystemProduct.UUID`).
- [ ] Ekstraksi Hostname mesin (`GetComputerNameW`).
- [ ] Ekstraksi Primary MAC Address aktif dan Local IP Address untuk rute default.
- [ ] Pengambilan metrik CPU usage (persen), memori terpakai (MB), dan uptime sistem (detik).
- [ ] Unit test fungsi identitas mesin.

### Milestone 2: Active Window & Screen Time Tracker (`src/window_tracker.rs`)
- [ ] Polling foreground window handle setiap 3–5 detik via `GetForegroundWindow`.
- [ ] Pembacaan teks judul window aktif via `GetWindowTextW`.
- [ ] Pengambilan Process ID (`PID`) aplikasi aktif via `GetWindowThreadProcessId`.
- [ ] Deteksi user idle state dengan `GetLastInputInfo` (pause timer jika idle > 5 menit).
- [ ] Parser judul window browser (Chrome, Edge, Firefox, Brave) untuk ekstraksi domain/FQDN.

### Milestone 3: Windows DNS ETW Sniffer Engine (`src/dns_etw.rs`)
- [ ] Buka session ETW ke provider `Microsoft-Windows-DNS-Client` (`{1C950233-BE26-4226-90F9-C1E47214E7E8}`).
- [ ] Tangkap Event ID 3008 (DNS Query Completed).
- [ ] Parse field `QueryName` (FQDN), `QueryType`, `QueryStatus`, dan `PID`.
- [ ] Normalisasi FQDN (strip trailing dot, lowercase, buang noise domain internal/CDNs).

### Milestone 4: SQLite Offline Store & FIFO Buffer (`src/storage.rs`)
- [ ] Inisialisasi file database pada path `%PROGRAMDATA%\ITMS\buffer\telemetry_queue.db`.
- [ ] Migrasi tabel `activity_queue` dan `metric_queue`.
- [ ] Fitur insert batch aktivitas dari sniffer & window tracker.
- [ ] Proteksi ukuran file maksimum (50 MB) dengan eliminasi record tertua (FIFO).

### Milestone 5: HTTP Batch Flusher ke ITMS Backend (`src/flusher.rs`)
- [ ] Pembuatan payload JSON sesuai kontrak schema `POST /network/api/telemetry/push/`.
- [ ] Penyusunan HTTP request dengan header `X-ITMS-Agent-Key` dan `X-Machine-UUID`.
- [ ] Background worker loop (interval 60s):
  - Ambil hingga 100 entri dari SQLite queue.
  - Kirim HTTP POST ke backend.
  - Hapus entri dari database lokal jika respon HTTP 200/201 berhasil diterima.
  - Tunda pengiriman dengan exponential backoff jika koneksi offline/gagal.

### Milestone 6: Windows Service Wrapper & CLI Runner (`src/service.rs`)
- [ ] Integrasi crate `windows-service` untuk registrasi service dispatcher.
- [ ] Implementasi service event handler (Start, Stop, Interrogate).
- [ ] CLI argument parser:
  - `install`: Mendaftarkan service ke Service Control Manager (SCM) sebagai `ITMSAgentService`.
  - `uninstall`: Menghapus service dari SCM.
  - `start` / `stop`: Mengontrol service via SCM API.
  - `run`: Menjalankan daemon di konsol interaktif (mode debug/foreground).

### Milestone 7: End-to-End Test, Defender & Packaging
- [ ] Validasi konsumsi memori (< 15 MB) dan CPU idle (< 0.1%) saat berjalan penuh.
- [ ] Validasi kompatibilitas Windows Defender (tidak memicu false positive / alert heuristik).
- [ ] Pengujian skenario offline (putus koneksi Wi-Fi $\rightarrow$ sambung kembali $\rightarrow$ data tersinkronisasi utuh ke ITMS-Pro).
- [ ] Kompilasi binary release yang teroptimasi (`cargo build --release`).
