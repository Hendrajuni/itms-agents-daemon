use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityRecord {
    pub id: Option<i64>,
    pub domain: String,
    pub app_name: String,
    pub category: String,
    pub duration_seconds: u32,
    pub total_bytes: u64,
    pub source_type: String,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLogRecord {
    pub id: Option<i64>,
    pub timestamp: String,
    pub hostname: String,
    pub host_ip: String,
    pub machine_uuid: String,
    pub event_id: u32,
    pub channel: String,
    pub severity: String,
    pub provider: String,
    pub message: String,
    pub details_json: String,
    pub created_at: String,
}

pub struct TelemetryStorage {
    db_path: PathBuf,
    max_size_bytes: u64,
}

impl TelemetryStorage {
    pub fn new<P: AsRef<Path>>(db_path: P, max_size_mb: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let path = db_path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let storage = Self {
            db_path: path,
            max_size_bytes: max_size_mb * 1024 * 1024,
        };

        storage.init_tables()?;
        Ok(storage)
    }

    fn get_connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA temp_store = MEMORY;
             PRAGMA busy_timeout = 5000;"
        )?;
        Ok(conn)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.get_connection()?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS activity_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                app_name TEXT NOT NULL,
                category TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                source_type TEXT NOT NULL DEFAULT 'agent',
                recorded_at TEXT NOT NULL,
                synced INTEGER NOT NULL DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_activity_synced ON activity_queue (synced, id);",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS event_log_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                host_ip TEXT NOT NULL,
                machine_uuid TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                channel TEXT NOT NULL,
                severity TEXT NOT NULL,
                provider TEXT NOT NULL,
                message TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                synced INTEGER NOT NULL DEFAULT 0
            );",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_event_log_synced ON event_log_queue (synced, id);",
            [],
        )?;

        Ok(())
    }

    pub fn insert_activity(&self, record: &ActivityRecord) -> Result<i64> {
        self.enforce_fifo_capacity()?;

        let conn = self.get_connection()?;
        conn.execute(
            "INSERT INTO activity_queue (domain, app_name, category, duration_seconds, total_bytes, source_type, recorded_at, synced)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0);",
            params![
                record.domain,
                record.app_name,
                record.category,
                record.duration_seconds,
                record.total_bytes,
                record.source_type,
                record.recorded_at,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Akumulasi durasi dan total byte secara atomik jika domain yang sama sudah ada di antrean
    pub fn upsert_or_accumulate_activity(&self, record: &ActivityRecord) -> Result<()> {
        self.enforce_fifo_capacity()?;

        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, duration_seconds, total_bytes FROM activity_queue WHERE domain = ?1 AND synced = 0 ORDER BY id DESC LIMIT 1;"
        )?;

        let existing: Option<(i64, u32, u64)> = stmt.query_row(params![record.domain], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        }).ok();

        if let Some((id, existing_dur, existing_bytes)) = existing {
            let new_dur = existing_dur.saturating_add(record.duration_seconds);
            let new_bytes = existing_bytes.saturating_add(record.total_bytes);
            conn.execute(
                "UPDATE activity_queue SET duration_seconds = ?1, total_bytes = ?2 WHERE id = ?3;",
                params![new_dur, new_bytes, id],
            )?;
        } else {
            conn.execute(
                "INSERT INTO activity_queue (domain, app_name, category, duration_seconds, total_bytes, source_type, recorded_at, synced)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0);",
                params![
                    record.domain,
                    record.app_name,
                    record.category,
                    record.duration_seconds,
                    record.total_bytes,
                    record.source_type,
                    record.recorded_at,
                ],
            )?;
        }

        Ok(())
    }

    pub fn get_unsynced_batch(&self, limit: usize) -> Result<Vec<ActivityRecord>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, domain, app_name, category, duration_seconds, total_bytes, source_type, recorded_at
             FROM activity_queue
             WHERE synced = 0
             ORDER BY id ASC
             LIMIT ?1;",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ActivityRecord {
                id: Some(row.get(0)?),
                domain: row.get(1)?,
                app_name: row.get(2)?,
                category: row.get(3)?,
                duration_seconds: row.get(4)?,
                total_bytes: row.get(5)?,
                source_type: row.get(6)?,
                recorded_at: row.get(7)?,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    pub fn delete_or_mark_synced(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        let mut conn = self.get_connection()?;
        let tx = conn.transaction()?;

        // Hapus langsung baris yang sudah terkirim agar ukuran database tetap hemat
        for chunk in ids.chunks(50) {
            let id_list: Vec<String> = chunk.iter().map(|id| id.to_string()).collect();
            let sql = format!("DELETE FROM activity_queue WHERE id IN ({});", id_list.join(","));
            tx.execute(&sql, [])?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn insert_event_log(&self, record: &EventLogRecord) -> Result<i64> {
        self.enforce_eventlog_fifo_capacity()?;

        let conn = self.get_connection()?;
        conn.execute(
            "INSERT INTO event_log_queue (
                timestamp, hostname, host_ip, machine_uuid, event_id, channel,
                severity, provider, message, details_json, created_at, synced
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0);",
            params![
                record.timestamp,
                record.hostname,
                record.host_ip,
                record.machine_uuid,
                record.event_id,
                record.channel,
                record.severity,
                record.provider,
                record.message,
                record.details_json,
                record.created_at,
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    pub fn get_unsynced_event_logs(&self, limit: usize) -> Result<Vec<EventLogRecord>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, hostname, host_ip, machine_uuid, event_id, channel,
                    severity, provider, message, details_json, created_at
             FROM event_log_queue
             WHERE synced = 0
             ORDER BY id ASC
             LIMIT ?1;",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(EventLogRecord {
                id: Some(row.get(0)?),
                timestamp: row.get(1)?,
                hostname: row.get(2)?,
                host_ip: row.get(3)?,
                machine_uuid: row.get(4)?,
                event_id: row.get(5)?,
                channel: row.get(6)?,
                severity: row.get(7)?,
                provider: row.get(8)?,
                message: row.get(9)?,
                details_json: row.get(10)?,
                created_at: row.get(11)?,
            })
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    pub fn delete_or_mark_synced_event_logs(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        let mut conn = self.get_connection()?;
        let tx = conn.transaction()?;

        for chunk in ids.chunks(50) {
            let id_list: Vec<String> = chunk.iter().map(|id| id.to_string()).collect();
            let sql = format!("DELETE FROM event_log_queue WHERE id IN ({});", id_list.join(","));
            tx.execute(&sql, [])?;
        }

        tx.commit()?;
        Ok(())
    }

    fn enforce_eventlog_fifo_capacity(&self) -> Result<()> {
        let max_eventlog_bytes = 20 * 1024 * 1024; // 20 MB khusus kuota event log buffer
        if let Ok(meta) = fs::metadata(&self.db_path) {
            if meta.len() > max_eventlog_bytes {
                warn!("Ukuran database melampaui batas kuota 20 MB. Menghapus 200 event log terlama.");
                let conn = self.get_connection()?;
                conn.execute(
                    "DELETE FROM event_log_queue WHERE id IN (SELECT id FROM event_log_queue ORDER BY id ASC LIMIT 200);",
                    [],
                )?;
            }
        }
        Ok(())
    }

    fn enforce_fifo_capacity(&self) -> Result<()> {
        if let Ok(meta) = fs::metadata(&self.db_path) {
            if meta.len() > self.max_size_bytes {
                warn!("Ukuran database melampaui batas maksimum ({} MB). Menghapus 500 rekaman terlama.", self.max_size_bytes / (1024 * 1024));
                let conn = self.get_connection()?;
                conn.execute(
                    "DELETE FROM activity_queue WHERE id IN (SELECT id FROM activity_queue ORDER BY id ASC LIMIT 500);",
                    [],
                )?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_storage_insert_and_get_batch() {
        let temp_dir = std::env::temp_dir().join(format!("itms_test_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let db_file = temp_dir.join("test_queue.db");

        let storage = TelemetryStorage::new(&db_file, 50).expect("Inisialisasi test storage gagal");

        let record = ActivityRecord {
            id: None,
            domain: "erp.pmgcloud.my.id".to_string(),
            app_name: "Internal SAP / ERP".to_string(),
            category: "work_productivity".to_string(),
            duration_seconds: 120,
            total_bytes: 45000,
            source_type: "agent".to_string(),
            recorded_at: Utc::now().to_rfc3339(),
        };

        let row_id = storage.insert_activity(&record).expect("Insert gagal");
        assert!(row_id > 0);

        let batch = storage.get_unsynced_batch(10).expect("Get batch gagal");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].domain, "erp.pmgcloud.my.id");
        assert_eq!(batch[0].duration_seconds, 120);

        // Test delete / mark synced
        let ids = vec![batch[0].id.unwrap()];
        storage.delete_or_mark_synced(&ids).expect("Delete failed");

        let batch_after = storage.get_unsynced_batch(10).expect("Get batch after failed");
        assert_eq!(batch_after.len(), 0);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_event_log_storage_insert_and_get_batch() {
        let temp_dir = std::env::temp_dir().join(format!("itms_event_test_{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let db_file = temp_dir.join("test_event_queue.db");

        let storage = TelemetryStorage::new(&db_file, 50).expect("Inisialisasi test storage gagal");

        let event = EventLogRecord {
            id: None,
            timestamp: "2026-10-29T13:30:00Z".to_string(),
            hostname: "SRV-DC01".to_string(),
            host_ip: "192.168.1.15".to_string(),
            machine_uuid: "4C4C4544-004B-4D10-8043-B2C04F323533".to_string(),
            event_id: 4625,
            channel: "Security".to_string(),
            severity: "WARNING".to_string(),
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            message: "An account failed to log on. TargetUser: Administrator, Workstation: WS-01, SourceIP: 192.168.1.88, Status: 0xC000006D".to_string(),
            details_json: r#"{"target_user":"Administrator","workstation":"WS-01","source_ip":"192.168.1.88","status_code":"0xC000006D"}"#.to_string(),
            created_at: Utc::now().to_rfc3339(),
        };

        let row_id = storage.insert_event_log(&event).expect("Insert event log gagal");
        assert!(row_id > 0);

        let batch = storage.get_unsynced_event_logs(10).expect("Get unsynced event logs gagal");
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].event_id, 4625);
        assert_eq!(batch[0].hostname, "SRV-DC01");
        assert_eq!(batch[0].severity, "WARNING");

        let ids = vec![batch[0].id.unwrap()];
        storage.delete_or_mark_synced_event_logs(&ids).expect("Delete event logs failed");

        let batch_after = storage.get_unsynced_event_logs(10).expect("Get unsynced after delete failed");
        assert_eq!(batch_after.len(), 0);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
