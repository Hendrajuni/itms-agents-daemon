use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::debug;

/// Entri pemetaan IP ke Domain hasil resolusi DNS
#[derive(Debug, Clone)]
pub struct DnsResolutionEntry {
    pub domain: String,
    pub app_name: String,
    pub category: String,
    pub resolved_at: Instant,
    pub ttl_secs: u32,
}

impl DnsResolutionEntry {
    pub fn is_expired(&self) -> bool {
        self.resolved_at.elapsed() >= Duration::from_secs(self.ttl_secs as u64)
    }
}

/// Cache In-Memory resolusi DNS (Thread-Safe untuk concurrent high-throughput lookup)
#[derive(Clone)]
pub struct DnsResolutionCache {
    entries: Arc<RwLock<HashMap<IpAddr, DnsResolutionEntry>>>,
    max_entries: usize,
    default_ttl: Duration,
}

impl DnsResolutionCache {
    pub fn new(max_entries: usize, default_ttl_secs: u32) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::with_capacity(1024))),
            max_entries,
            default_ttl: Duration::from_secs(default_ttl_secs as u64),
        }
    }

    /// Memasukkan pemetaan IP -> Domain ke dalam cache
    pub fn insert(
        &self,
        ip: IpAddr,
        domain: String,
        app_name: String,
        category: String,
        ttl_secs: Option<u32>,
    ) {
        if is_internal_or_noise_ip(&ip) {
            return;
        }

        let ttl = ttl_secs
            .map(|t| Duration::from_secs(t as u64))
            .unwrap_or(self.default_ttl);

        let entry = DnsResolutionEntry {
            domain,
            app_name,
            category,
            resolved_at: Instant::now(),
            ttl_secs: ttl.as_secs() as u32,
        };

        if let Ok(mut lock) = self.entries.write() {
            // Jika kapasitas melampaui batas, lakukan pembersihan darurat
            if lock.len() >= self.max_entries {
                lock.retain(|_, v| !v.is_expired());
                // Jika masih penuh setelah retain expired, hapus sebagian entri tertua
                if lock.len() >= self.max_entries {
                    let to_remove: Vec<IpAddr> = lock.keys().take(self.max_entries / 5).cloned().collect();
                    for k in to_remove {
                        lock.remove(&k);
                    }
                }
            }
            lock.insert(ip, entry);
        }
    }

    /// Mencari domain yang diasosiasikan dengan IP tujuan
    pub fn lookup(&self, ip: &IpAddr) -> Option<DnsResolutionEntry> {
        if let Ok(lock) = self.entries.read() {
            if let Some(entry) = lock.get(ip) {
                if !entry.is_expired() {
                    return Some(entry.clone());
                }
            }
        }
        None
    }

    /// Membersihkan entri yang telah kedaluwarsa (TTL habis)
    pub fn prune_expired(&self) {
        if let Ok(mut lock) = self.entries.write() {
            let before = lock.len();
            lock.retain(|_, v| !v.is_expired());
            let removed = before - lock.len();
            if removed > 0 {
                debug!("DnsResolutionCache: dibersihkan {} entri kedaluwarsa.", removed);
            }
        }
    }

    /// Jumlah entri aktif di dalam cache
    pub fn len(&self) -> usize {
        self.entries.read().map(|l| l.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Delta byte transfer yang dikumpulkan dalam satu siklus flush
#[derive(Debug, Clone)]
pub struct DomainTrafficDelta {
    pub domain: String,
    pub app_name: String,
    pub category: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub total_bytes: u64,
}

struct AccumulatorEntry {
    domain: String,
    app_name: String,
    category: String,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

/// Akumulator byte traffic in-memory (Thread-Safe untuk concurrent TCPIP packet events)
#[derive(Clone)]
pub struct TrafficAggregator {
    buckets: Arc<RwLock<HashMap<String, Arc<AccumulatorEntry>>>>,
}

impl TrafficAggregator {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::with_capacity(512))),
        }
    }

    /// Menambahkan byte network untuk domain atau proses tertentu
    pub fn record_traffic(
        &self,
        domain: &str,
        app_name: &str,
        category: &str,
        bytes_sent: u64,
        bytes_recv: u64,
    ) {
        if domain.is_empty() || (bytes_sent == 0 && bytes_recv == 0) {
            return;
        }

        let entry = {
            let read_lock = self.buckets.read().unwrap();
            if let Some(existing) = read_lock.get(domain) {
                existing.clone()
            } else {
                drop(read_lock);
                let mut write_lock = self.buckets.write().unwrap();
                write_lock
                    .entry(domain.to_string())
                    .or_insert_with(|| {
                        Arc::new(AccumulatorEntry {
                            domain: domain.to_string(),
                            app_name: app_name.to_string(),
                            category: category.to_string(),
                            bytes_sent: AtomicU64::new(0),
                            bytes_received: AtomicU64::new(0),
                        })
                    })
                    .clone()
            }
        };

        if bytes_sent > 0 {
            entry.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
        }
        if bytes_recv > 0 {
            entry.bytes_received.fetch_add(bytes_recv, Ordering::Relaxed);
        }
    }

    /// Menguras (drain) akumulasi delta byte yang tercatat sejak pemanggilan terakhir.
    /// Mengosongkan akumulator tanpa menghapus bucket agar alokasi memory tetap efisien.
    pub fn drain_deltas(&self) -> Vec<DomainTrafficDelta> {
        let mut deltas = Vec::new();
        if let Ok(lock) = self.buckets.read() {
            for entry in lock.values() {
                let sent = entry.bytes_sent.swap(0, Ordering::Relaxed);
                let recv = entry.bytes_received.swap(0, Ordering::Relaxed);
                let total = sent.saturating_add(recv);

                if total > 0 {
                    deltas.push(DomainTrafficDelta {
                        domain: entry.domain.clone(),
                        app_name: entry.app_name.clone(),
                        category: entry.category.clone(),
                        bytes_sent: sent,
                        bytes_received: recv,
                        total_bytes: total,
                    });
                }
            }
        }
        deltas
    }

    /// Mengambil dan menguras total byte untuk domain tertentu (digunakan oleh WindowTracker saat flush)
    pub fn drain_bytes_for_domain(&self, domain: &str) -> u64 {
        if let Ok(lock) = self.buckets.read() {
            if let Some(entry) = lock.get(domain) {
                let sent = entry.bytes_sent.swap(0, Ordering::Relaxed);
                let recv = entry.bytes_received.swap(0, Ordering::Relaxed);
                return sent.saturating_add(recv);
            }
        }
        0
    }
}

/// Memeriksa apakah IP merupakan rute internal, loopback, multicast, atau noise
pub fn is_internal_or_noise_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()                           // 127.0.0.0/8
            || ipv4.is_broadcast()                       // 255.255.255.255
            || ipv4.is_multicast()                       // 224.0.0.0/4
            || ipv4.is_link_local()                      // 169.254.0.0/16
            || ipv4.is_unspecified()                     // 0.0.0.0
            || is_private_subnet_broadcast(ipv4)
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()                           // ::1
            || ipv6.is_multicast()                       // ff00::/8
            || ipv6.is_unspecified()                     // ::
        }
    }
}

fn is_private_subnet_broadcast(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 255 broadcast di akhir subnet umum
    octets[3] == 255
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_cache_insert_and_lookup() {
        let cache = DnsResolutionCache::new(100, 60);
        let ip: IpAddr = "142.250.190.46".parse().unwrap();

        cache.insert(
            ip,
            "youtube.com".to_string(),
            "YouTube".to_string(),
            "streaming".to_string(),
            Some(60),
        );

        let entry = cache.lookup(&ip).expect("Lookup harus berhasil");
        assert_eq!(entry.domain, "youtube.com");
        assert_eq!(entry.app_name, "YouTube");
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_traffic_aggregator_record_and_drain() {
        let agg = TrafficAggregator::new();

        agg.record_traffic("youtube.com", "YouTube", "streaming", 5000, 150000);
        agg.record_traffic("youtube.com", "YouTube", "streaming", 1000, 50000);
        agg.record_traffic("chatgpt.com", "ChatGPT", "work_productivity", 200, 800);

        let deltas = agg.drain_deltas();
        assert_eq!(deltas.len(), 2);

        let yt = deltas.iter().find(|d| d.domain == "youtube.com").unwrap();
        assert_eq!(yt.bytes_sent, 6000);
        assert_eq!(yt.bytes_received, 200000);
        assert_eq!(yt.total_bytes, 206000);

        // Setelah drain, nilai ter-reset ke 0
        let drained_again = agg.drain_deltas();
        assert_eq!(drained_again.len(), 0);
    }

    #[test]
    fn test_noise_ip_filter() {
        assert!(is_internal_or_noise_ip(&"127.0.0.1".parse().unwrap()));
        assert!(is_internal_or_noise_ip(&"::1".parse().unwrap()));
        assert!(is_internal_or_noise_ip(&"224.0.0.1".parse().unwrap()));
        assert!(is_internal_or_noise_ip(&"169.254.1.1".parse().unwrap()));

        // Public internet IPs must NOT be filtered
        assert!(!is_internal_or_noise_ip(&"142.250.190.46".parse().unwrap())); // YouTube / Google
        assert!(!is_internal_or_noise_ip(&"104.244.42.1".parse().unwrap()));   // Twitter
    }
}
