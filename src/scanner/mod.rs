pub mod connect;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Semaphore};

pub use connect::{probe_tcp_connect, probe_tcp_connect_stream};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanResult {
    pub host: IpAddr,
    pub port: u16,
    pub is_open: bool,
    pub rtt_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub total_targets: usize,
    pub scanned_count: usize,
    pub open_count: usize,
    pub closed_count: usize,
    pub duration_secs: f64,
    pub scan_rate: f64,
    pub results: Vec<ScanResult>,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub concurrency: usize,
    pub timeout: Duration,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            concurrency: 500,
            timeout: Duration::from_millis(1500),
        }
    }
}

/// Execute high-concurrency async TCP port scan bounded by Tokio Semaphore.
pub async fn run_scan(hosts: &[IpAddr], ports: &[u16], config: ScanConfig) -> ScanReport {
    let start_time = Instant::now();
    let total_targets = hosts.len() * ports.len();

    let concurrency = config.concurrency.clamp(1, 10000);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let (tx, mut rx) = mpsc::channel::<Option<ScanResult>>(concurrency * 2);

    for &host in hosts {
        for &port in ports {
            let sem = Arc::clone(&semaphore);
            let tx = tx.clone();
            let timeout_dur = config.timeout;

            tokio::spawn(async move {
                let _permit = match sem.acquire().await {
                    Ok(p) => p,
                    Err(_) => {
                        let _ = tx.send(None).await;
                        return;
                    }
                };

                let addr = SocketAddr::new(host, port);
                let result = if let Some(rtt) = probe_tcp_connect(addr, timeout_dur).await {
                    Some(ScanResult {
                        host,
                        port,
                        is_open: true,
                        rtt_ms: rtt.as_secs_f64() * 1000.0,
                    })
                } else {
                    None
                };

                let _ = tx.send(result).await;
            });
        }
    }

    drop(tx);

    let mut open_results = Vec::new();
    let mut scanned_count: usize = 0;

    while let Some(item) = rx.recv().await {
        scanned_count += 1;
        if let Some(res) = item {
            open_results.push(res);
        }
    }

    let duration_secs = start_time.elapsed().as_secs_f64();
    let scan_rate = if duration_secs > 0.0 {
        scanned_count as f64 / duration_secs
    } else {
        scanned_count as f64
    };

    open_results.sort_by(|a, b| a.host.cmp(&b.host).then_with(|| a.port.cmp(&b.port)));

    let open_count = open_results.len();
    let closed_count = scanned_count.saturating_sub(open_count);

    ScanReport {
        total_targets,
        scanned_count,
        open_count,
        closed_count,
        duration_secs,
        scan_rate,
        results: open_results,
    }
}
