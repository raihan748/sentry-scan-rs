use sentry_scan::cidr::{parse_ports, parse_targets};
use sentry_scan::scanner::{run_scan, ScanConfig};

#[tokio::main]
async fn main() {
    println!("SentryScan async TCP port scanner engine initialized.");
    let targets = parse_targets("127.0.0.1", true).expect("valid target");
    let ports = parse_ports(Some("80,443"), None).expect("valid ports");
    let report = run_scan(&targets, &ports, ScanConfig::default()).await;
    println!("Scanned {} targets in {:.2}s", report.scanned_count, report.duration_secs);
}
