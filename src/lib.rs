//! SentryScan: High-concurrency async TCP CIDR port scanner & service banner reconnaissance CLI.

pub mod cidr;
pub mod error;
pub mod scanner;

pub use cidr::{expand_ipnet, parse_ports, parse_targets};
pub use error::SentryScanError;
pub use scanner::{run_scan, ScanConfig, ScanReport, ScanResult};
