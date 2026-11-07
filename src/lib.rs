//! SentryScan: High-concurrency async TCP CIDR port scanner & service banner reconnaissance CLI.

pub mod cidr;
pub mod classification;
pub mod cli;
pub mod error;
pub mod output;
pub mod scanner;

pub use cidr::{expand_ipnet, parse_ports, parse_targets};
pub use classification::{evaluate_risk, RiskAssessment, RiskLevel, ServiceInfo};
pub use error::SentryScanError;
pub use output::{render_json, render_sarif, render_table};
pub use scanner::{run_scan, ScanConfig, ScanReport, ScanResult};
