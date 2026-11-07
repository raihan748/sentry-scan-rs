use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "sentry-scan",
    author = "Developer <developer@telkom.sch.id>",
    version = "0.1.0",
    about = "High-concurrency async TCP CIDR port scanner & service banner reconnaissance CLI"
)]
pub struct CliArgs {
    /// Target IP, CIDR subnet, or IP range (e.g., 192.168.1.1, 10.0.0.0/24, 192.168.1.1-50)
    #[arg(short = 't', long = "target")]
    pub target: String,

    /// Comma-separated ports or port ranges to scan (e.g., 80,443,8000-8080)
    #[arg(short = 'p', long = "ports")]
    pub ports: Option<String>,

    /// Built-in port preset (top100, telecom, web)
    #[arg(long = "preset", value_parser = ["top100", "telecom", "web"])]
    pub preset: Option<String>,

    /// Maximum concurrent TCP connection probes (1 - 10000)
    #[arg(short = 'c', long = "concurrency", default_value_t = 500)]
    pub concurrency: usize,

    /// Connection probe timeout in milliseconds
    #[arg(long = "timeout", default_value_t = 1500)]
    pub timeout_ms: u64,

    /// Perform active protocol banner grabbing on open ports (HTTP, SSH, FTP, Telnet, Redis)
    #[arg(short = 'b', long = "banner", default_value_t = false)]
    pub banner: bool,

    /// Output results in structured JSON format
    #[arg(long = "json", default_value_t = false)]
    pub json: bool,

    /// Output results in OASIS SARIF v2.1.0 security format for CI/CD integration
    #[arg(long = "sarif", default_value_t = false)]
    pub sarif: bool,

    /// Save output report to specified file path
    #[arg(short = 'o', long = "output")]
    pub output_file: Option<String>,

    /// Include network and broadcast addresses in IPv4 CIDR blocks
    #[arg(long = "all-hosts", default_value_t = false)]
    pub all_hosts: bool,
}
