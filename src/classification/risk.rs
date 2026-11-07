use serde::{Deserialize, Serialize};
use crate::scanner::banner::BannerInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Critical => "CRITICAL",
            RiskLevel::High => "HIGH",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::Low => "LOW",
            RiskLevel::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub transport: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub summary: String,
    pub tags: Vec<String>,
    pub recommendation: String,
}

/// Analyze port and optional banner to produce service identification and risk rating.
pub fn evaluate_risk(port: u16, banner: Option<&BannerInfo>) -> (ServiceInfo, RiskAssessment) {
    match port {
        23 => (
            ServiceInfo {
                name: "telnet".to_string(),
                transport: "tcp".to_string(),
                description: "Plaintext Remote Terminal Protocol".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Critical,
                summary: "Unencrypted Telnet management protocol exposed".to_string(),
                tags: vec![
                    "plaintext".to_string(),
                    "credentials-in-flight".to_string(),
                    "remote-admin".to_string(),
                ],
                recommendation: "Disable Telnet immediately and migrate all management access to SSH (port 22).".to_string(),
            },
        ),
        8291 => (
            ServiceInfo {
                name: "mikrotik-winbox".to_string(),
                transport: "tcp".to_string(),
                description: "MikroTik RouterOS Winbox Administration".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "MikroTik WinBox management port exposed directly to network".to_string(),
                tags: vec![
                    "telecom-mgmt".to_string(),
                    "routeros".to_string(),
                    "winbox".to_string(),
                ],
                recommendation: "Restrict WinBox access via firewall filter rules to trusted management VLANs or VPN only.".to_string(),
            },
        ),
        6379 => {
            let is_unauth = banner.map_or(false, |b| b.raw_banner.contains("+PONG"));
            let level = if is_unauth {
                RiskLevel::Critical
            } else {
                RiskLevel::High
            };
            (
                ServiceInfo {
                    name: "redis".to_string(),
                    transport: "tcp".to_string(),
                    description: "Redis In-Memory Key-Value Data Store".to_string(),
                },
                RiskAssessment {
                    level,
                    summary: if is_unauth {
                        "Redis database exposed WITHOUT AUTHENTICATION (Remote Code Execution risk)".to_string()
                    } else {
                        "Redis in-memory store exposed to network".to_string()
                    },
                    tags: vec![
                        "database".to_string(),
                        "nosql".to_string(),
                        "rce-risk".to_string(),
                    ],
                    recommendation: "Enable 'requirepass' authentication and bind Redis strictly to localhost (127.0.0.1) or unix sockets.".to_string(),
                },
            )
        }
        21 => (
            ServiceInfo {
                name: "ftp".to_string(),
                transport: "tcp".to_string(),
                description: "File Transfer Protocol (Plaintext)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "Unencrypted FTP service exposed; credentials and transfers transmitted in cleartext".to_string(),
                tags: vec![
                    "plaintext".to_string(),
                    "file-transfer".to_string(),
                    "credentials-in-flight".to_string(),
                ],
                recommendation: "Enforce SFTP (via SSH) or FTPS (TLS encryption) and disable legacy plaintext FTP.".to_string(),
            },
        ),
        7547 => (
            ServiceInfo {
                name: "cwmp-tr069".to_string(),
                transport: "tcp".to_string(),
                description: "CPE WAN Management Protocol (TR-069)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "TR-069 Auto-Configuration Server (ACS) client port exposed".to_string(),
                tags: vec!["gpon".to_string(), "tr-069".to_string(), "telecom-mgmt".to_string()],
                recommendation: "Block port 7547 from user-facing subnets; restrict to ISP management OAM network.".to_string(),
            },
        ),
        8728 => (
            ServiceInfo {
                name: "mikrotik-api".to_string(),
                transport: "tcp".to_string(),
                description: "MikroTik RouterOS Plaintext API".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "MikroTik RouterOS Plaintext API service exposed".to_string(),
                tags: vec!["telecom-mgmt".to_string(), "routeros".to_string(), "plaintext-api".to_string()],
                recommendation: "Disable plaintext API or migrate to TLS-secured API on port 8729.".to_string(),
            },
        ),
        8729 => (
            ServiceInfo {
                name: "mikrotik-api-ssl".to_string(),
                transport: "tcp".to_string(),
                description: "MikroTik RouterOS Encrypted API (SSL/TLS)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Medium,
                summary: "MikroTik RouterOS Encrypted API exposed".to_string(),
                tags: vec!["telecom-mgmt".to_string(), "routeros".to_string(), "encrypted".to_string()],
                recommendation: "Restrict access to automated provisioning systems via firewall ACL.".to_string(),
            },
        ),
        3306 => (
            ServiceInfo {
                name: "mysql".to_string(),
                transport: "tcp".to_string(),
                description: "MySQL / MariaDB Relational Database".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "MySQL database port exposed directly to network".to_string(),
                tags: vec!["database".to_string(), "sql".to_string(), "brute-force-target".to_string()],
                recommendation: "Bind MySQL to 127.0.0.1 or internal private network. Use SSH tunnel or VPN for remote access.".to_string(),
            },
        ),
        5432 => (
            ServiceInfo {
                name: "postgresql".to_string(),
                transport: "tcp".to_string(),
                description: "PostgreSQL Relational Database".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "PostgreSQL database port exposed directly to network".to_string(),
                tags: vec!["database".to_string(), "sql".to_string()],
                recommendation: "Configure pg_hba.conf to enforce strict host filtering and client SSL certificates.".to_string(),
            },
        ),
        27017 => (
            ServiceInfo {
                name: "mongodb".to_string(),
                transport: "tcp".to_string(),
                description: "MongoDB NoSQL Document Store".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "MongoDB database service exposed to network".to_string(),
                tags: vec!["database".to_string(), "nosql".to_string()],
                recommendation: "Ensure mongod authentication (--auth) is active and bind to loopback/private IP.".to_string(),
            },
        ),
        3389 => (
            ServiceInfo {
                name: "ms-wbt-server".to_string(),
                transport: "tcp".to_string(),
                description: "Microsoft Remote Desktop Protocol (RDP)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "RDP service exposed; frequent target for ransomware and brute-force attacks".to_string(),
                tags: vec!["remote-desktop".to_string(), "windows".to_string(), "brute-force-target".to_string()],
                recommendation: "Enable Network Level Authentication (NLA), place RDP behind VPN, or restrict via firewall.".to_string(),
            },
        ),
        5900 => (
            ServiceInfo {
                name: "vnc".to_string(),
                transport: "tcp".to_string(),
                description: "Virtual Network Computing (VNC)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::High,
                summary: "VNC remote screen sharing exposed".to_string(),
                tags: vec!["remote-desktop".to_string(), "vnc".to_string()],
                recommendation: "Tunnel VNC sessions over SSH or VPN to prevent eavesdropping and unauthorized access.".to_string(),
            },
        ),
        161 | 162 => (
            ServiceInfo {
                name: "snmp".to_string(),
                transport: "tcp".to_string(),
                description: "Simple Network Management Protocol".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Medium,
                summary: "SNMP service reachable".to_string(),
                tags: vec!["monitoring".to_string(), "telecom".to_string(), "recon".to_string()],
                recommendation: "Ensure default community strings ('public'/'private') are changed; upgrade to SNMPv3 with USM encryption.".to_string(),
            },
        ),
        179 => (
            ServiceInfo {
                name: "bgp".to_string(),
                transport: "tcp".to_string(),
                description: "Border Gateway Protocol".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Medium,
                summary: "BGP routing port exposed".to_string(),
                tags: vec!["routing".to_string(), "telecom-core".to_string(), "bgp".to_string()],
                recommendation: "Enforce TCP MD5 authentication / RFC 2385 and GTSM (RFC 5082) on BGP peerings.".to_string(),
            },
        ),
        554 => (
            ServiceInfo {
                name: "rtsp".to_string(),
                transport: "tcp".to_string(),
                description: "Real-Time Streaming Protocol (IP Cameras)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Medium,
                summary: "RTSP video streaming protocol exposed (IP camera feed)".to_string(),
                tags: vec!["surveillance".to_string(), "streaming".to_string(), "iot".to_string()],
                recommendation: "Require authentication for RTSP streams and isolate video surveillance devices onto an isolated VLAN.".to_string(),
            },
        ),
        2000 => (
            ServiceInfo {
                name: "mikrotik-btest".to_string(),
                transport: "tcp".to_string(),
                description: "MikroTik Bandwidth Test Server".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Medium,
                summary: "MikroTik Bandwidth Test server reachable".to_string(),
                tags: vec!["telecom-mgmt".to_string(), "routeros".to_string(), "dos-vector".to_string()],
                recommendation: "Disable '/tool bandwidth-server' when not performing active benchmark tests.".to_string(),
            },
        ),
        80 | 8080 | 8000 | 8008 | 8888 => (
            ServiceInfo {
                name: "http".to_string(),
                transport: "tcp".to_string(),
                description: "Hypertext Transfer Protocol (Plaintext)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Low,
                summary: "Plaintext HTTP web service exposed without encryption".to_string(),
                tags: vec!["web".to_string(), "plaintext".to_string()],
                recommendation: "Redirect all HTTP traffic to HTTPS (port 443) with valid TLS certificates.".to_string(),
            },
        ),
        22 => (
            ServiceInfo {
                name: "ssh".to_string(),
                transport: "tcp".to_string(),
                description: "Secure Shell Protocol".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Info,
                summary: "Encrypted SSH service active".to_string(),
                tags: vec!["remote-admin".to_string(), "encrypted".to_string()],
                recommendation: "Disable password-based authentication; enforce ED25519 public keys and fail2ban.".to_string(),
            },
        ),
        443 | 8443 | 9443 => (
            ServiceInfo {
                name: "https".to_string(),
                transport: "tcp".to_string(),
                description: "HTTP over TLS/SSL (Encrypted)".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Info,
                summary: "Encrypted HTTPS service active".to_string(),
                tags: vec!["web".to_string(), "tls".to_string(), "encrypted".to_string()],
                recommendation: "Maintain TLS 1.2/1.3 configurations and enforce HSTS headers.".to_string(),
            },
        ),
        _ => (
            ServiceInfo {
                name: format!("unknown-{}", port),
                transport: "tcp".to_string(),
                description: "Unclassified TCP Port".to_string(),
            },
            RiskAssessment {
                level: RiskLevel::Low,
                summary: format!("Open unclassified TCP port {}", port),
                tags: vec!["custom-service".to_string()],
                recommendation: "Audit host service binding to verify legitimate business need.".to_string(),
            },
        ),
    }
}
