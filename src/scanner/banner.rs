use std::net::IpAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BannerInfo {
    pub protocol: String,
    pub raw_banner: String,
    pub server_header: Option<String>,
    pub version: Option<String>,
}

/// Grab banner from an established TCP stream based on port or generic response.
pub async fn grab_banner(
    stream: &mut TcpStream,
    port: u16,
    host: IpAddr,
    probe_timeout: Duration,
) -> Option<BannerInfo> {
    match port {
        22 => grab_ssh_banner(stream, probe_timeout).await,
        21 => grab_ftp_banner(stream, probe_timeout).await,
        23 => grab_telnet_banner(stream, probe_timeout).await,
        80 | 8080 | 8000 | 8081 | 8888 | 3000 | 5000 => {
            grab_http_banner(stream, host, port, probe_timeout).await
        }
        443 | 8443 | 9443 => Some(BannerInfo {
            protocol: "HTTPS/TLS".to_string(),
            raw_banner: "TLS/SSL Encrypted Endpoint".to_string(),
            server_header: None,
            version: None,
        }),
        6379 => grab_redis_banner(stream, probe_timeout).await,
        8291 => Some(BannerInfo {
            protocol: "MikroTik-Winbox".to_string(),
            raw_banner: "MikroTik RouterOS Winbox Management Protocol".to_string(),
            server_header: None,
            version: None,
        }),
        _ => grab_generic_banner(stream, probe_timeout).await,
    }
}

pub async fn grab_ssh_banner(stream: &mut TcpStream, dur: Duration) -> Option<BannerInfo> {
    let mut buf = [0u8; 512];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            let first_line = text.lines().next().unwrap_or("").trim().to_string();
            if first_line.starts_with("SSH-") {
                return Some(BannerInfo {
                    protocol: "SSH".to_string(),
                    raw_banner: first_line.clone(),
                    server_header: None,
                    version: Some(first_line),
                });
            }
        }
    }
    None
}

pub async fn grab_ftp_banner(stream: &mut TcpStream, dur: Duration) -> Option<BannerInfo> {
    let mut buf = [0u8; 512];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            let text = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            let first_line = text.lines().next().unwrap_or("").trim().to_string();
            return Some(BannerInfo {
                protocol: "FTP".to_string(),
                raw_banner: first_line,
                server_header: None,
                version: None,
            });
        }
    }
    None
}

pub async fn grab_telnet_banner(stream: &mut TcpStream, dur: Duration) -> Option<BannerInfo> {
    let mut buf = [0u8; 512];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            // Strip Telnet IAC (0xFF) sequences
            let sanitized: Vec<u8> = buf[..n]
                .iter()
                .filter(|&&b| b >= 32 && b <= 126 || b == b'\n' || b == b'\r')
                .copied()
                .collect();
            let text = String::from_utf8_lossy(&sanitized).trim().to_string();
            return Some(BannerInfo {
                protocol: "Telnet".to_string(),
                raw_banner: if text.is_empty() {
                    "Telnet Service (IAC negotiation detected)".to_string()
                } else {
                    text
                },
                server_header: None,
                version: None,
            });
        }
    }
    None
}

pub async fn grab_http_banner(
    stream: &mut TcpStream,
    host: IpAddr,
    _port: u16,
    dur: Duration,
) -> Option<BannerInfo> {
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: SentryScan/1.0\r\nConnection: close\r\n\r\n",
        host
    );

    if stream.write_all(request.as_bytes()).await.is_err() {
        return None;
    }

    let mut buf = [0u8; 2048];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            let response = String::from_utf8_lossy(&buf[..n]);
            return parse_http_response(&response);
        }
    }
    None
}

/// Parse HTTP status line and Server header
pub fn parse_http_response(raw: &str) -> Option<BannerInfo> {
    let mut lines = raw.lines();
    let status_line = lines.next()?.trim().to_string();
    if !status_line.starts_with("HTTP/") {
        return None;
    }

    let mut server_header = None;
    for line in lines {
        let line_lower = line.to_ascii_lowercase();
        if line_lower.starts_with("server:") {
            let val = line["server:".len()..].trim().to_string();
            server_header = Some(val);
            break;
        }
    }

    Some(BannerInfo {
        protocol: "HTTP".to_string(),
        raw_banner: status_line,
        server_header,
        version: None,
    })
}

pub async fn grab_redis_banner(stream: &mut TcpStream, dur: Duration) -> Option<BannerInfo> {
    if stream.write_all(b"PING\r\n").await.is_err() {
        return None;
    }

    let mut buf = [0u8; 256];
    if let Ok(Ok(n)) = timeout(dur, stream.read(&mut buf)).await {
        if n > 0 {
            let resp = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            let is_unauth = resp.contains("+PONG");
            let is_auth_req = resp.contains("NOAUTH");
            return Some(BannerInfo {
                protocol: "Redis".to_string(),
                raw_banner: if is_unauth {
                    "Redis: Exposed without authentication (+PONG)".to_string()
                } else if is_auth_req {
                    "Redis: Authentication required (-NOAUTH)".to_string()
                } else {
                    resp
                },
                server_header: None,
                version: None,
            });
        }
    }
    None
}

pub async fn grab_generic_banner(stream: &mut TcpStream, dur: Duration) -> Option<BannerInfo> {
    // Attempt passive read first
    let mut buf = [0u8; 256];
    if let Ok(Ok(n)) = timeout(dur / 2, stream.read(&mut buf)).await {
        if n > 0 {
            let text = sanitize_banner(&buf[..n]);
            if !text.is_empty() {
                return Some(BannerInfo {
                    protocol: "Unknown".to_string(),
                    raw_banner: text,
                    server_header: None,
                    version: None,
                });
            }
        }
    }

    // Try sending CRLF probe
    if stream.write_all(b"\r\n").await.is_ok() {
        if let Ok(Ok(n)) = timeout(dur / 2, stream.read(&mut buf)).await {
            if n > 0 {
                let text = sanitize_banner(&buf[..n]);
                if !text.is_empty() {
                    return Some(BannerInfo {
                        protocol: "Unknown".to_string(),
                        raw_banner: text,
                        server_header: None,
                        version: None,
                    });
                }
            }
        }
    }

    None
}

fn sanitize_banner(bytes: &[u8]) -> String {
    let clean: Vec<u8> = bytes
        .iter()
        .filter(|&&b| (b >= 32 && b <= 126) || b == b' ' || b == b'\t')
        .copied()
        .collect();
    String::from_utf8_lossy(&clean).trim().to_string()
}
