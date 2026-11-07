use sentry_scan::classification::{evaluate_risk, RiskLevel};
use sentry_scan::scanner::banner::{parse_http_response, BannerInfo};

#[test]
fn test_parse_http_response_nginx() {
    let raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\nContent-Type: text/html\r\n\r\nHello";
    let banner = parse_http_response(raw).expect("should parse http response");
    assert_eq!(banner.protocol, "HTTP");
    assert_eq!(banner.raw_banner, "HTTP/1.1 200 OK");
    assert_eq!(banner.server_header, Some("nginx/1.24.0".to_string()));
}

#[test]
fn test_parse_http_response_mikrotik() {
    let raw = "HTTP/1.0 401 Unauthorized\r\nServer: Mikrotik HttpProxy\r\nWWW-Authenticate: Basic realm=\"MikroTik\"\r\n\r\n";
    let banner = parse_http_response(raw).expect("should parse mikrotik http");
    assert_eq!(banner.protocol, "HTTP");
    assert_eq!(banner.raw_banner, "HTTP/1.0 401 Unauthorized");
    assert_eq!(banner.server_header, Some("Mikrotik HttpProxy".to_string()));
}

#[test]
fn test_parse_http_response_invalid() {
    let raw = "NOT_HTTP_DATA\r\nsome random garbage";
    assert!(parse_http_response(raw).is_none());
}

#[test]
fn test_risk_evaluation_telnet() {
    let (service, risk) = evaluate_risk(23, None);
    assert_eq!(service.name, "telnet");
    assert_eq!(risk.level, RiskLevel::Critical);
    assert!(risk.tags.contains(&"plaintext".to_string()));
}

#[test]
fn test_risk_evaluation_winbox() {
    let (service, risk) = evaluate_risk(8291, None);
    assert_eq!(service.name, "mikrotik-winbox");
    assert_eq!(risk.level, RiskLevel::High);
    assert!(risk.tags.contains(&"telecom-mgmt".to_string()));
}

#[test]
fn test_risk_evaluation_redis_unauth_vs_auth() {
    let unauth_banner = BannerInfo {
        protocol: "Redis".to_string(),
        raw_banner: "+PONG".to_string(),
        server_header: None,
        version: None,
    };
    let (_, unauth_risk) = evaluate_risk(6379, Some(&unauth_banner));
    assert_eq!(unauth_risk.level, RiskLevel::Critical);

    let auth_banner = BannerInfo {
        protocol: "Redis".to_string(),
        raw_banner: "-NOAUTH Authentication required.".to_string(),
        server_header: None,
        version: None,
    };
    let (_, auth_risk) = evaluate_risk(6379, Some(&auth_banner));
    assert_eq!(auth_risk.level, RiskLevel::High);
}

#[test]
fn test_risk_evaluation_ssh_and_https() {
    let (ssh_svc, ssh_risk) = evaluate_risk(22, None);
    assert_eq!(ssh_svc.name, "ssh");
    assert_eq!(ssh_risk.level, RiskLevel::Info);

    let (https_svc, https_risk) = evaluate_risk(443, None);
    assert_eq!(https_svc.name, "https");
    assert_eq!(https_risk.level, RiskLevel::Info);
}
