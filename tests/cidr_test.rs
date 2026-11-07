use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use sentry_scan::cidr::{parse_ports, parse_targets, PRESET_TELECOM, PRESET_TOP100, PRESET_WEB};

#[test]
fn test_parse_single_ipv4_and_ipv6() {
    let res = parse_targets("192.168.1.1", true).expect("should parse ipv4");
    assert_eq!(res.len(), 1);
    assert_eq!(res[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

    let res6 = parse_targets("::1", true).expect("should parse ipv6");
    assert_eq!(res6.len(), 1);
    assert_eq!(res6[0], IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));

    let res_localhost = parse_targets("localhost", true).expect("should parse localhost");
    assert_eq!(res_localhost[0], IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
}

#[test]
fn test_parse_cidr_ipv4_subnet_usable_only() {
    // /24 subnet has 256 addresses: 0 is network, 255 is broadcast. Usable = 254
    let hosts = parse_targets("192.168.10.0/24", true).expect("should expand /24");
    assert_eq!(hosts.len(), 254);
    assert_eq!(hosts[0], IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1)));
    assert_eq!(hosts[253], IpAddr::V4(Ipv4Addr::new(192, 168, 10, 254)));
}

#[test]
fn test_parse_cidr_ipv4_all_hosts() {
    let hosts = parse_targets("192.168.10.0/24", false).expect("should expand all /24");
    assert_eq!(hosts.len(), 256);
    assert_eq!(hosts[0], IpAddr::V4(Ipv4Addr::new(192, 168, 10, 0)));
    assert_eq!(hosts[255], IpAddr::V4(Ipv4Addr::new(192, 168, 10, 255)));
}

#[test]
fn test_parse_cidr_edge_subnets() {
    // /32 single host
    let h32 = parse_targets("10.0.0.5/32", true).expect("should expand /32");
    assert_eq!(h32.len(), 1);
    assert_eq!(h32[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));

    // /31 RFC 3021 point-to-point (both IPs usable)
    let h31 = parse_targets("10.0.0.0/31", true).expect("should expand /31");
    assert_eq!(h31.len(), 2);
    assert_eq!(h31[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    assert_eq!(h31[1], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    // /30 standard link (2 usable hosts: .1 and .2)
    let h30 = parse_targets("10.0.0.0/30", true).expect("should expand /30");
    assert_eq!(h30.len(), 2);
    assert_eq!(h30[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(h30[1], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
}

#[test]
fn test_parse_ip_range() {
    let hosts = parse_targets("10.0.1.10-10.0.1.15", true).expect("should parse range");
    assert_eq!(hosts.len(), 6);
    assert_eq!(hosts[0], IpAddr::V4(Ipv4Addr::new(10, 0, 1, 10)));
    assert_eq!(hosts[5], IpAddr::V4(Ipv4Addr::new(10, 0, 1, 15)));

    let short_range = parse_targets("192.168.1.1-5", true).expect("should parse short range");
    assert_eq!(short_range.len(), 5);
    assert_eq!(short_range[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(short_range[4], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)));
}

#[test]
fn test_parse_multiple_comma_targets() {
    let targets = parse_targets("127.0.0.1, 192.168.1.1-3, 10.0.0.0/31", true)
        .expect("should parse multi targets");
    // 127.0.0.1 (1) + 192.168.1.1-3 (3) + 10.0.0.0/31 (2) = 6
    assert_eq!(targets.len(), 6);
}

#[test]
fn test_port_ranges_and_deduplication() {
    let ports = parse_ports(Some("80, 443, 8080-8083, 80"), None).expect("valid ports");
    assert_eq!(ports, vec![80, 443, 8080, 8081, 8082, 8083]);
}

#[test]
fn test_port_presets() {
    let top100 = parse_ports(None, Some("top100")).expect("top100 preset");
    assert_eq!(top100.len(), PRESET_TOP100.len());
    assert!(top100.contains(&80));
    assert!(top100.contains(&443));
    assert!(top100.contains(&22));
    assert!(top100.contains(&8291));

    let telecom = parse_ports(None, Some("telecom")).expect("telecom preset");
    assert_eq!(telecom.len(), PRESET_TELECOM.len());
    assert!(telecom.contains(&8291)); // Winbox
    assert!(telecom.contains(&179));  // BGP
    assert!(telecom.contains(&7547)); // TR-069
    assert!(telecom.contains(&8728)); // MikroTik API

    let web = parse_ports(None, Some("web")).expect("web preset");
    assert_eq!(web.len(), PRESET_WEB.len());
    assert!(web.contains(&80));
    assert!(web.contains(&443));
}

#[test]
fn test_invalid_target_and_ports() {
    assert!(parse_targets("invalid-ip-string", true).is_err());
    assert!(parse_targets("192.168.1.50-10", true).is_err()); // inverted
    assert!(parse_ports(Some("8080-8000"), None).is_err());  // inverted
    assert!(parse_ports(Some("0"), None).is_err());          // reserved 0
    assert!(parse_ports(Some("70000"), None).is_err());      // > 65535
    assert!(parse_ports(None, Some("unknown-preset")).is_err());
}
