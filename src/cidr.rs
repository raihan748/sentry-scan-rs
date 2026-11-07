use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use crate::error::SentryScanError;

/// Parse target input string which may contain:
/// - Single IP: "192.168.1.1" or "::1"
/// - CIDR block: "192.168.1.0/24"
/// - IP Range: "192.168.1.1-192.168.1.10" or "192.168.1.1-10"
/// - Comma-separated combination of the above: "127.0.0.1, 10.0.0.0/29"
pub fn parse_targets(input: &str, usable_only: bool) -> Result<Vec<IpAddr>, SentryScanError> {
    let mut results = Vec::new();

    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        if let Ok(ip) = token.parse::<IpAddr>() {
            results.push(ip);
        } else if let Ok(net) = token.parse::<IpNet>() {
            results.extend(expand_ipnet(net, usable_only));
        } else if token.contains('-') {
            results.extend(parse_ip_range(token)?);
        } else if token.eq_ignore_ascii_case("localhost") {
            results.push(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        } else {
            return Err(SentryScanError::InvalidTarget(format!(
                "Unrecognized IP, CIDR, or range specification: '{}'",
                token
            )));
        }
    }

    if results.is_empty() {
        return Err(SentryScanError::InvalidTarget(
            "Target specification yielded zero valid host addresses".to_string(),
        ));
    }

    results.sort();
    results.dedup();
    Ok(results)
}

/// Expand an IpNet (IPv4 or IPv6) to host addresses.
/// If `usable_only` is true for IPv4 subnets <= /30, network and broadcast addresses are excluded.
pub fn expand_ipnet(net: IpNet, usable_only: bool) -> Vec<IpAddr> {
    match net {
        IpNet::V4(net4) => expand_ipv4_net(net4, usable_only)
            .into_iter()
            .map(IpAddr::V4)
            .collect(),
        IpNet::V6(net6) => expand_ipv6_net(net6)
            .into_iter()
            .map(IpAddr::V6)
            .collect(),
    }
}

fn expand_ipv4_net(net: Ipv4Net, usable_only: bool) -> Vec<Ipv4Addr> {
    let prefix = net.prefix_len();
    let network_u32 = u32::from(net.network());
    let broadcast_u32 = u32::from(net.broadcast());

    if prefix == 32 {
        vec![net.network()]
    } else if prefix == 31 {
        // RFC 3021: /31 subnets for point-to-point links (both IPs are usable hosts)
        vec![net.network(), net.broadcast()]
    } else if usable_only {
        // Standard subnet: exclude network and broadcast
        let start = network_u32 + 1;
        let end = broadcast_u32 - 1;
        if start <= end {
            (start..=end).map(Ipv4Addr::from).collect()
        } else {
            vec![net.network()]
        }
    } else {
        (network_u32..=broadcast_u32).map(Ipv4Addr::from).collect()
    }
}

fn expand_ipv6_net(net: Ipv6Net) -> Vec<Ipv6Addr> {
    // Limit expansion for IPv6 to max 65536 to avoid runaway allocation
    let host_count = if net.prefix_len() >= 112 {
        1u128 << (128 - net.prefix_len())
    } else {
        1024 // Cap expansion for large v6 nets
    };

    let start_u128 = u128::from(net.network());
    (0..host_count.min(65536))
        .map(|offset| Ipv6Addr::from(start_u128 + offset))
        .collect()
}

/// Parse IPv4 range, such as "192.168.1.1-192.168.1.10" or "192.168.1.1-10"
fn parse_ip_range(token: &str) -> Result<Vec<IpAddr>, SentryScanError> {
    let parts: Vec<&str> = token.split('-').map(|s| s.trim()).collect();
    if parts.len() != 2 {
        return Err(SentryScanError::InvalidTarget(format!(
            "Invalid IP range format: '{}'",
            token
        )));
    }

    let start_ip: Ipv4Addr = parts[0].parse().map_err(|_| {
        SentryScanError::InvalidTarget(format!("Invalid start IP in range: '{}'", parts[0]))
    })?;

    let end_ip: Ipv4Addr = if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
        ip
    } else if let Ok(last_octet) = parts[1].parse::<u8>() {
        let octets = start_ip.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
    } else {
        return Err(SentryScanError::InvalidTarget(format!(
            "Invalid end IP in range: '{}'",
            parts[1]
        )));
    };

    let start_u32 = u32::from(start_ip);
    let end_u32 = u32::from(end_ip);

    if start_u32 > end_u32 {
        return Err(SentryScanError::InvalidTarget(format!(
            "Start IP '{}' is greater than end IP '{}'",
            start_ip, end_ip
        )));
    }

    if (end_u32 - start_u32) > 65536 {
        return Err(SentryScanError::InvalidTarget(format!(
            "IP range too large (>65536 hosts): '{}'",
            token
        )));
    }

    Ok((start_u32..=end_u32)
        .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
        .collect())
}

/// Port Presets: top100, telecom, web
pub const PRESET_TOP100: &[u16] = &[
    20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179,
    389, 443, 445, 465, 500, 514, 515, 520, 587, 636, 873, 902, 989, 990, 993, 995, 1025, 1080,
    1194, 1433, 1434, 1521, 1723, 1812, 1813, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 3000,
    3128, 3306, 3389, 4333, 4443, 4500, 5000, 5060, 5061, 5432, 5672, 5900, 5985, 5986, 6000,
    6379, 7001, 7077, 7547, 8000, 8008, 8080, 8081, 8082, 8088, 8090, 8181, 8291, 8443, 8500,
    8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 27017,
    28017, 50000, 50070,
];

pub const PRESET_TELECOM: &[u16] = &[
    20, 21, 22, 23, 53, 67, 68, 69, 80, 88, 110, 123, 161, 162, 179, 389, 443, 500, 514, 520,
    554, 636, 873, 1194, 1701, 1723, 1812, 1813, 2000, 2001, 2022, 4500, 5060, 5061, 7547,
    8080, 8291, 8443, 8728, 8729, 9100,
];

pub const PRESET_WEB: &[u16] = &[
    80, 81, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443,
];

/// Parse port specification string or preset name.
/// Examples:
/// - "80"
/// - "80,443,8080"
/// - "8000-8010"
/// - "22,80-85,443"
/// - "top100", "telecom", "web"
pub fn parse_ports(spec: Option<&str>, preset: Option<&str>) -> Result<Vec<u16>, SentryScanError> {
    let mut ports = Vec::new();

    if let Some(p) = preset {
        match p.to_ascii_lowercase().as_str() {
            "top100" => ports.extend_from_slice(PRESET_TOP100),
            "telecom" => ports.extend_from_slice(PRESET_TELECOM),
            "web" => ports.extend_from_slice(PRESET_WEB),
            other => {
                return Err(SentryScanError::InvalidPort(format!(
                    "Unknown port preset: '{}'. Choose from: 'top100', 'telecom', 'web'",
                    other
                )));
            }
        }
    }

    if let Some(spec_str) = spec {
        for segment in spec_str.split(',') {
            let seg = segment.trim();
            if seg.is_empty() {
                continue;
            }

            if seg.eq_ignore_ascii_case("top100") {
                ports.extend_from_slice(PRESET_TOP100);
            } else if seg.eq_ignore_ascii_case("telecom") {
                ports.extend_from_slice(PRESET_TELECOM);
            } else if seg.eq_ignore_ascii_case("web") {
                ports.extend_from_slice(PRESET_WEB);
            } else if seg.contains('-') {
                let parts: Vec<&str> = seg.split('-').map(|s| s.trim()).collect();
                if parts.len() != 2 {
                    return Err(SentryScanError::InvalidPort(format!(
                        "Invalid port range format: '{}'",
                        seg
                    )));
                }
                let start: u16 = parts[0].parse().map_err(|_| {
                    SentryScanError::InvalidPort(format!("Invalid start port: '{}'", parts[0]))
                })?;
                let end: u16 = parts[1].parse().map_err(|_| {
                    SentryScanError::InvalidPort(format!("Invalid end port: '{}'", parts[1]))
                })?;

                if start == 0 || end == 0 {
                    return Err(SentryScanError::InvalidPort(
                        "Port 0 is reserved and invalid for TCP scan".to_string(),
                    ));
                }
                if start > end {
                    return Err(SentryScanError::InvalidPort(format!(
                        "Start port {} > end port {}",
                        start, end
                    )));
                }
                for port in start..=end {
                    ports.push(port);
                }
            } else {
                let port: u16 = seg.parse().map_err(|_| {
                    SentryScanError::InvalidPort(format!("Invalid port number: '{}'", seg))
                })?;
                if port == 0 {
                    return Err(SentryScanError::InvalidPort(
                        "Port 0 is reserved and invalid for TCP scan".to_string(),
                    ));
                }
                ports.push(port);
            }
        }
    }

    if ports.is_empty() {
        return Err(SentryScanError::InvalidPort(
            "No ports specified. Provide --ports or --preset".to_string(),
        ));
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}
