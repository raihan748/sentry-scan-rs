use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use sentry_scan::scanner::{run_scan, ScanConfig};

#[tokio::test]
async fn test_loopback_scan_discovers_open_ports_and_omits_closed() {
    // 1. Bind an ephemeral loopback TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let open_port = listener.local_addr().expect("local addr").port();

    // Spawn task to accept and hold open connection briefly
    let handle = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 128];
            let _ = socket.read(&mut buf).await;
        }
    });

    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Test ports: the open port and closed arbitrary ports
    let closed_port_1 = 59123;
    let closed_port_2 = 59124;
    let ports = vec![open_port, closed_port_1, closed_port_2];

    let config = ScanConfig {
        concurrency: 10,
        timeout: Duration::from_millis(500),
        grab_banner: false,
    };

    let report = run_scan(&[localhost], &ports, config).await;

    assert_eq!(report.scanned_count, 3);
    assert_eq!(report.open_count, 1);
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].port, open_port);
    assert!(report.results[0].is_open);
    assert!(report.results[0].rtt_ms >= 0.0);

    let _ = handle.await;
}

#[tokio::test]
async fn test_loopback_http_banner_grab() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let open_port = listener.local_addr().expect("local addr").port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 512];
            let _ = socket.read(&mut buf).await;
            let response = "HTTP/1.1 200 OK\r\nServer: MockSentryGateway/1.0\r\nContent-Length: 2\r\n\r\nOK";
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let config = ScanConfig {
        concurrency: 5,
        timeout: Duration::from_millis(1000),
        grab_banner: true,
    };

    let report = run_scan(&[localhost], &[open_port], config).await;

    assert_eq!(report.open_count, 1);
    let res = &report.results[0];
    assert_eq!(res.port, open_port);
    assert!(res.banner.is_some());
    let banner = res.banner.as_ref().unwrap();
    assert!(banner.raw_banner.contains("MockSentryGateway") || banner.server_header.as_deref() == Some("MockSentryGateway/1.0"));

    let _ = server_task.await;
}

#[tokio::test]
async fn test_high_concurrency_scan_with_multiple_listeners() {
    let l1 = TcpListener::bind("127.0.0.1:0").await.expect("bind l1");
    let l2 = TcpListener::bind("127.0.0.1:0").await.expect("bind l2");
    let l3 = TcpListener::bind("127.0.0.1:0").await.expect("bind l3");

    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();
    let p3 = l3.local_addr().unwrap().port();

    let t1 = tokio::spawn(async move {
        if let Ok((mut s, _)) = l1.accept().await {
            let _ = s.write_all(b"OK").await;
        }
    });
    let t2 = tokio::spawn(async move {
        if let Ok((mut s, _)) = l2.accept().await {
            let _ = s.write_all(b"OK").await;
        }
    });
    let t3 = tokio::spawn(async move {
        if let Ok((mut s, _)) = l3.accept().await {
            let _ = s.write_all(b"OK").await;
        }
    });

    let mut ports = vec![p1, p2, p3];
    // Add 40 closed ports
    for offset in 0..40 {
        ports.push(58000 + offset);
    }

    let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let config = ScanConfig {
        concurrency: 50,
        timeout: Duration::from_millis(300),
        grab_banner: false,
    };

    let report = run_scan(&[localhost], &ports, config).await;

    assert_eq!(report.scanned_count, ports.len());
    assert_eq!(report.open_count, 3);

    let discovered_ports: Vec<u16> = report.results.iter().map(|r| r.port).collect();
    let mut expected_ports = vec![p1, p2, p3];
    expected_ports.sort_unstable();
    assert_eq!(discovered_ports, expected_ports);

    let _ = tokio::join!(t1, t2, t3);
}
