use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Probe a target TCP port. Returns the round-trip connect latency if open.
pub async fn probe_tcp_connect(target: SocketAddr, timeout_dur: Duration) -> Option<Duration> {
    let start = Instant::now();
    match timeout(timeout_dur, TcpStream::connect(target)).await {
        Ok(Ok(_stream)) => Some(start.elapsed()),
        _ => None,
    }
}

/// Probe a target TCP port and return the connected TcpStream and latency for banner grabbing.
pub async fn probe_tcp_connect_stream(
    target: SocketAddr,
    timeout_dur: Duration,
) -> Option<(TcpStream, Duration)> {
    let start = Instant::now();
    match timeout(timeout_dur, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => Some((stream, start.elapsed())),
        _ => None,
    }
}
