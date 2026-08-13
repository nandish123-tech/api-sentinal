/// Parses raw bytes captured by the eBPF program into structured HTTP events.

#[derive(Debug, serde::Serialize)]
pub struct HttpEvent {
    pub pid: u32,
    pub comm: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_us: u64,
}

/// Attempt to parse an HTTP request/response pair from raw bytes.
pub fn parse_http(buf: &[u8]) -> Option<HttpEvent> {
    // TODO: implement real HTTP parsing from eBPF captured data
    let _ = buf;
    None
}
