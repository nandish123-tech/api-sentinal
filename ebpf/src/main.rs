use aya::{Bpf, programs::TracePoint, maps::RingBuf};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::config::ClientConfig;
use serde_json::json;
use bytes::Bytes;
use tokio::time;

#[derive(Debug, Clone, serde::Serialize)]
struct HttpEvent {
    timestamp: u64,
    pid: u32,
    uid: u32,
    method: String,
    path: String,
    host: String,
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load eBPF program
    let mut bpf = Bpf::load(include_bytes!("ebpf_prog.o"))?;
    let prog: &mut TracePoint = bpf.program_mut("trace_connect")?.try_into()?;
    prog.load()?;
    prog.attach("syscalls", "sys_enter_connect")?;

    // Ring buffer
    let ring_buf = RingBuf::try_from(bpf.map("events")?)?;

    // Kafka producer
    let kafka_brokers = std::env::var("KAFKA_BROKERS").unwrap_or("localhost:9092".to_string());
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &kafka_brokers)
        .set("message.timeout.ms", "5000")
        .create()?;

    println!("✅ Sensor started. Capturing HTTP metadata...");

    // Poll events
    let mut reader = ring_buf.into_reader();
    loop {
        if let Some(event_bytes) = reader.next().await {
            // Parse raw bytes into HttpEvent (simplified)
            let raw = event_bytes.as_slice();
            if raw.len() < 32 { continue; }
            let method = String::from_utf8_lossy(&raw[32..40]).trim_end_matches('\0').to_string();
            let path = String::from_utf8_lossy(&raw[40..168]).trim_end_matches('\0').to_string();
            let host = String::from_utf8_lossy(&raw[168..232]).trim_end_matches('\0').to_string();
            let port = u16::from_le_bytes([raw[232], raw[233]]);
            let event = HttpEvent {
                timestamp: u64::from_le_bytes(raw[0..8].try_into().unwrap()),
                pid: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
                uid: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
                method,
                path,
                host,
                port,
            };
            // Send to Kafka
            let payload = serde_json::to_vec(&event)?;
            let record = FutureRecord::to("raw-http")
                .payload(&payload)
                .key(&event.host);
            if let Err(e) = producer.send(record, time::Duration::from_secs(5)).await {
                eprintln!("❌ Kafka send error: {:?}", e);
            }
        }
    }
}