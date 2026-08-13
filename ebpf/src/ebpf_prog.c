#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Ring buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Event structure
struct http_event {
    u64 timestamp;
    u32 pid;
    u32 uid;
    u8 method[8];
    u8 path[128];
    u8 host[64];
    u16 port;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *args) {
    // Simplified: we only capture connect() to correlate with later sends
    // Real implementation would use sock filter or tracepoint for sendto/recv
    // For demo, we just emit a dummy event
    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    __builtin_memcpy(e->method, "GET", 4);
    __builtin_memcpy(e->path, "/", 2);
    __builtin_memcpy(e->host, "example.com", 12);
    e->port = 80;
    bpf_ringbuf_submit(e, 0);
    return 0;
}