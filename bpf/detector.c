//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Event types
#define EVENT_EXECVE 1
#define EVENT_SETUID 2
#define EVENT_SETGID 3
#define EVENT_CLONE  4

struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u32 _pad;           // explicit padding for 8-byte alignment
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint context for sys_enter
struct syscall_trace_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    unsigned long args[6];
};

// Track execve syscalls
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct syscall_trace_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->pid = pid_tgid >> 32;
    e->ppid = 0;
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    e->event_type = EVENT_EXECVE;
    e->_pad = 0;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Initialize filename buffer
    e->filename[0] = '\0';

    // Read filename from syscall argument
    const char *filename_ptr = (const char *)ctx->args[0];
    if (filename_ptr) {
        long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);
        if (ret < 0) {
            // Try kernel memory if user read fails (some edge cases)
            bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename_ptr);
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Track setuid syscalls (privilege escalation detection)
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct syscall_trace_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->pid = pid_tgid >> 32;
    e->ppid = 0;
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    e->event_type = EVENT_SETUID;
    e->_pad = 0;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Track setgid syscalls
SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct syscall_trace_enter *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->pid = pid_tgid >> 32;
    e->ppid = 0;
    e->uid = uid_gid & 0xFFFFFFFF;
    e->gid = uid_gid >> 32;
    e->event_type = EVENT_SETGID;
    e->_pad = 0;
    e->timestamp = bpf_ktime_get_ns();

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}
