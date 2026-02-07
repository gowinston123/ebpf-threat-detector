# eBPF Threat Detector

## Project Overview
Linux security monitoring tool using eBPF for real-time process/syscall monitoring. Detects suspicious process behavior and privilege escalation attempts.

## Tech Stack
- **Language**: Go 1.21+
- **eBPF Library**: cilium/ebpf v0.12.3
- **eBPF Programs**: C with libbpf/CO-RE
- **Build Tool**: bpf2go (generates Go bindings from C)

## Directory Structure
```
bpf/              # eBPF C programs (kernel-space)
cmd/detector/     # Main entry point
internal/loader/  # eBPF program loading (bpf2go generated)
internal/detector/# Threat detection logic
pkg/events/       # Event types shared between kernel/user space
```

## Build (requires Linux with BTF)
```bash
# Lima VM is available: limactl shell ebpf-vm
export PATH=/usr/local/go/bin:$HOME/go/bin:$PATH
make deps    # Install bpf2go
make build   # Generate + compile
sudo ./bin/ebpf-threat-detector
```

## Key Files
- `bpf/detector.c` - eBPF tracepoints (execve, setuid, setgid)
- `internal/detector/detector.go` - Threat analysis rules
- `pkg/events/events.go` - Event struct matching C struct

## Development Notes
- eBPF C struct `event` must match Go `events.Event` (binary layout)
- Run as root (eBPF requires CAP_BPF/CAP_SYS_ADMIN)
- Target kernel 5.8+ with BTF support
- Lima VM: `ebpf-vm` with project mounted at `/Users/leemingi/ebpf-threat-detector`
