# eBPF Threat Detector

A Linux security monitoring tool using eBPF for real-time process and syscall monitoring.

## Features

- Process execution monitoring (execve syscalls)
- Privilege escalation detection (setuid/setgid calls)
- Suspicious syscall pattern detection

## Requirements

- Linux kernel 5.8+ with BTF support
- Go 1.21+
- clang/llvm for compiling eBPF programs
- Root privileges for loading eBPF programs

## Build

```bash
make build
```

## Run

```bash
sudo ./bin/ebpf-threat-detector
```

## Project Structure

```
├── bpf/              # eBPF C programs
├── cmd/              # Application entry point
├── internal/
│   ├── detector/     # Threat detection logic
│   └── loader/       # eBPF program loader
└── pkg/
    └── events/       # Event types and parsing
```


## References
https://github.com/cilium/cilium
