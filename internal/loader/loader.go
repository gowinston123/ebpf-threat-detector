package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event detector ../../bpf/detector.c

// Loader manages eBPF program lifecycle
type Loader struct {
	objs   detectorObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// New creates a new eBPF loader
func New() (*Loader, error) {
	var objs detectorObjects
	if err := loadDetectorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	return &Loader{
		objs:  objs,
		links: make([]link.Link, 0),
	}, nil
}

// Attach attaches all eBPF programs to their hooks
func (l *Loader) Attach() error {
	// Attach execve tracepoint
	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", l.objs.TraceExecve, nil)
	if err != nil {
		return fmt.Errorf("attaching execve tracepoint: %w", err)
	}
	l.links = append(l.links, execveLink)

	// Attach setuid tracepoint
	setuidLink, err := link.Tracepoint("syscalls", "sys_enter_setuid", l.objs.TraceSetuid, nil)
	if err != nil {
		return fmt.Errorf("attaching setuid tracepoint: %w", err)
	}
	l.links = append(l.links, setuidLink)

	// Attach setgid tracepoint
	setgidLink, err := link.Tracepoint("syscalls", "sys_enter_setgid", l.objs.TraceSetgid, nil)
	if err != nil {
		return fmt.Errorf("attaching setgid tracepoint: %w", err)
	}
	l.links = append(l.links, setgidLink)

	return nil
}

// EventsMap returns the ring buffer map for reading events
func (l *Loader) EventsMap() *ebpf.Map {
	return l.objs.Events
}

// Close cleans up all resources
func (l *Loader) Close() error {
	for _, link := range l.links {
		link.Close()
	}
	return l.objs.Close()
}
