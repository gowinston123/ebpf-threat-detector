package detector

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/leemingi/ebpf-threat-detector/internal/config"
	"github.com/leemingi/ebpf-threat-detector/internal/loader"
	"github.com/leemingi/ebpf-threat-detector/pkg/events"
)

// ThreatCallback is called when a potential threat is detected
type ThreatCallback func(event *events.Event, reason string)

// Detector monitors system events and detects threats
type Detector struct {
	loader   *loader.Loader
	config   *config.Config
	callback ThreatCallback
}

// New creates a new threat detector
func New(cfg *config.Config, callback ThreatCallback) (*Detector, error) {
	l, err := loader.New()
	if err != nil {
		return nil, fmt.Errorf("creating loader: %w", err)
	}

	return &Detector{
		loader:   l,
		config:   cfg,
		callback: callback,
	}, nil
}

// Start begins monitoring for threats
func (d *Detector) Start(ctx context.Context) error {
	if err := d.loader.Attach(); err != nil {
		return fmt.Errorf("attaching programs: %w", err)
	}

	reader, err := ringbuf.NewReader(d.loader.EventsMap())
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer reader.Close()

	log.Println("Threat detector started. Monitoring syscalls...")

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := reader.Read()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			var event events.Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Error parsing event: %v", err)
				continue
			}

			d.analyzeEvent(&event)
		}
	}
}

// analyzeEvent checks if an event is a potential threat
func (d *Detector) analyzeEvent(event *events.Event) {
	// Check if process should be ignored
	if d.shouldIgnore(event) {
		return
	}

	switch event.EventType {
	case events.EventExecve:
		if d.config.Rules.Execve.Enabled {
			d.analyzeExecve(event)
		}
	case events.EventSetuid:
		if d.config.Rules.PrivilegeEscalation.MonitorSetuid {
			d.analyzeSetuid(event)
		}
	case events.EventSetgid:
		if d.config.Rules.PrivilegeEscalation.MonitorSetgid {
			d.analyzeSetgid(event)
		}
	}
}

func (d *Detector) shouldIgnore(event *events.Event) bool {
	comm := event.GetEffectiveComm()
	for _, ignored := range d.config.Rules.Process.IgnoreComm {
		if comm == ignored {
			return true
		}
	}
	return false
}

func (d *Detector) analyzeExecve(event *events.Event) {
	filename := event.GetFilename()

	// Check against configured suspicious binaries
	for _, bin := range d.config.Rules.Execve.SuspiciousBinaries {
		if filename == bin {
			if d.config.Rules.Execve.AlertNonRoot && event.UID != 0 {
				log.Printf("[ALERT] Suspicious exec: %s", event)
				if d.callback != nil {
					d.callback(event, fmt.Sprintf("Suspicious binary execution: %s", filename))
				}
				return
			}
		}
	}

	log.Printf("[INFO] %s", event)
}

func (d *Detector) analyzeSetuid(event *events.Event) {
	if event.UID != 0 {
		log.Printf("[ALERT] Privilege escalation attempt: %s", event)
		if d.callback != nil {
			d.callback(event, "setuid called by non-root process")
		}
		return
	}
	log.Printf("[INFO] %s", event)
}

func (d *Detector) analyzeSetgid(event *events.Event) {
	if event.UID != 0 {
		log.Printf("[ALERT] Privilege escalation attempt: %s", event)
		if d.callback != nil {
			d.callback(event, "setgid called by non-root process")
		}
		return
	}
	log.Printf("[INFO] %s", event)
}

// Close cleans up resources
func (d *Detector) Close() error {
	return d.loader.Close()
}
