package events

import (
	"fmt"
	"time"
)

const (
	EventExecve = 1
	EventSetuid = 2
	EventSetgid = 3
	EventClone  = 4
)

// Event represents a security event from eBPF
type Event struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	EventType uint32
	Timestamp uint64
	Comm      [16]byte
	Filename  [256]byte
}

// GetComm returns the command name as a string
func (e *Event) GetComm() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// GetFilename returns the filename as a string
func (e *Event) GetFilename() string {
	for i, b := range e.Filename {
		if b == 0 {
			return string(e.Filename[:i])
		}
	}
	return string(e.Filename[:])
}

// GetEventTypeName returns human-readable event type
func (e *Event) GetEventTypeName() string {
	switch e.EventType {
	case EventExecve:
		return "EXECVE"
	case EventSetuid:
		return "SETUID"
	case EventSetgid:
		return "SETGID"
	case EventClone:
		return "CLONE"
	default:
		return "UNKNOWN"
	}
}

// GetTime converts kernel timestamp to time.Time
func (e *Event) GetTime() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

func (e *Event) String() string {
	return fmt.Sprintf("[%s] PID=%d UID=%d COMM=%s FILE=%s",
		e.GetEventTypeName(),
		e.PID,
		e.UID,
		e.GetComm(),
		e.GetFilename(),
	)
}
