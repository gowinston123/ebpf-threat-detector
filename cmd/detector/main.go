package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/leemingi/ebpf-threat-detector/internal/detector"
	"github.com/leemingi/ebpf-threat-detector/pkg/events"
)

func main() {
	// Check for root privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program requires root privileges. Run with sudo.")
	}

	log.Println("eBPF Threat Detector starting...")

	// Create threat callback
	callback := func(event *events.Event, reason string) {
		log.Printf("🚨 THREAT DETECTED: %s - %s", reason, event)
	}

	// Create detector
	d, err := detector.New(callback)
	if err != nil {
		log.Fatalf("Failed to create detector: %v", err)
	}
	defer d.Close()

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down...")
		cancel()
	}()

	// Start monitoring
	if err := d.Start(ctx); err != nil {
		log.Fatalf("Detector error: %v", err)
	}

	log.Println("Threat detector stopped.")
}
