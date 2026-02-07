package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/leemingi/ebpf-threat-detector/internal/config"
	"github.com/leemingi/ebpf-threat-detector/internal/detector"
	"github.com/leemingi/ebpf-threat-detector/pkg/events"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	// Check for root privileges
	if os.Geteuid() != 0 {
		log.Fatal("This program requires root privileges. Run with sudo.")
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("Warning: Could not load config file: %v. Using defaults.", err)
		cfg = config.Default()
	}

	log.Println("eBPF Threat Detector starting...")
	log.Printf("Config: execve=%v, setuid=%v, setgid=%v",
		cfg.Rules.Execve.Enabled,
		cfg.Rules.PrivilegeEscalation.MonitorSetuid,
		cfg.Rules.PrivilegeEscalation.MonitorSetgid,
	)

	// Create threat callback
	callback := func(event *events.Event, reason string) {
		log.Printf("[ALERT] THREAT DETECTED: %s - %s", reason, event)
	}

	// Create detector
	d, err := detector.New(cfg, callback)
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
