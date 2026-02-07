package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Logging LoggingConfig `yaml:"logging"`
	Alerts  AlertsConfig  `yaml:"alerts"`
	Rules   RulesConfig   `yaml:"rules"`
}

type LoggingConfig struct {
	Level    string `yaml:"level"`
	Format   string `yaml:"format"`
	Output   string `yaml:"output"`
	FilePath string `yaml:"file_path"`
}

type AlertsConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	LogFile    string `yaml:"log_file"`
}

type RulesConfig struct {
	Execve              ExecveRules              `yaml:"execve"`
	PrivilegeEscalation PrivilegeEscalationRules `yaml:"privilege_escalation"`
	Process             ProcessRules             `yaml:"process"`
}

type ExecveRules struct {
	Enabled             bool     `yaml:"enabled"`
	SuspiciousBinaries  []string `yaml:"suspicious_binaries"`
	AlertNonRoot        bool     `yaml:"alert_non_root"`
}

type PrivilegeEscalationRules struct {
	Enabled            bool `yaml:"enabled"`
	MonitorSetuid      bool `yaml:"monitor_setuid"`
	MonitorSetgid      bool `yaml:"monitor_setgid"`
	MonitorCapabilities bool `yaml:"monitor_capabilities"`
}

type ProcessRules struct {
	Enabled    bool     `yaml:"enabled"`
	IgnoreComm []string `yaml:"ignore_comm"`
}

// Load reads config from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Default returns default configuration
func Default() *Config {
	return &Config{
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
			Output: "stdout",
		},
		Alerts: AlertsConfig{
			Enabled: true,
		},
		Rules: RulesConfig{
			Execve: ExecveRules{
				Enabled:      true,
				AlertNonRoot: true,
				SuspiciousBinaries: []string{
					"/bin/sh", "/bin/bash", "/bin/nc",
					"/usr/bin/wget", "/usr/bin/curl",
				},
			},
			PrivilegeEscalation: PrivilegeEscalationRules{
				Enabled:       true,
				MonitorSetuid: true,
				MonitorSetgid: true,
			},
			Process: ProcessRules{
				Enabled: true,
			},
		},
	}
}
