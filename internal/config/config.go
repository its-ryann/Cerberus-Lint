package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
	"github.com/ryakikayi/cerberus-lint/internal/detector"
	"github.com/ryakikayi/cerberus-lint/internal/parser"
	"github.com/ryakikayi/cerberus-lint/internal/sink"
)

// Config holds the application configuration.
type Config struct {
	LogFormat     string        `mapstructure:"log_format"`
	WindowSeconds int           `mapstructure:"window_seconds"`
	Rules         []RuleConfig  `mapstructure:"rules"`
	Sinks         []SinkConfig  `mapstructure:"sinks"`
}

// RuleConfig defines a rule configuration.
type RuleConfig struct {
	Name           string `mapstructure:"name"`
	ThresholdCount int    `mapstructure:"threshold_count"`
	Severity       string `mapstructure:"severity"`
	EventType      string `mapstructure:"event_type"`
}

// SinkConfig defines a sink configuration.
type SinkConfig struct {
	Type    string `mapstructure:"type"`
	Target  string `mapstructure:"target"`
	Enabled bool   `mapstructure:"enabled"`
}

// GetWindowDuration returns the window as a time.Duration.
func (c *Config) GetWindowDuration() time.Duration {
	if c.WindowSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.WindowSeconds) * time.Second
}

// GetRules converts config rules to detector rules.
func (c *Config) GetRules() []detector.Rule {
	rules := make([]detector.Rule, len(c.Rules))
	for i, r := range c.Rules {
		rules[i] = detector.Rule{
			Name:           r.Name,
			ThresholdCount: r.ThresholdCount,
			Severity:       r.Severity,
			EventType:      r.EventType,
		}
	}
	return rules
}

// GetParserType returns the parser type.
func (c *Config) GetParserType() parser.ParserType {
	return parser.ParserType(c.LogFormat)
}

// GetSinkTypes returns enabled sink types.
func (c *Config) GetSinkTypes() []sink.SinkType {
	types := make([]sink.SinkType, 0)
	for _, s := range c.Sinks {
		if s.Enabled {
			types = append(types, sink.SinkType(s.Type))
		}
	}
	return types
}

// Load loads configuration from a file path.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// Set defaults
	v.SetDefault("log_format", "sshd")
	v.SetDefault("window_seconds", 30)
	v.SetDefault("rules", []RuleConfig{
		{
			Name:           "brute_force",
			ThresholdCount: 10,
			Severity:       "high",
			EventType:      "brute_force_login",
		},
	})
	v.SetDefault("sinks", []SinkConfig{
		{
			Type:    "stdout",
			Enabled: true,
		},
	})

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		LogFormat:     "sshd",
		WindowSeconds: 30,
		Rules: []RuleConfig{
			{
				Name:           "brute_force",
				ThresholdCount: 10,
				Severity:       "high",
				EventType:      "brute_force_login",
			},
		},
		Sinks: []SinkConfig{
			{
				Type:    "stdout",
				Enabled: true,
			},
		},
	}
}