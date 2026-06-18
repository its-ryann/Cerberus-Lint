package sink

import "github.com/ryakikayi/cerberus-lint/internal/event"

// Sink defines the interface for outputting detected incidents.
type Sink interface {
	// Write outputs an incident to the sink.
	Write(incident *event.Incident) error
	// Close releases any resources held by the sink.
	Close() error
}

// SinkType identifies the type of sink.
type SinkType string

const (
	SinkStdout SinkType = "stdout"
	SinkFile   SinkType = "file"
	SinkSlack  SinkType = "slack"
)