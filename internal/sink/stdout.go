package sink

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// StdoutSink writes incidents to stdout as JSON lines.
type StdoutSink struct {
	writer io.Writer
}

// NewStdoutSink creates a new stdout sink.
func NewStdoutSink() *StdoutSink {
	return &StdoutSink{
		writer: os.Stdout,
	}
}

// Write outputs an incident as a JSON line to stdout.
func (s *StdoutSink) Write(incident *event.Incident) error {
	data, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	_, err = s.writer.Write(append(data, '\n'))
	return err
}

// Close is a no-op for stdout.
func (s *StdoutSink) Close() error {
	return nil
}