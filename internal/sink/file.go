package sink

import (
	"encoding/json"
	"os"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// FileSink writes incidents to a file as JSON lines.
type FileSink struct {
	file *os.File
}

// NewFileSink creates a new file sink.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &FileSink{file: f}, nil
}

// Write outputs an incident as a JSON line to the file.
func (s *FileSink) Write(incident *event.Incident) error {
	data, err := json.Marshal(incident)
	if err != nil {
		return err
	}
	_, err = s.file.Write(append(data, '\n'))
	return err
}

// Close closes the file.
func (s *FileSink) Close() error {
	return s.file.Close()
}