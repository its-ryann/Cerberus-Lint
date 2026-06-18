package parser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSSHDParser_GoldenFile(t *testing.T) {
	// Read the sample log file
	logPath := filepath.Join("..", "..", "testdata", "sshd_sample.log")
	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read golden log file: %v", err)
	}

	p := NewSSHDParser()
	events := make([]map[string]interface{}, 0)

	// Parse each line
	lines := splitLines(string(logContent))
	for _, line := range lines {
		evt, err := p.Parse(line)
		if err != nil {
			continue
		}
		if evt != nil {
			events = append(events, map[string]interface{}{
				"source_ip":  evt.SourceIP,
				"username":   evt.Username,
				"event_type": evt.EventType,
			})
		}
	}

	// Read expected output
	expectedPath := filepath.Join("..", "..", "testdata", "sshd_sample_expected.json")
	expectedContent, err := os.ReadFile(expectedPath)
	if err != nil {
		// If expected file doesn't exist, create it
		if os.IsNotExist(err) {
			data, _ := json.MarshalIndent(events, "", "  ")
			if err := os.WriteFile(expectedPath, data, 0644); err != nil {
				t.Logf("Created golden file: %s", expectedPath)
			}
			return
		}
		t.Fatalf("Failed to read expected file: %v", err)
	}

	// Compare
	var expected []map[string]interface{}
	if err := json.Unmarshal(expectedContent, &expected); err != nil {
		t.Fatalf("Failed to parse expected JSON: %v", err)
	}

	if len(events) != len(expected) {
		t.Errorf("Got %d events, expected %d", len(events), len(expected))
	}

	for i, evt := range events {
		if i >= len(expected) {
			break
		}
		if evt["source_ip"] != expected[i]["source_ip"] {
			t.Errorf("Event %d: source_ip = %v, expected %v", i, evt["source_ip"], expected[i]["source_ip"])
		}
		if evt["username"] != expected[i]["username"] {
			t.Errorf("Event %d: username = %v, expected %v", i, evt["username"], expected[i]["username"])
		}
		if evt["event_type"] != expected[i]["event_type"] {
			t.Errorf("Event %d: event_type = %v, expected %v", i, evt["event_type"], expected[i]["event_type"])
		}
	}
}

func splitLines(s string) []string {
	lines := make([]string, 0)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}