package event

import (
	"time"
)

// Event represents a normalized log entry from any supported source.
type Event struct {
	SourceIP   string
	Username   string
	Timestamp  time.Time
	EventType  string
	Raw        string
}

// Incident represents a detected security incident.
type Incident struct {
	SchemaVersion   string   `json:"schema_version"`
	IncidentID      string   `json:"incident_id"`
	DetectedAt      string   `json:"detected_at"`
	SourceIP        string   `json:"source_ip"`
	TargetUsernames []string `json:"target_usernames"`
	EventType       string   `json:"event_type"`
	Severity        string   `json:"severity"`
	AttemptCount    int      `json:"attempt_count"`
	WindowStart     string   `json:"window_start"`
	WindowEnd       string   `json:"window_end"`
	SampleRawLines  []string `json:"sample_raw_lines"`
}