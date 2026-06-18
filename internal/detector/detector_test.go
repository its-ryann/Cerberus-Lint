package detector

import (
	"testing"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

func TestDetector_Check(t *testing.T) {
	tests := []struct {
		name       string
		rules      []Rule
		eventCount int
		wantNil    bool
	}{
		{
			name: "below threshold",
			rules: []Rule{
				{Name: "brute_force", ThresholdCount: 10, Severity: "high", EventType: "brute_force_login"},
			},
			eventCount: 5,
			wantNil:    true,
		},
		{
			name: "at threshold",
			rules: []Rule{
				{Name: "brute_force", ThresholdCount: 10, Severity: "high", EventType: "brute_force_login"},
			},
			eventCount: 10,
			wantNil:    false,
		},
		{
			name: "above threshold",
			rules: []Rule{
				{Name: "brute_force", ThresholdCount: 10, Severity: "high", EventType: "brute_force_login"},
			},
			eventCount: 15,
			wantNil:    false,
		},
		{
			name: "deduplication",
			rules: []Rule{
				{Name: "brute_force", ThresholdCount: 10, Severity: "high", EventType: "brute_force_login"},
			},
			eventCount: 10,
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDetector(tt.rules)
			now := time.Now()
			events := []*event.Event{
				{SourceIP: "192.168.1.100", Username: "root", EventType: "failed_auth", Raw: "test"},
			}

			// First call
			incident := d.Check("192.168.1.100", tt.eventCount, []string{"root"}, now, now, events)
			if (incident == nil) != tt.wantNil {
				t.Errorf("First Check() = %v, wantNil %v", incident, tt.wantNil)
			}

			// Second call for deduplication test
			if tt.name == "deduplication" {
				incident2 := d.Check("192.168.1.100", 20, []string{"root", "admin"}, now, now, events)
				if incident2 != nil {
					t.Errorf("Second Check() should be nil due to deduplication, got %v", incident2)
				}
			}
		})
	}
}

func TestDetector_IncidentFields(t *testing.T) {
	d := NewDetector([]Rule{
		{Name: "brute_force", ThresholdCount: 10, Severity: "high", EventType: "brute_force_login"},
	})
	now := time.Now()
	events := []*event.Event{
		{SourceIP: "192.168.1.100", Username: "root", EventType: "failed_auth", Raw: "line1"},
		{SourceIP: "192.168.1.100", Username: "admin", EventType: "failed_auth", Raw: "line2"},
	}

	incident := d.Check("192.168.1.100", 10, []string{"root", "admin"}, now, now, events)
	if incident == nil {
		t.Fatal("Expected incident, got nil")
	}

	if incident.SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %v, want 1.0", incident.SchemaVersion)
	}
	if incident.SourceIP != "192.168.1.100" {
		t.Errorf("SourceIP = %v, want 192.168.1.100", incident.SourceIP)
	}
	if incident.Severity != "high" {
		t.Errorf("Severity = %v, want high", incident.Severity)
	}
	if incident.EventType != "brute_force_login" {
		t.Errorf("EventType = %v, want brute_force_login", incident.EventType)
	}
	if incident.AttemptCount != 10 {
		t.Errorf("AttemptCount = %v, want 10", incident.AttemptCount)
	}
	if len(incident.SampleRawLines) != 2 {
		t.Errorf("SampleRawLines length = %v, want 2", len(incident.SampleRawLines))
	}
}