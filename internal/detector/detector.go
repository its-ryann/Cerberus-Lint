package detector

import (
	"fmt"
	"sync"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// Rule defines a detection rule.
type Rule struct {
	Name           string
	ThresholdCount int
	Severity       string
	EventType      string // e.g., "failed_auth"
}

// Detector evaluates events against rules.
type Detector struct {
	rules    []Rule
	notified map[string]struct{}
	mu       sync.Mutex
}

// NewDetector creates a new detector with the given rules.
func NewDetector(rules []Rule) *Detector {
	return &Detector{
		rules:    rules,
		notified: make(map[string]struct{}),
	}
}

// Check evaluates an event record against all rules.
// Returns an incident if a rule is triggered, nil otherwise.
// Each source IP triggers only once per session (deduplication).
func (d *Detector) Check(sourceIP string, eventCount int, usernames []string, windowStart, windowEnd time.Time, sampleEvents []*event.Event) *event.Incident {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check if already notified for this IP
	if _, already := d.notified[sourceIP]; already {
		return nil
	}

	for _, rule := range d.rules {
		if eventCount >= rule.ThresholdCount {
			d.notified[sourceIP] = struct{}{}
			return &event.Incident{
				SchemaVersion:   "1.0",
				IncidentID:      fmt.Sprintf("%s-%d", sourceIP, time.Now().UnixNano()),
				DetectedAt:      time.Now().UTC().Format(time.RFC3339),
				SourceIP:        sourceIP,
				TargetUsernames: usernames,
				EventType:       rule.EventType,
				Severity:        rule.Severity,
				AttemptCount:    eventCount,
				WindowStart:     windowStart.UTC().Format(time.RFC3339),
				WindowEnd:       windowEnd.UTC().Format(time.RFC3339),
				SampleRawLines:  getSampleLines(sampleEvents),
			}
		}
	}
	return nil
}

// getSampleLines extracts up to 5 raw lines from events.
func getSampleLines(events []*event.Event) []string {
	maxSamples := 5
	if len(events) < maxSamples {
		maxSamples = len(events)
	}
	lines := make([]string, maxSamples)
	for i := 0; i < maxSamples; i++ {
		lines[i] = events[i].Raw
	}
	return lines
}