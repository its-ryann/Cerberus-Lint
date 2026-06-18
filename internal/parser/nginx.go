package parser

import (
	"errors"
	"regexp"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// nginx patterns for common log formats
// Combined log format: IP - - [date] "METHOD URL" status size "referer" "user-agent"
var (
	nginxCombinedRegex = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)`)
)

// NginxParser parses nginx access log entries.
type NginxParser struct {
	year int
}

// NewNginxParser creates a new nginx parser.
func NewNginxParser() *NginxParser {
	return &NginxParser{
		year: time.Now().Year(),
	}
}

// Parse attempts to parse a raw log line into an Event.
func (p *NginxParser) Parse(line string) (*event.Event, error) {
	// Defensive: cap line length
	if len(line) > maxLineLength {
		return nil, errors.New("line exceeds maximum length")
	}

	matches := nginxCombinedRegex.FindStringSubmatch(line)
	if matches == nil {
		return nil, nil
	}

	sourceIP := matches[1]
	timestamp, err := p.parseTimestamp(matches[2])
	if err != nil {
		return nil, err
	}

	_ = matches[3] // method, for future use
	statusCode := matches[5]

	// Determine event type based on status code
	eventType := "http_request"
	if statusCode == "401" || statusCode == "403" {
		eventType = "auth_failure"
	}

	return &event.Event{
		SourceIP:  sourceIP,
		Username:  "", // nginx doesn't log usernames in standard format
		Timestamp: timestamp,
		EventType: eventType,
		Raw:       line,
	}, nil
}

// parseTimestamp parses nginx log timestamp (e.g., "12/Jun/2026:14:30:45 +0000")
func (p *NginxParser) parseTimestamp(ts string) (time.Time, error) {
	// Remove timezone offset for parsing
	// Format: 12/Jun/2026:14:30:45 +0000
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", ts)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}