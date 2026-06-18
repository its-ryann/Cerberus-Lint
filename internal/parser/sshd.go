package parser

import (
	"errors"
	"regexp"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// maxLineLength caps the maximum line length to prevent memory exhaustion.
const maxLineLength = 65536

var (
	// sshd patterns for common authentication log entries
	// Pattern: Failed password for [invalid user] <username> from <ip> port <port>
	failedPasswordRegex = regexp.MustCompile(`^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+)\s+from\s+([0-9a-fA-F.:]+)\s+port\s+\d+`)

	// Pattern: Accepted password for <username> from <ip> port <port>
	acceptedPasswordRegex = regexp.MustCompile(`^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Accepted password for (\S+)\s+from\s+([0-9a-fA-F.:]+)\s+port\s+\d+`)

	// Pattern: Connection closed by <ip> port <port>
	connectionClosedRegex = regexp.MustCompile(`^(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Connection closed by ([0-9a-fA-F.:]+)\s+port\s+\d+`)
)

// SSHDParser parses OpenSSH log entries.
type SSHDParser struct {
	year int // for parsing timestamps without year
}

// NewSSHDParser creates a new SSHD parser.
func NewSSHDParser() *SSHDParser {
	return &SSHDParser{
		year: time.Now().Year(),
	}
}

// Parse attempts to parse a raw log line into an Event.
func (p *SSHDParser) Parse(line string) (*event.Event, error) {
	// Defensive: cap line length
	if len(line) > maxLineLength {
		return nil, errors.New("line exceeds maximum length")
	}

	// Try failed password pattern
	if matches := failedPasswordRegex.FindStringSubmatch(line); matches != nil {
		timestamp, err := p.parseTimestamp(matches[1])
		if err != nil {
			return nil, err
		}
		return &event.Event{
			SourceIP:  matches[3],
			Username:  matches[2],
			Timestamp: timestamp,
			EventType: "failed_auth",
			Raw:       line,
		}, nil
	}

	// Try accepted password pattern
	if matches := acceptedPasswordRegex.FindStringSubmatch(line); matches != nil {
		timestamp, err := p.parseTimestamp(matches[1])
		if err != nil {
			return nil, err
		}
		return &event.Event{
			SourceIP:  matches[3],
			Username:  matches[2],
			Timestamp: timestamp,
			EventType: "successful_auth",
			Raw:       line,
		}, nil
	}

	// Try connection closed pattern
	if matches := connectionClosedRegex.FindStringSubmatch(line); matches != nil {
		timestamp, err := p.parseTimestamp(matches[1])
		if err != nil {
			return nil, err
		}
		return &event.Event{
			SourceIP:  matches[2],
			Username:  "",
			Timestamp: timestamp,
			EventType: "connection_closed",
			Raw:       line,
		}, nil
	}

	return nil, nil
}

// parseTimestamp parses syslog-style timestamp (e.g., "Jun 12 14:30:45")
func (p *SSHDParser) parseTimestamp(ts string) (time.Time, error) {
	// Parse the timestamp without year, add current year
	t, err := time.Parse("Jan 2 15:04:05", ts)
	if err != nil {
		return time.Time{}, err
	}
	return time.Date(p.year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC), nil
}