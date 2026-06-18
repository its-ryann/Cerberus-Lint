package parser

import "github.com/ryakikayi/cerberus-lint/internal/event"

// Parser defines the interface for parsing log lines into normalized events.
type Parser interface {
	// Parse attempts to parse a raw log line into an Event.
	// Returns nil if the line is not recognized as belonging to this parser.
	// Returns an error if the line is malformed but recognized.
	Parse(line string) (*event.Event, error)
}

// ParserType identifies the type of parser.
type ParserType string

const (
	ParserSSHD    ParserType = "sshd"
	ParserNginx   ParserType = "nginx"
	ParserGeneric ParserType = "generic"
)