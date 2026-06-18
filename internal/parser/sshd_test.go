package parser

import (
	"testing"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

func TestSSHDParser_FailedPassword(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		want     *event.Event
		wantErr  bool
	}{
		{
			name: "failed password for root",
			line: "Jun 12 14:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22",
			want: &event.Event{
				SourceIP:  "192.168.1.100",
				Username:  "root",
				EventType: "failed_auth",
			},
			wantErr: false,
		},
		{
			name: "failed password for invalid user",
			line: "Jun 12 14:30:47 server sshd[12345]: Failed password for invalid user admin from 10.0.0.50 port 22",
			want: &event.Event{
				SourceIP:  "10.0.0.50",
				Username:  "admin",
				EventType: "failed_auth",
			},
			wantErr: false,
		},
		{
			name: "IPv6 address",
			line: "Jun 12 14:30:50 server sshd[12345]: Failed password for test from 2001:db8::1 port 22",
			want: &event.Event{
				SourceIP:  "2001:db8::1",
				Username:  "test",
				EventType: "failed_auth",
			},
			wantErr: false,
		},
		{
			name:    "malformed line",
			line:    "This is a malformed line that should be skipped",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "empty line",
			line:    "",
			want:    nil,
			wantErr: false,
		},
		{
			name: "accepted password",
			line: "Jun 12 14:30:48 server sshd[12345]: Accepted password for user1 from 192.168.1.10 port 22",
			want: &event.Event{
				SourceIP:  "192.168.1.10",
				Username:  "user1",
				EventType: "successful_auth",
			},
			wantErr: false,
		},
		{
			name: "connection closed",
			line: "Jun 12 14:30:49 server sshd[12345]: Connection closed by 192.168.1.100 port 22",
			want: &event.Event{
				SourceIP:  "192.168.1.100",
				Username:  "",
				EventType: "connection_closed",
			},
			wantErr: false,
		},
	}

	p := NewSSHDParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.Parse(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("Parse() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("Parse() = nil, want %v", tt.want)
				return
			}
			if got.SourceIP != tt.want.SourceIP {
				t.Errorf("SourceIP = %v, want %v", got.SourceIP, tt.want.SourceIP)
			}
			if got.Username != tt.want.Username {
				t.Errorf("Username = %v, want %v", got.Username, tt.want.Username)
			}
			if got.EventType != tt.want.EventType {
				t.Errorf("EventType = %v, want %v", got.EventType, tt.want.EventType)
			}
		})
	}
}

func TestSSHDParser_Timestamp(t *testing.T) {
	p := NewSSHDParser()
	line := "Jun 12 14:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22"
	evt, err := p.Parse(line)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	// Check that timestamp is in 2026 (current year)
	if evt.Timestamp.Year() != time.Now().Year() {
		t.Errorf("Timestamp year = %v, want %v", evt.Timestamp.Year(), time.Now().Year())
	}
	if evt.Timestamp.Month() != 6 {
		t.Errorf("Timestamp month = %v, want 6", evt.Timestamp.Month())
	}
	if evt.Timestamp.Day() != 12 {
		t.Errorf("Timestamp day = %v, want 12", evt.Timestamp.Day())
	}
}

func TestSSHDParser_Adversarial(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantNil    bool
		wantSource string
	}{
		{
			name:       "extremely long line",
			line:       string(make([]byte, 100000)), // 100KB line
			wantNil:    true,
			wantSource: "",
		},
		{
			name:       "null bytes in line - still parses but raw is preserved",
			line:       "Jun 12 14:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22\x00\x00\x00",
			wantNil:    false,
			wantSource: "192.168.1.100",
		},
		{
			name:       "unicode in username",
			line:       "Jun 12 14:30:45 server sshd[12345]: Failed password for 日本語 from 192.168.1.100 port 22",
			wantNil:    false,
			wantSource: "192.168.1.100",
		},
		{
			name:       "special chars in username - raw preserved for sanitization",
			line:       "Jun 12 14:30:45 server sshd[12345]: Failed password for user<script>alert(1)</script> from 192.168.1.100 port 22",
			wantNil:    false,
			wantSource: "192.168.1.100",
		},
		{
			name:       "truncated entry",
			line:       "Jun 12 14:30:45 server sshd[12345]: Failed password for",
			wantNil:    true,
			wantSource: "",
		},
		{
			name:       "log injection attempt - first line parsed",
			line:       "Jun 12 14:30:45 server sshd[12345]: Failed password for root from 192.168.1.100 port 22\nJun 12 14:30:46 server sshd[12345]: Accepted password for admin from 10.0.0.1 port 22",
			wantNil:    false,
			wantSource: "192.168.1.100",
		},
	}

	p := NewSSHDParser()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.Parse(tt.line)
			if tt.wantNil {
				// For adversarial input, we expect either nil or error
				if got != nil && err == nil {
					t.Errorf("Parse() = %v, want nil for adversarial input", got)
				}
				return
			}
			if err != nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf("Parse() = nil, want non-nil result")
				return
			}
			if got.SourceIP != tt.wantSource {
				t.Errorf("SourceIP = %v, want %v", got.SourceIP, tt.wantSource)
			}
		})
	}
}