package aggregator

import (
	"testing"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

func TestAggregator_AddAndGet(t *testing.T) {
	agg := NewAggregator(30 * time.Second)
	defer agg.Stop()

	evt := &event.Event{
		SourceIP:  "192.168.1.100",
		Username:  "root",
		EventType: "failed_auth",
		Raw:       "test line",
	}

	agg.Add(evt)

	record := agg.Get("192.168.1.100")
	if record == nil {
		t.Fatal("Expected record, got nil")
	}

	if len(record.Events) != 1 {
		t.Errorf("Events length = %v, want 1", len(record.Events))
	}

	if _, ok := record.UsernameSet["root"]; !ok {
		t.Error("Expected 'root' in UsernameSet")
	}
}

func TestAggregator_GetAll(t *testing.T) {
	agg := NewAggregator(30 * time.Second)
	defer agg.Stop()

	agg.Add(&event.Event{SourceIP: "192.168.1.100", Username: "root", EventType: "failed_auth", Raw: "line1"})
	agg.Add(&event.Event{SourceIP: "192.168.1.101", Username: "admin", EventType: "failed_auth", Raw: "line2"})

	all := agg.GetAll()
	if len(all) != 2 {
		t.Errorf("GetAll() returned %d records, want 2", len(all))
	}
}

func TestAggregator_GetWindowStats(t *testing.T) {
	agg := NewAggregator(30 * time.Second)
	defer agg.Stop()

	agg.Add(&event.Event{SourceIP: "192.168.1.100", Username: "root", EventType: "failed_auth", Raw: "line1"})
	agg.Add(&event.Event{SourceIP: "192.168.1.100", Username: "admin", EventType: "failed_auth", Raw: "line2"})
	agg.Add(&event.Event{SourceIP: "192.168.1.100", Username: "root", EventType: "failed_auth", Raw: "line3"})

	count, usernames := agg.GetWindowStats("192.168.1.100")
	if count != 3 {
		t.Errorf("Count = %v, want 3", count)
	}
	if len(usernames) != 2 {
		t.Errorf("Usernames length = %v, want 2", len(usernames))
	}
}

func TestAggregator_EmptyIP(t *testing.T) {
	agg := NewAggregator(30 * time.Second)
	defer agg.Stop()

	count, usernames := agg.GetWindowStats("192.168.1.100")
	if count != 0 {
		t.Errorf("Count = %v, want 0", count)
	}
	if usernames != nil {
		t.Errorf("Usernames = %v, want nil", usernames)
	}
}