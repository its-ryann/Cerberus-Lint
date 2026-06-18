package aggregator

import (
	"sync"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// EventRecord stores aggregated event data for a source IP.
type EventRecord struct {
	Events      []*event.Event
	LastSeen    time.Time
	UsernameSet map[string]struct{}
}

// Aggregator tracks events within a sliding time window.
type Aggregator struct {
	mu          sync.Mutex
	records     map[string]*EventRecord
	window      time.Duration
	cleanupTick time.Duration
	stopCh      chan struct{}
}

// NewAggregator creates a new aggregator with the specified window duration.
func NewAggregator(window time.Duration) *Aggregator {
	a := &Aggregator{
		records:     make(map[string]*EventRecord),
		window:      window,
		cleanupTick: window / 10, // cleanup every 1/10 of window
		stopCh:      make(chan struct{}),
	}
	go a.cleanupLoop()
	return a
}

// Add adds an event to the aggregator.
func (a *Aggregator) Add(evt *event.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := evt.SourceIP
	record, exists := a.records[key]
	if !exists {
		record = &EventRecord{
			Events:      make([]*event.Event, 0),
			UsernameSet: make(map[string]struct{}),
		}
		a.records[key] = record
	}

	record.Events = append(record.Events, evt)
	record.LastSeen = time.Now()
	if evt.Username != "" {
		record.UsernameSet[evt.Username] = struct{}{}
	}
}

// Get returns the event record for a source IP.
func (a *Aggregator) Get(sourceIP string) *EventRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.records[sourceIP]
}

// GetAll returns all current records.
func (a *Aggregator) GetAll() map[string]*EventRecord {
	a.mu.Lock()
	defer a.mu.Unlock()

	result := make(map[string]*EventRecord)
	for k, v := range a.records {
		result[k] = v
	}
	return result
}

// cleanupLoop periodically removes expired entries.
func (a *Aggregator) cleanupLoop() {
	ticker := time.NewTicker(a.cleanupTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.cleanup()
		case <-a.stopCh:
			return
		}
	}
}

// cleanup removes entries older than the window.
func (a *Aggregator) cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := time.Now().Add(-a.window)
	for key, record := range a.records {
		if record.LastSeen.Before(cutoff) {
			delete(a.records, key)
		}
	}
}

// Stop stops the cleanup goroutine.
func (a *Aggregator) Stop() {
	close(a.stopCh)
}

// GetWindowStats returns the count of events and unique usernames for a source IP.
func (a *Aggregator) GetWindowStats(sourceIP string) (eventCount int, usernames []string) {
	record := a.Get(sourceIP)
	if record == nil {
		return 0, nil
	}

	usernames = make([]string, 0, len(record.UsernameSet))
	for u := range record.UsernameSet {
		usernames = append(usernames, u)
	}
	return len(record.Events), usernames
}