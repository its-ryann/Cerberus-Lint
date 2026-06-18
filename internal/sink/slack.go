package sink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ryakikayi/cerberus-lint/internal/event"
)

// SlackSink sends incidents to a Slack webhook.
type SlackSink struct {
	webhookURL string
	client     *http.Client
}

// NewSlackSink creates a new Slack sink.
func NewSlackSink(webhookURL string) *SlackSink {
	return &SlackSink{
		webhookURL: webhookURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Write sends an incident to Slack.
func (s *SlackSink) Write(incident *event.Incident) error {
	payload := map[string]interface{}{
		"text":       fmt.Sprintf("🚨 Security Alert: %s from %s", incident.EventType, incident.SourceIP),
		"attachments": []map[string]interface{}{
			{
				"color": incident.Severity,
				"fields": []map[string]interface{}{
					{
						"title": "Source IP",
						"value": incident.SourceIP,
						"short": true,
					},
					{
						"title": "Attempt Count",
						"value": fmt.Sprintf("%d", incident.AttemptCount),
						"short": true,
					},
					{
						"title": "Usernames Targeted",
						"value": fmt.Sprintf("%v", incident.TargetUsernames),
						"short": true,
					},
					{
						"title": "Detected At",
						"value": incident.DetectedAt,
						"short": true,
					},
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := s.client.Post(s.webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// Close is a no-op for Slack sink.
func (s *SlackSink) Close() error {
	return nil
}