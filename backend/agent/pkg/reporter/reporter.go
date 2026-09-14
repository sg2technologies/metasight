// Package reporter sends security events to the MetaSight server over HTTPS.
package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// Event is the payload sent to POST /security/activity.
type Event struct {
	AgentName  string `json:"agent_name"`
	DBType     string `json:"db_type"`
	SourceID   int    `json:"source_id,omitempty"`
	SessionPID string `json:"session_pid"`
	DBUser     string `json:"db_user"`
	ClientIP   string `json:"client_ip"`
	ClientAddr string `json:"client_addr"`
	AppName    string `json:"app_name"`
	Database   string `json:"database"`
	CurrentSQL string `json:"current_sql"`
	State      string `json:"state"`
	Blocked    bool   `json:"blocked"`
	Timestamp  string `json:"timestamp"`
}

// HeartbeatPayload is sent to POST /agents/heartbeat every 60 s.
type HeartbeatPayload struct {
	AgentName      string `json:"agent_name"`
	AgentIP        string `json:"agent_ip,omitempty"`
	DBType         string `json:"db_type"`
	SourceID       int    `json:"source_id,omitempty"`
	ActiveSessions int    `json:"active_sessions"`
	Timestamp      string `json:"timestamp"`
}

// LiveConfig is returned by GET /agents/config and applied without restart.
type LiveConfig struct {
	AllowedIPs    []string `json:"allowed_ips"`
	AllowedUsers  []string `json:"allowed_users"`
	BlockedOps    []string `json:"blocked_ops"`
	BlockMode     bool     `json:"block_mode"`
	AlertOnBypass bool     `json:"alert_on_bypass"`
}

// PAMEvent is sent to POST /pam/agent/events.
// The DB agent uses this to request a screenshot from the PAM endpoint agent
// that is running on the user's actual workstation (not the DB server).
type PAMEvent struct {
	AgentName string         `json:"agent_name"`
	EventType string         `json:"event_type"`
	SessionID string         `json:"session_id,omitempty"`
	RiskFlag  bool           `json:"risk_flag"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// Reporter holds the HTTP client and auth header.
type Reporter struct {
	serverURL string
	apiKey    string
	client    *http.Client
}

// New creates a Reporter.
func New(serverURL, apiKey string) *Reporter {
	if strings.HasPrefix(strings.ToLower(serverURL), "http://") {
		log.Printf("WARNING: MS_SERVER=%s is plaintext HTTP — the agent API key, "+
			"captured SQL text, and (in PAM mode) screenshots/clipboard content will "+
			"transit the network unencrypted. Set MS_SERVER=https://... in production.",
			serverURL)
	}
	return &Reporter{
		serverURL: serverURL,
		apiKey:    apiKey,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SendEvent posts a single unauthorized-access event to MetaSight.
func (r *Reporter) SendEvent(evt Event) error {
	evt.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return r.post("/security/activity", evt)
}

// SendPAMEvent sends an endpoint-level event (e.g. SCREENSHOT_REQUESTED) to
// the PAM agent event queue on the MetaSight backend.
// When event_type is SCREENSHOT_REQUESTED, the backend queues a trigger that
// the PAM agent (running on the user's workstation) polls for. On receiving
// the trigger the PAM agent captures the user's actual screen.
func (r *Reporter) SendPAMEvent(evt PAMEvent) error {
	return r.post("/pam/agent/events", evt)
}

// SendHeartbeat notifies MetaSight the agent is alive and reports its own IP.
func (r *Reporter) SendHeartbeat(hb HeartbeatPayload) error {
	if hb.AgentIP == "" {
		hb.AgentIP = outboundIP()
	}
	hb.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return r.post("/agents/heartbeat", hb)
}

// FetchLiveConfig pulls the current access-control policy from MetaSight.
// The agent calls this every 30 s so policy changes take effect without restart.
func (r *Reporter) FetchLiveConfig() (*LiveConfig, error) {
	req, err := http.NewRequest(http.MethodGet, r.serverURL+"/agents/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Key", r.apiKey)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("config fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("config fetch: server returned %d", resp.StatusCode)
	}
	var cfg LiveConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config decode: %w", err)
	}
	return &cfg, nil
}

// post sends the payload with a small bounded retry: transient failures
// (network errors, 5xx) get up to 2 retries with exponential backoff before
// giving up. This doesn't make delivery durable — there's still no on-disk
// queue, so an outage longer than ~3 seconds still drops the event — but it
// absorbs the common case of a brief blip instead of losing evidence on the
// first failed connection attempt.
func (r *Reporter) post(path string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	const maxAttempts = 3
	backoff := 250 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodPost, r.serverURL+path, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-Key", r.apiKey)

		resp, err := r.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP POST %s: %w", path, err)
		} else {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("server returned %d for %s", resp.StatusCode, path)
			} else if resp.StatusCode >= 400 {
				// Client error (bad payload, revoked key, ...) — retrying won't help.
				return fmt.Errorf("server returned %d for %s", resp.StatusCode, path)
			} else {
				return nil // success
			}
		}

		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return lastErr
}

// outboundIP returns the preferred outbound IP of this machine.
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
