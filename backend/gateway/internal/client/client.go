// Package client is the gateway's HTTP client for the MetaSight backend's
// /gateway/* endpoints — authenticate/prepare/audit (business logic, guard/
// policy/rewrite) and backend-credentials (resolving the real DB the
// gateway itself connects to). The gateway process never talks to the
// metadata DB directly; this is its only line back to the control plane.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	baseURL        string
	internalAPIKey string
	http           *http.Client
}

func New(baseURL, internalAPIKey string) *Client {
	return &Client{
		baseURL:        baseURL,
		internalAPIKey: internalAPIKey,
		http:           &http.Client{Timeout: 10 * time.Second},
	}
}

// GatewayError wraps any failure talking to the backend. Callers must fail
// closed on this — never fall back to executing the original, unrewritten
// query when the control plane is unreachable.
type GatewayError struct {
	Message string
}

func (e *GatewayError) Error() string { return e.Message }

func (c *Client) post(path string, body any, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return &GatewayError{Message: fmt.Sprintf("encoding request: %v", err)}
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return &GatewayError{Message: fmt.Sprintf("building request: %v", err)}
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return &GatewayError{Message: fmt.Sprintf("could not reach MetaSight backend: %v", err)}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		return &AuthError{Message: extractDetail(respBody)}
	}
	if resp.StatusCode >= 400 {
		return &GatewayError{Message: fmt.Sprintf("backend %s returned %d: %s", path, resp.StatusCode, string(respBody))}
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return &GatewayError{Message: fmt.Sprintf("unexpected response shape from %s: %v", path, err)}
		}
	}
	return nil
}

// AuthError distinguishes "the backend explicitly rejected this identity"
// (bad credential, expired, revoked) from a GatewayError (backend
// unreachable/broken) — session.go maps this to a Postgres auth-failure
// ErrorResponse specifically, not a generic internal error.
type AuthError struct {
	Message string
}

func (e *AuthError) Error() string { return e.Message }

func extractDetail(body []byte) string {
	var v struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &v); err == nil && v.Detail != "" {
		return v.Detail
	}
	return string(body)
}

// ── Authenticate ───────────────────────────────────────────────────────────

type AuthenticateResult struct {
	CredentialID int    `json:"credential_id"`
	DataSourceID int    `json:"data_source_id"`
	Role         string `json:"role"`
}

func (c *Client) Authenticate(username, secret string) (*AuthenticateResult, error) {
	var out AuthenticateResult
	err := c.post("/gateway/authenticate", map[string]string{
		"gateway_username": username,
		"secret":           secret,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Prepare ──────────────────────────────────────────────────────────────────

type PrepareResult struct {
	Allowed              bool              `json:"allowed"`
	Reason               *string           `json:"reason"`
	RewrittenQuery       *string           `json:"rewritten_query"`
	Tables               []string          `json:"tables"`
	DeniedColumns        []string          `json:"denied_columns"`
	MaskedColumns        []string          `json:"masked_columns"`
	ColumnPiiMap         map[string]string `json:"column_pii_map"`
	MaskingLevel         string            `json:"masking_level"`
	PolicyClassification *string           `json:"policy_classification"`
}

func (c *Client) Prepare(credentialID int, sql, applicationName, clientIP string) (*PrepareResult, error) {
	var out PrepareResult
	err := c.post("/gateway/prepare", map[string]any{
		"credential_id":    credentialID,
		"query":            sql,
		"application_name": applicationName,
		"client_ip":        clientIP,
	}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ── Audit ────────────────────────────────────────────────────────────────────

type AuditEntry struct {
	CredentialID    int
	Resource        string
	Action          string // defaults to "gateway_query" if empty; session.go sets "gateway_query_blocked" for denials
	OriginalQuery   string
	RewrittenQuery  string
	PolicyApplied   string
	RowCount        int
	ApplicationName string
	ClientIP        string
}

// Audit is fire-and-forget from the caller's perspective — call it in a
// goroutine. Errors are returned so the caller can log them, but must never
// block or fail the client's actual query.
func (c *Client) Audit(e AuditEntry) error {
	action := e.Action
	if action == "" {
		action = "gateway_query"
	}
	return c.post("/gateway/audit", map[string]any{
		"credential_id":    e.CredentialID,
		"resource":         e.Resource,
		"action":           action,
		"original_query":   e.OriginalQuery,
		"rewritten_query":  e.RewrittenQuery,
		"policy_applied":   e.PolicyApplied,
		"row_count":        e.RowCount,
		"application_name": e.ApplicationName,
		"client_ip":        e.ClientIP,
	}, nil)
}

// ── Backend credentials (internal-only) ───────────────────────────────────────

type BackendCredentials struct {
	DBType   string `json:"db_type"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

func (c *Client) BackendCredentials(sourceID int) (*BackendCredentials, error) {
	req, err := http.NewRequest(http.MethodGet,
		c.baseURL+"/gateway/backend-credentials?"+url.Values{"source_id": {fmt.Sprint(sourceID)}}.Encode(), nil)
	if err != nil {
		return nil, &GatewayError{Message: fmt.Sprintf("building request: %v", err)}
	}
	req.Header.Set("X-Internal-Key", c.internalAPIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &GatewayError{Message: fmt.Sprintf("could not reach MetaSight backend: %v", err)}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, &GatewayError{Message: fmt.Sprintf("backend-credentials returned %d: %s", resp.StatusCode, string(body))}
	}
	var out BackendCredentials
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &GatewayError{Message: fmt.Sprintf("unexpected response shape from backend-credentials: %v", err)}
	}
	return &out, nil
}
