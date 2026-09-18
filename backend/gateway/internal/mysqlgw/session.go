// Package mysqlgw is the MySQL counterpart to internal/session's Postgres
// wire-protocol adapter — same shape (auth -> /gateway/prepare -> execute
// against a pooled real backend -> mask -> stream back), built on
// github.com/go-mysql-org/go-mysql/server, which already implements full
// MySQL client/server protocol framing (handshake, auth negotiation,
// COM_QUERY dispatch) — the net-new code here is business logic, not
// hand-rolled wire bytes, same principle internal/session documents for
// pgproto3.
//
// Auth model: MySQL's default challenge-response auth methods
// (caching_sha2_password, etc.) require the SERVER to know the plaintext
// password up front to validate the client's response — incompatible with
// our model, where only a salted hash is ever stored and validation happens
// via an HTTP call to /gateway/authenticate. So this adapter forces
// mysql_clear_password (the client sends the plaintext password directly,
// the same trust model as Postgres's cleartext-password-over-mandatory-TLS)
// and validates it the same way the Postgres gateway does. Some clients
// need to opt into mysql_clear_password explicitly (the `mysql` CLI needs
// --enable-cleartext-plugin) — documented in DEPLOYMENT.md, not a gap this
// package can paper over.
package mysqlgw

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	"github.com/metasight/gateway/internal/backend"
	"github.com/metasight/gateway/internal/client"
	"github.com/metasight/gateway/internal/masking"
	"github.com/metasight/gateway/internal/mysqltext"
)

const maxRows = 10_000 // mirrors internal/session's Postgres cap and backend/app/core/query_engine.py's

// ── Auth ─────────────────────────────────────────────────────────────────────

// AuthProvider implements both server.AuthenticationHandler and
// server.AuthenticationProvider. It's shared across all connections (one
// instance passed to server.NewServerWithAuth), so per-connection auth
// results are correlated via Conn.ConnectionID() — HandleQuery itself never
// sees *server.Conn (the Handler interface doesn't pass it), so the accept
// loop retrieves the result right after a successful NewCustomizedConn and
// hands it to that connection's own Handler instance.
type AuthProvider struct {
	apiClient *client.Client
	results   sync.Map // uint32 (ConnectionID) -> *client.AuthenticateResult
}

func NewAuthProvider(apiClient *client.Client) *AuthProvider {
	return &AuthProvider{apiClient: apiClient}
}

// GetCredential always defers to Authenticate below — the real check is an
// HTTP call, not a local password comparison, so there's nothing meaningful
// to return here except "yes, use clear-password auth for this user."
func (p *AuthProvider) GetCredential(_ string) (server.Credential, bool, error) {
	return server.Credential{Passwords: []string{"unused"}, AuthPluginName: gomysql.AUTH_CLEAR_PASSWORD}, true, nil
}

func (p *AuthProvider) OnAuthSuccess(_ *server.Conn) error   { return nil }
func (p *AuthProvider) OnAuthFailure(_ *server.Conn, _ error) {}

func (p *AuthProvider) Validate(authPluginName string) bool {
	return authPluginName == gomysql.AUTH_CLEAR_PASSWORD
}

func (p *AuthProvider) Authenticate(c *server.Conn, authPluginName string, clientAuthData []byte) error {
	if authPluginName != gomysql.AUTH_CLEAR_PASSWORD {
		return gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, "MetaSight Gateway: unsupported authentication method")
	}

	tlsConn, ok := c.Conn.Conn.(*tls.Conn)
	if !ok || !tlsConn.ConnectionState().HandshakeComplete {
		return gomysql.NewError(gomysql.ER_ACCESS_DENIED_ERROR, "MetaSight Gateway requires TLS")
	}

	password := clearPassword(clientAuthData)
	result, err := p.apiClient.Authenticate(c.GetUser(), password)
	if err != nil {
		return gomysql.NewError(gomysql.ER_ACCESS_DENIED_ERROR,
			fmt.Sprintf("Access denied for user '%s' (%v)", c.GetUser(), err))
	}
	p.results.Store(c.ConnectionID(), result)
	return nil
}

// TakeResult retrieves and clears the auth result stored by Authenticate
// for a connection — called once, right after NewCustomizedConn returns.
func (p *AuthProvider) TakeResult(connID uint32) (*client.AuthenticateResult, bool) {
	v, ok := p.results.LoadAndDelete(connID)
	if !ok {
		return nil, false
	}
	return v.(*client.AuthenticateResult), true
}

// clearPassword strips the trailing NUL some clients append to a
// mysql_clear_password response.
func clearPassword(data []byte) string {
	if n := len(data); n > 0 && data[n-1] == 0 {
		data = data[:n-1]
	}
	return string(data)
}

// ── Per-connection handler ────────────────────────────────────────────────────

// Handler implements server.Handler. One instance per accepted connection,
// constructed before NewCustomizedConn is called and populated with the
// auth result immediately after (see AuthProvider.TakeResult above).
type Handler struct {
	auth      *client.AuthenticateResult
	apiClient *client.Client
	pools     *backend.MySQLPoolManager
	clientIP  string
	appName   string
}

func NewHandler(apiClient *client.Client, pools *backend.MySQLPoolManager, clientIP string) *Handler {
	return &Handler{apiClient: apiClient, pools: pools, clientIP: clientIP}
}

// Finalize is called once, right after a successful NewCustomizedConn — the
// auth result and connection attributes (app name) are only known once the
// handshake completes, but this Handler had to exist before the handshake
// started (NewCustomizedConn takes it as a constructor argument).
func (h *Handler) Finalize(auth *client.AuthenticateResult, appName string) {
	h.auth = auth
	h.appName = appName
}

// UseDB is a no-op: like the Postgres gateway, a GatewayCredential is
// already scoped to exactly one DataSource, so the client-selected schema
// name is informational only, not a selector.
func (h *Handler) UseDB(_ string) error { return nil }

func (h *Handler) HandleFieldList(_ string, _ string) ([]*gomysql.Field, error) {
	return nil, gomysql.NewError(gomysql.ER_NOT_SUPPORTED_YET, "MetaSight Gateway: COM_FIELD_LIST is not supported")
}

// HandleStmtPrepare/Execute/Close: prepared statements are out of scope —
// same documented tradeoff as the Postgres gateway's Extended Query
// rejection (see DEPLOYMENT.md's "Current scope" section for this adapter).
func (h *Handler) HandleStmtPrepare(_ string) (int, int, any, error) {
	return 0, 0, nil, gomysql.NewError(gomysql.ER_NOT_SUPPORTED_YET,
		"MetaSight Gateway: prepared statements are not supported yet — use simple query execution")
}

func (h *Handler) HandleStmtExecute(_ any, _ string, _ []any) (*gomysql.Result, error) {
	return nil, gomysql.NewError(gomysql.ER_NOT_SUPPORTED_YET, "MetaSight Gateway: prepared statements are not supported yet")
}

func (h *Handler) HandleStmtClose(_ any) error { return nil }

func (h *Handler) HandleOtherCommand(cmd byte, _ []byte) error {
	return gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, fmt.Sprintf("MetaSight Gateway: command %d is not supported", cmd))
}

func (h *Handler) HandleQuery(query string) (*gomysql.Result, error) {
	ctx := context.Background()

	if hasMultipleStatements(query) {
		return nil, gomysql.NewError(gomysql.ER_SYNTAX_ERROR, "MetaSight Gateway: multiple statements in one query are not supported")
	}

	prep, err := h.apiClient.Prepare(h.auth.CredentialID, query, h.appName, h.clientIP)
	if err != nil {
		return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, "MetaSight Gateway: "+err.Error())
	}
	if !prep.Allowed {
		reason := "query denied by MetaSight policy"
		if prep.Reason != nil {
			reason = *prep.Reason
		}
		go h.auditBestEffort(client.AuditEntry{
			CredentialID: h.auth.CredentialID, Resource: "unknown", Action: "gateway_query_blocked",
			OriginalQuery: query, PolicyApplied: "DENY", ApplicationName: h.appName, ClientIP: h.clientIP,
		})
		return nil, gomysql.NewError(gomysql.ER_DBACCESS_DENIED_ERROR, reason)
	}

	db, err := h.pools.Get(ctx, h.auth.DataSourceID)
	if err != nil {
		return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, "MetaSight Gateway: "+err.Error())
	}

	rewrittenSQL := ""
	if prep.RewrittenQuery != nil {
		rewrittenSQL = *prep.RewrittenQuery
	}

	rows, err := db.QueryContext(ctx, rewrittenSQL)
	if err != nil {
		return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, err.Error())
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, err.Error())
	}

	piiMap := prep.ColumnPiiMap
	deniedSet := toSet(prep.DeniedColumns)

	values := make([][]any, 0, 64)
	rowCount := 0
	for rows.Next() {
		if rowCount >= maxRows {
			break
		}
		scanTargets := make([]any, len(columns))
		scanValues := make([]any, len(columns))
		for i := range scanValues {
			scanTargets[i] = &scanValues[i]
		}
		if err := rows.Scan(scanTargets...); err != nil {
			return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, err.Error())
		}

		textRow := make(map[string]*string, len(columns))
		for i, col := range columns {
			textRow[col] = mysqltext.Format(scanValues[i])
		}
		for col := range deniedSet {
			textRow[col] = nil
		}
		if len(prep.MaskedColumns) > 0 {
			masking.MaskRow(textRow, prep.MaskedColumns, piiMap, prep.MaskingLevel)
		}

		rowValues := make([]any, len(columns))
		for i, col := range columns {
			if v := textRow[col]; v != nil {
				rowValues[i] = *v
			} else {
				rowValues[i] = nil
			}
		}
		values = append(values, rowValues)
		rowCount++
	}
	if err := rows.Err(); err != nil {
		return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, err.Error())
	}

	resultset, err := gomysql.BuildSimpleTextResultset(columns, values)
	if err != nil {
		return nil, gomysql.NewError(gomysql.ER_UNKNOWN_ERROR, err.Error())
	}

	classification := ""
	if prep.PolicyClassification != nil {
		classification = *prep.PolicyClassification
	}
	go h.auditBestEffort(client.AuditEntry{
		CredentialID: h.auth.CredentialID, Resource: joinTables(prep.Tables), OriginalQuery: query,
		RewrittenQuery: rewrittenSQL, PolicyApplied: classification, RowCount: rowCount,
		ApplicationName: h.appName, ClientIP: h.clientIP,
	})

	return gomysql.NewResult(resultset), nil
}

func (h *Handler) auditBestEffort(e client.AuditEntry) {
	if err := h.apiClient.Audit(e); err != nil {
		log.Printf("mysql gateway: audit report failed (non-fatal): %v", err)
	}
}

// ── Small local helpers (duplicated from internal/session rather than
// shared — same rationale as pgtext/mysqltext both existing: tiny, protocol-
// adjacent, not worth a cross-package dependency) ────────────────────────────

func hasMultipleStatements(sqlText string) bool {
	trimmed := trimSpaceAndSemicolon(sqlText)
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] == ';' {
			return true
		}
	}
	return false
}

func trimSpaceAndSemicolon(s string) string {
	i, j := 0, len(s)
	for i < j && isSpace(s[i]) {
		i++
	}
	for j > i && isSpace(s[j-1]) {
		j--
	}
	if j > i && s[j-1] == ';' {
		j--
	}
	for j > i && isSpace(s[j-1]) {
		j--
	}
	return s[i:j]
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, it := range items {
		set[it] = struct{}{}
	}
	return set
}

func joinTables(tables []string) string {
	if len(tables) == 0 {
		return "unknown"
	}
	out := tables[0]
	for _, t := range tables[1:] {
		out += "," + t
	}
	return out
}

var _ server.Handler = (*Handler)(nil)
var _ server.AuthenticationHandler = (*AuthProvider)(nil)
var _ server.AuthenticationProvider = (*AuthProvider)(nil)
