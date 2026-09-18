// Package session implements the per-connection Postgres wire-protocol
// state machine: TLS-mandatory startup handshake, cleartext-password auth
// against a GatewayCredential, then a Simple Query loop. Built on
// github.com/jackc/pgx/v5/pgproto3, which already implements full
// frontend/backend message encoding/decoding (including Extended Query
// messages, so rejecting them is a type switch, not hand-rolled byte
// matching) — the net-new code here is business logic (auth, policy
// call-backs, masking, connection pooling), not protocol framing.
package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/metasight/gateway/internal/backend"
	"github.com/metasight/gateway/internal/client"
	"github.com/metasight/gateway/internal/masking"
	"github.com/metasight/gateway/internal/pgtext"
)

const maxRows = 10_000 // mirrors backend/app/core/query_engine.py's row cap

var paramStatus = map[string]string{
	"server_version":              "18.0 (MetaSight Gateway)",
	"client_encoding":             "UTF8",
	"DateStyle":                   "ISO, MDY",
	"TimeZone":                    "UTC",
	"integer_datetimes":           "on",
	"standard_conforming_strings": "on",
}

type Session struct {
	rawConn   net.Conn
	tlsConfig *tls.Config
	apiClient *client.Client
	pools     *backend.PoolManager
}

func New(conn net.Conn, tlsConfig *tls.Config, apiClient *client.Client, pools *backend.PoolManager) *Session {
	return &Session{rawConn: conn, tlsConfig: tlsConfig, apiClient: apiClient, pools: pools}
}

func (s *Session) Run(ctx context.Context) {
	defer s.rawConn.Close()
	if err := s.handle(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("gateway session error (peer=%s): %v", s.rawConn.RemoteAddr(), err)
	}
}

func (s *Session) handle(ctx context.Context) error {
	startupBackend := pgproto3.NewBackend(s.rawConn, s.rawConn)
	firstMsg, err := startupBackend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("reading startup packet: %w", err)
	}

	if _, ok := firstMsg.(*pgproto3.CancelRequest); ok {
		// Cancel Request is out of scope for this MVP — the client expects
		// no reply either way; just close.
		return nil
	}

	if _, ok := firstMsg.(*pgproto3.SSLRequest); !ok {
		startupBackend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL", Code: "08P01",
			Message: "MetaSight Gateway requires TLS — send SSLRequest before StartupMessage",
		})
		startupBackend.Flush()
		return errors.New("client did not request TLS")
	}

	if _, err := s.rawConn.Write([]byte{'S'}); err != nil {
		return fmt.Errorf("sending SSL accept byte: %w", err)
	}

	tlsConn := tls.Server(s.rawConn, s.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	pgBackend := pgproto3.NewBackend(tlsConn, tlsConn)
	secondMsg, err := pgBackend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("reading post-TLS startup message: %w", err)
	}
	startup, ok := secondMsg.(*pgproto3.StartupMessage)
	if !ok {
		pgBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "08004", Message: "expected StartupMessage after TLS upgrade"})
		pgBackend.Flush()
		return errors.New("expected StartupMessage after TLS upgrade")
	}

	username := startup.Parameters["user"]
	applicationName := startup.Parameters["application_name"]
	clientIP := ""
	if addr, ok := tlsConn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	if err := pgBackend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return err
	}
	pgBackend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := pgBackend.Flush(); err != nil {
		return err
	}

	pwMsg, err := pgBackend.Receive()
	if err != nil {
		return fmt.Errorf("reading PasswordMessage: %w", err)
	}
	pw, ok := pwMsg.(*pgproto3.PasswordMessage)
	if !ok {
		pgBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: "expected PasswordMessage"})
		pgBackend.Flush()
		return errors.New("expected PasswordMessage")
	}

	auth, err := s.apiClient.Authenticate(username, pw.Password)
	if err != nil {
		var authErr *client.AuthError
		if errors.As(err, &authErr) {
			pgBackend.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL", Code: "28P01",
				Message: fmt.Sprintf("password authentication failed for user %q", username),
			})
		} else {
			pgBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "08006", Message: "MetaSight backend unreachable: " + err.Error()})
		}
		pgBackend.Flush()
		return err
	}

	pgBackend.Send(&pgproto3.AuthenticationOk{})
	for name, value := range paramStatus {
		pgBackend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}
	pgBackend.Send(&pgproto3.BackendKeyData{ProcessID: 0, SecretKey: []byte{0, 0, 0, 0}})
	pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := pgBackend.Flush(); err != nil {
		return err
	}

	inErrorRecovery := false
	for {
		msg, err := pgBackend.Receive()
		if err != nil {
			return fmt.Errorf("receiving message: %w", err)
		}

		switch m := msg.(type) {
		case *pgproto3.Query:
			inErrorRecovery = false
			s.handleQuery(ctx, pgBackend, auth, m.String, applicationName, clientIP)

		case *pgproto3.Sync:
			inErrorRecovery = false
			pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := pgBackend.Flush(); err != nil {
				return err
			}

		case *pgproto3.Terminate:
			return nil

		case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe, *pgproto3.Execute, *pgproto3.Close, *pgproto3.Flush:
			// Extended Query protocol — out of scope this MVP. Send exactly
			// one ErrorResponse, then silently discard further
			// Extended-protocol messages until the client's own Sync
			// arrives (matches Postgres's own error-recovery semantics),
			// so the connection doesn't desync and stays usable.
			if !inErrorRecovery {
				pgBackend.Send(&pgproto3.ErrorResponse{
					Severity: "ERROR", Code: "0A000",
					Message: "MetaSight Gateway: extended query protocol (prepared statements) is not supported yet — use simple query execution",
				})
				if err := pgBackend.Flush(); err != nil {
					return err
				}
				inErrorRecovery = true
			}

		default:
			if !inErrorRecovery {
				pgBackend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "0A000", Message: fmt.Sprintf("MetaSight Gateway: unsupported message type %T", m)})
				pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if err := pgBackend.Flush(); err != nil {
					return err
				}
			}
		}
	}
}

func (s *Session) handleQuery(ctx context.Context, pgBackend *pgproto3.Backend, auth *client.AuthenticateResult, sql, applicationName, clientIP string) {
	if hasMultipleStatements(sql) {
		s.sendError(pgBackend, "42601", "MetaSight Gateway: multiple statements in one query are not supported")
		return
	}

	prep, err := s.apiClient.Prepare(auth.CredentialID, sql, applicationName, clientIP)
	if err != nil {
		s.sendError(pgBackend, "XX000", "MetaSight Gateway: "+err.Error())
		return
	}
	if !prep.Allowed {
		reason := "query denied by MetaSight policy"
		if prep.Reason != nil {
			reason = *prep.Reason
		}
		s.sendError(pgBackend, "42501", reason)
		go s.auditBestEffort(client.AuditEntry{
			CredentialID: auth.CredentialID, Resource: "unknown", Action: "gateway_query_blocked",
			OriginalQuery: sql, PolicyApplied: "DENY", ApplicationName: applicationName, ClientIP: clientIP,
		})
		return
	}

	pool, err := s.pools.Get(ctx, auth.DataSourceID)
	if err != nil {
		s.sendError(pgBackend, "XX000", "MetaSight Gateway: "+err.Error())
		return
	}

	rewrittenSQL := ""
	if prep.RewrittenQuery != nil {
		rewrittenSQL = *prep.RewrittenQuery
	}

	rows, err := pool.Query(ctx, rewrittenSQL)
	if err != nil {
		s.sendPgError(pgBackend, err)
		return
	}
	defer rows.Close()

	fields := rows.FieldDescriptions()
	columns := make([]string, len(fields))
	rowDesc := pgproto3.RowDescription{Fields: make([]pgproto3.FieldDescription, len(fields))}
	for i, f := range fields {
		columns[i] = f.Name
		rowDesc.Fields[i] = pgproto3.FieldDescription{
			Name: []byte(f.Name), TableOID: 0, TableAttributeNumber: 0,
			DataTypeOID: f.DataTypeOID, DataTypeSize: f.DataTypeSize, TypeModifier: -1, Format: pgproto3.TextFormat,
		}
	}
	pgBackend.Send(&rowDesc)

	piiMap := prep.ColumnPiiMap
	deniedSet := toSet(prep.DeniedColumns)

	rowCount := 0
	for rows.Next() {
		if rowCount >= maxRows {
			break
		}
		values, err := rows.Values()
		if err != nil {
			s.sendPgError(pgBackend, err)
			return
		}

		textRow := make(map[string]*string, len(columns))
		for i, col := range values {
			textRow[columns[i]] = pgtext.Format(col)
		}
		for col := range deniedSet {
			textRow[col] = nil
		}
		if len(prep.MaskedColumns) > 0 {
			masking.MaskRow(textRow, prep.MaskedColumns, piiMap, prep.MaskingLevel)
		}

		dataRow := pgproto3.DataRow{Values: make([][]byte, len(columns))}
		for i, colName := range columns {
			if v := textRow[colName]; v != nil {
				dataRow.Values[i] = []byte(*v)
			}
		}
		pgBackend.Send(&dataRow)
		rowCount++

		if rowCount%200 == 0 {
			if err := pgBackend.Flush(); err != nil {
				return
			}
		}
	}
	if err := rows.Err(); err != nil {
		s.sendPgError(pgBackend, err)
		return
	}

	pgBackend.Send(&pgproto3.CommandComplete{CommandTag: []byte(fmt.Sprintf("SELECT %d", rowCount))})
	pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := pgBackend.Flush(); err != nil {
		return
	}

	classification := ""
	if prep.PolicyClassification != nil {
		classification = *prep.PolicyClassification
	}
	go s.auditBestEffort(client.AuditEntry{
		CredentialID: auth.CredentialID, Resource: joinTables(prep.Tables), OriginalQuery: sql,
		RewrittenQuery: rewrittenSQL, PolicyApplied: classification, RowCount: rowCount,
		ApplicationName: applicationName, ClientIP: clientIP,
	})
}

func (s *Session) sendError(pgBackend *pgproto3.Backend, sqlstate, message string) {
	pgBackend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: sqlstate, Message: message})
	pgBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	pgBackend.Flush()
}

func (s *Session) sendPgError(pgBackend *pgproto3.Backend, err error) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		s.sendError(pgBackend, pgErr.Code, pgErr.Message)
		return
	}
	s.sendError(pgBackend, "XX000", err.Error())
}

func (s *Session) auditBestEffort(e client.AuditEntry) {
	if err := s.apiClient.Audit(e); err != nil {
		log.Printf("gateway: audit report failed (non-fatal): %v", err)
	}
}

func hasMultipleStatements(sql string) bool {
	trimmed := trimSpaceAndSemicolon(sql)
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
