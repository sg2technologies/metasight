package monitor

import (
	"database/sql"
	"fmt"
	"net"
	"strings"

	_ "github.com/lib/pq"

	"github.com/metasight/agent/pkg/config"
)

type postgresMonitor struct {
	db *sql.DB
}

func newPostgres(cfg *config.Config) (Monitor, error) {
	dsn := cfg.DSN
	if dsn == "" {
		port := cfg.DBPort
		if port == "" {
			port = "5432"
		}
		sslmode := cfg.DBSSLMode
		if sslmode == "" {
			sslmode = "disable"
		}
		dsn = fmt.Sprintf(
			"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s connect_timeout=5",
			cfg.DBHost, port, cfg.DBUser, cfg.DBPassword, cfg.DBName, sslmode,
		)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("postgres ping: %w", err)
	}
	return &postgresMonitor{db: db}, nil
}

// Sessions queries pg_stat_activity for all non-system, non-self connections.
func (m *postgresMonitor) Sessions() ([]Session, error) {
	const q = `
		SELECT
			pid::text,
			usename,
			COALESCE(client_addr::text, ''),
			COALESCE(application_name, ''),
			COALESCE(datname, ''),
			COALESCE(LEFT(query, 200), ''),
			COALESCE(state, '')
		FROM pg_stat_activity
		WHERE pid <> pg_backend_pid()
		  AND backend_type = 'client backend'
		  AND state IS NOT NULL
	`
	rows, err := m.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("pg_stat_activity query: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var clientAddr string
		if err := rows.Scan(&s.PID, &s.DBUser, &clientAddr, &s.AppName, &s.Database, &s.CurrentSQL, &s.State); err != nil {
			continue
		}
		s.ClientAddr = clientAddr
		s.ClientIP = extractIP(clientAddr)
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (m *postgresMonitor) Terminate(pid string) error {
	_, err := m.db.Exec(`SELECT pg_terminate_backend($1::int)`, pid)
	return err
}

func (m *postgresMonitor) Close() error {
	return m.db.Close()
}

// extractIP strips the port from "192.168.1.1:54321" or returns the value as-is.
func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	// IPv6 bracket form [::1]:port
	if strings.HasPrefix(addr, "[") {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			return host
		}
	}
	if strings.Contains(addr, ":") {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			return host
		}
	}
	return addr
}
