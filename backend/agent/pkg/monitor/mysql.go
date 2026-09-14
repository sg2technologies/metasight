package monitor

import (
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/go-sql-driver/mysql"

	"github.com/metasight/agent/pkg/config"
)

type mysqlMonitor struct {
	db *sql.DB
}

func newMySQL(cfg *config.Config) (Monitor, error) {
	dsn := cfg.DSN
	if dsn == "" {
		port := cfg.DBPort
		if port == "" {
			port = "3306"
		}
		// tls= maps our --db-sslmode onto the go-sql-driver's TLS modes:
		//   disable     -> false        (default — preserves existing installs)
		//   require     -> skip-verify  (encrypted, cert not validated)
		//   verify-full -> true         (encrypted, validated against system CA)
		tlsMode := "false"
		switch cfg.DBSSLMode {
		case "require":
			tlsMode = "skip-verify"
		case "verify-full":
			tlsMode = "true"
		}
		// DSN format: user:password@tcp(host:port)/dbname?timeout=5s
		dsn = fmt.Sprintf(
			"%s:%s@tcp(%s:%s)/%s?timeout=5s&parseTime=true&tls=%s",
			cfg.DBUser, cfg.DBPassword, cfg.DBHost, port, cfg.DBName, tlsMode,
		)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql open: %w", err)
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("mysql ping: %w", err)
	}
	return &mysqlMonitor{db: db}, nil
}

// Sessions queries INFORMATION_SCHEMA.PROCESSLIST for active connections.
func (m *mysqlMonitor) Sessions() ([]Session, error) {
	const q = `
		SELECT
			ID,
			USER,
			COALESCE(HOST, ''),
			COALESCE(DB, ''),
			COALESCE(INFO, ''),
			COALESCE(COMMAND, '')
		FROM INFORMATION_SCHEMA.PROCESSLIST
		WHERE ID <> CONNECTION_ID()
		  AND COMMAND != 'Sleep'
	`
	rows, err := m.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("processlist query: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var id int64
		var host string
		if err := rows.Scan(&id, &s.DBUser, &host, &s.Database, &s.CurrentSQL, &s.State); err != nil {
			continue
		}
		s.PID = strconv.FormatInt(id, 10)
		s.ClientAddr = host
		s.ClientIP = extractIP(host)
		s.AppName = "mysql-client"
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (m *mysqlMonitor) Terminate(pid string) error {
	_, err := m.db.Exec("KILL CONNECTION " + pid)
	return err
}

func (m *mysqlMonitor) Close() error {
	return m.db.Close()
}
