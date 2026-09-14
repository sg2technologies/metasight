package monitor

import (
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/metasight/agent/pkg/config"
)

type mssqlMonitor struct {
	db *sql.DB
}

func newMSSQL(cfg *config.Config) (Monitor, error) {
	dsn := cfg.DSN
	if dsn == "" {
		port := cfg.DBPort
		if port == "" {
			port = "1433"
		}
		dsn = fmt.Sprintf(
			"sqlserver://%s:%s@%s:%s?database=%s&connection+timeout=5",
			cfg.DBUser, cfg.DBPassword, cfg.DBHost, port, cfg.DBName,
		)
	}
	db, err := sql.Open("sqlserver", dsn)
	if err != nil {
		return nil, fmt.Errorf("mssql open: %w", err)
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("mssql ping: %w", err)
	}
	return &mssqlMonitor{db: db}, nil
}

// Sessions queries sys.dm_exec_sessions + sys.dm_exec_connections.
func (m *mssqlMonitor) Sessions() ([]Session, error) {
	const q = `
		SELECT
			s.session_id,
			s.login_name,
			COALESCE(c.client_net_address, ''),
			COALESCE(s.program_name, ''),
			COALESCE(DB_NAME(s.database_id), ''),
			COALESCE((SELECT TOP 1 text FROM sys.dm_exec_sql_text(r.sql_handle)), ''),
			COALESCE(s.status, '')
		FROM sys.dm_exec_sessions s
		LEFT JOIN sys.dm_exec_connections c ON c.session_id = s.session_id
		LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id
		WHERE s.is_user_process = 1
		  AND s.session_id <> @@SPID
	`
	rows, err := m.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("dm_exec_sessions query: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var sessionID int
		if err := rows.Scan(&sessionID, &s.DBUser, &s.ClientAddr, &s.AppName, &s.Database, &s.CurrentSQL, &s.State); err != nil {
			continue
		}
		s.PID = strconv.Itoa(sessionID)
		s.ClientIP = extractIP(s.ClientAddr)
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (m *mssqlMonitor) Terminate(pid string) error {
	_, err := m.db.Exec("KILL " + pid)
	return err
}

func (m *mssqlMonitor) Close() error {
	return m.db.Close()
}
