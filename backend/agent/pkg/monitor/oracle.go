package monitor

import (
	"database/sql"
	"fmt"
	"net"
	"strings"

	_ "github.com/sijms/go-ora/v2"

	"github.com/metasight/agent/pkg/config"
)

type oracleMonitor struct {
	db *sql.DB
}

func newOracle(cfg *config.Config) (Monitor, error) {
	port := cfg.DBPort
	if port == "" {
		port = "1521"
	}
	service := cfg.DBName
	if service == "" {
		service = "ORCL"
	}

	dsn := fmt.Sprintf("oracle://%s:%s@%s/%s",
		cfg.DBUser, cfg.DBPassword,
		net.JoinHostPort(cfg.DBHost, port),
		service,
	)
	if cfg.DSN != "" {
		dsn = cfg.DSN
	}

	db, err := sql.Open("oracle", dsn)
	if err != nil {
		return nil, fmt.Errorf("oracle open: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("oracle ping: %w", err)
	}
	return &oracleMonitor{db: db}, nil
}

// Sessions queries v$session for all active user sessions.
// The monitoring user needs: GRANT SELECT ON V_$SESSION TO <user>;
//                            GRANT SELECT ON V_$SQL     TO <user>;
const oracleSessionSQL = `
SELECT
    TO_CHAR(s.sid) || ',' || TO_CHAR(s.serial#) AS pid,
    NVL(s.username, '(background)')              AS db_user,
    NVL(s.machine, '')                           AS machine,
    NVL(s.osuser, '')                            AS os_user,
    NVL(s.program, '')                           AS program,
    NVL(s.schemaname, '')                        AS schema_name,
    NVL(s.status, '')                            AS status,
    NVL(SUBSTR(q.sql_text, 1, 500), '')          AS sql_text
FROM v$session s
LEFT JOIN v$sql q ON s.sql_id = q.sql_id AND s.sql_child_number = q.child_number
WHERE s.type = 'USER'
  AND s.username IS NOT NULL
`

func (o *oracleMonitor) Sessions() ([]Session, error) {
	rows, err := o.db.Query(oracleSessionSQL)
	if err != nil {
		return nil, fmt.Errorf("oracle sessions query: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var pid, dbUser, machine, osUser, program, schema, status, sqlText string
		if err := rows.Scan(&pid, &dbUser, &machine, &osUser, &program, &schema, &status, &sqlText); err != nil {
			continue
		}
		clientIP := extractOracleHost(machine)
		sessions = append(sessions, Session{
			PID:        pid,
			DBUser:     dbUser,
			ClientAddr: machine,
			ClientIP:   clientIP,
			AppName:    program + " (os:" + osUser + ")",
			Database:   schema,
			CurrentSQL: strings.TrimSpace(sqlText),
			State:      strings.ToLower(status),
		})
	}
	return sessions, rows.Err()
}

func (o *oracleMonitor) Terminate(pid string) error {
	// pid is "sid,serial#"
	parts := strings.SplitN(pid, ",", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid oracle pid format (expected sid,serial#): %s", pid)
	}
	_, err := o.db.Exec(fmt.Sprintf("ALTER SYSTEM KILL SESSION '%s,%s' IMMEDIATE", parts[0], parts[1]))
	return err
}

func (o *oracleMonitor) Close() error {
	return o.db.Close()
}

// extractOracleHost pulls the IP from Oracle's machine field (e.g. "WORKGROUP\PC" or "192.168.1.10")
func extractOracleHost(machine string) string {
	if net.ParseIP(machine) != nil {
		return machine
	}
	// Oracle sometimes puts hostname — return as-is
	return machine
}
