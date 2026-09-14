// Package monitor defines the interface every DB monitor must implement,
// plus the shared Session type returned by all monitors.
package monitor

import "github.com/metasight/agent/pkg/config"

// Session represents one active connection on the database server.
type Session struct {
	PID         string // process / connection ID (string because Mongo uses hex)
	DBUser      string // authenticated DB username
	ClientAddr  string // client IP:port or hostname
	ClientIP    string // extracted IP only
	AppName     string // application name / driver name
	Database    string // target database / schema
	CurrentSQL  string // current or last query (may be empty)
	State       string // idle, active, waiting …
}

// Monitor is the interface each DB-type implementation satisfies.
type Monitor interface {
	// Sessions returns all currently active connections on the server.
	Sessions() ([]Session, error)

	// Terminate kills the session identified by pid.
	// Returns nil if the session no longer exists.
	Terminate(pid string) error

	// Close releases any resources held by the monitor.
	Close() error
}

// New creates the right Monitor for the configured DB type.
func New(cfg *config.Config) (Monitor, error) {
	switch cfg.DBType {
	case "postgres", "postgresql", "redshift", "greenplum", "cockroach", "timescaledb":
		return newPostgres(cfg)
	case "mysql", "mariadb":
		return newMySQL(cfg)
	case "mssql", "azuresql", "sqlserver":
		return newMSSQL(cfg)
	case "mongodb":
		return newMongoDB(cfg)
	case "oracle", "oracledb":
		return newOracle(cfg)
	default:
		// Fallback: generic TCP port monitor (just checks reachability)
		return newGeneric(cfg)
	}
}
