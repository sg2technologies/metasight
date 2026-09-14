package config

import (
	"flag"
	"log"
	"os"
	"strings"
	"time"
)

// Config holds all agent runtime configuration.
type Config struct {
	// MetaSight server
	ServerURL string
	APIKey    string

	// What DB to monitor
	DBType string // postgres | mysql | mssql | mongodb
	DSN    string // full connection string, or built from parts below

	// Connection parts (alternative to DSN)
	DBHost     string
	DBPort     string
	DBName     string
	DBUser     string
	DBPassword string
	// DBSSLMode controls TLS to the monitored database (postgres: sslmode
	// value; mysql: "disable"|anything-else maps to tls=skip-verify|true).
	// Default stays "disable" for backward compatibility with existing
	// installs whose DB side has no TLS configured — set to "require" or
	// "verify-full" in production wherever the DB supports it.
	DBSSLMode string

	// Authorization rules — sessions matching these are "safe".
	// CLI flags provide the initial values; the agent polls /agents/config
	// every 30 s so admins can update them live from the UI.
	AuthorizedUsers []string // e.g. ["metasight_gateway"]
	AuthorizedIPs   []string // CIDR or bare IP, e.g. ["10.0.0.0/8","192.168.1.50"]
	BlockedOps      []string // SQL operations to flag even from allowed IPs, e.g. ["DROP","GRANT"]
	AlertOnBypass   bool     // send alert when a bypass is detected

	// Behaviour
	Interval time.Duration
	Block    bool   // if true: kill unauthorized sessions (overridden by server config)
	LogFile  string // "" = stdout

	// Identity shown to MetaSight
	AgentName string
	SourceID  int // optional: MetaSight DataSource ID this agent guards
}

func Parse() *Config {
	cfg := &Config{}

	var modeDummy string
	flag.StringVar(&modeDummy, "mode", "db", "Agent mode (db or pam)")

	flag.StringVar(&cfg.ServerURL, "server", envOrDefault("MS_SERVER", "http://localhost:8000"), "MetaSight server URL")
	flag.StringVar(&cfg.APIKey, "api-key", envOrDefault("MS_API_KEY", ""), "MetaSight agent API key")

	flag.StringVar(&cfg.DBType, "db-type", envOrDefault("MS_DB_TYPE", "postgres"), "DB type: postgres|mysql|mssql|mongodb")
	flag.StringVar(&cfg.DSN, "dsn", envOrDefault("MS_DSN", ""), "Full DSN (optional, overrides host/port/etc.)")
	flag.StringVar(&cfg.DBHost, "db-host", envOrDefault("MS_DB_HOST", "localhost"), "DB host")
	flag.StringVar(&cfg.DBPort, "db-port", envOrDefault("MS_DB_PORT", ""), "DB port")
	flag.StringVar(&cfg.DBName, "db-name", envOrDefault("MS_DB_NAME", ""), "DB name")
	flag.StringVar(&cfg.DBUser, "db-user", envOrDefault("MS_DB_USER", ""), "DB user (gateway must have read on pg_stat_activity / processlist)")
	flag.StringVar(&cfg.DBPassword, "db-password", envOrDefault("MS_DB_PASSWORD", ""), "DB password")
	flag.StringVar(&cfg.DBSSLMode, "db-sslmode", envOrDefault("MS_DB_SSLMODE", "disable"), "TLS mode for the DB connection (postgres: disable|require|verify-full). Set to require/verify-full in production.")

	authUsers  := flag.String("authorized-users", envOrDefault("MS_AUTHORIZED_USERS", "metasight_gateway"), "Comma-separated list of authorized DB usernames")
	authIPs    := flag.String("authorized-ips", envOrDefault("MS_AUTHORIZED_IPS", ""), "Comma-separated CIDR list of authorized client IPs (empty = any IP)")
	blockedOps := flag.String("blocked-ops", envOrDefault("MS_BLOCKED_OPS", "DROP,TRUNCATE,GRANT,REVOKE"), "Comma-separated SQL ops to flag even from allowed IPs")

	flag.DurationVar(&cfg.Interval, "interval", 30*time.Second, "Poll interval (e.g. 30s, 1m)")
	flag.BoolVar(&cfg.Block, "block", false, "If true, automatically terminate unauthorized sessions")
	flag.BoolVar(&cfg.AlertOnBypass, "alert-on-bypass", true, "Alert when a bypass (direct connection outside allow-list) is detected")
	flag.StringVar(&cfg.LogFile, "log-file", "", "Log file path (default: stdout)")
	flag.StringVar(&cfg.AgentName, "name", hostname(), "Agent name shown in MetaSight")
	flag.IntVar(&cfg.SourceID, "source-id", 0, "MetaSight DataSource ID this agent guards (optional)")

	flag.Parse()

	// Validate required fields
	if cfg.APIKey == "" {
		log.Fatal("--api-key is required. Generate one from MetaSight Settings → Security.")
	}
	if cfg.DBType == "" {
		log.Fatal("--db-type is required.")
	}

	cfg.AuthorizedUsers = splitComma(*authUsers)
	cfg.AuthorizedIPs   = splitComma(*authIPs)
	cfg.BlockedOps      = splitComma(*blockedOps)

	return cfg
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
