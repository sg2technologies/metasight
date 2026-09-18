// Package config reads gateway process configuration from the environment.
// Deliberately thin — everything about policy/masking rules lives on the
// MetaSight backend side; this process only needs enough to listen for
// clients and call back to that backend.
package config

import (
	"os"
	"strconv"
)

type Config struct {
	ListenHost      string
	ListenPort      int
	TLSCertPath     string
	TLSKeyPath      string
	APIBaseURL      string // MetaSight backend base URL, e.g. https://metasight.example.com
	InternalAPIKey  string // must match GATEWAY_INTERNAL_API_KEY on the backend
	MaxBackendConns int32

	// MySQLListenPort is 0 unless GATEWAY_MYSQL_PORT is explicitly set — the
	// MySQL listener is opt-in, started alongside the (always-on) Postgres
	// listener only when configured. Shares ListenHost/TLS/API/internal-key
	// config with Postgres; there's one gateway process, one set of
	// credentials/audit trail, regardless of how many protocols it fronts.
	MySQLListenPort int
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// Load builds a Config from environment variables, applying the same
// defaults documented in DEPLOYMENT.md.
func Load() Config {
	return Config{
		ListenHost:      getEnv("GATEWAY_HOST", "0.0.0.0"),
		ListenPort:      getEnvInt("GATEWAY_PORT", 6543),
		TLSCertPath:     os.Getenv("GATEWAY_TLS_CERT"),
		TLSKeyPath:      os.Getenv("GATEWAY_TLS_KEY"),
		APIBaseURL:      getEnv("GATEWAY_API_BASE_URL", "http://127.0.0.1:8000"),
		InternalAPIKey:  os.Getenv("GATEWAY_INTERNAL_API_KEY"),
		MaxBackendConns: int32(getEnvInt("GATEWAY_MAX_BACKEND_CONNS", 10)),
		MySQLListenPort: getEnvInt("GATEWAY_MYSQL_PORT", 0),
	}
}
