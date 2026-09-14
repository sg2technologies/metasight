package monitor

import (
	"fmt"
	"net"
	"time"

	"github.com/metasight/agent/pkg/config"
)

// genericMonitor only verifies TCP reachability — no session introspection.
type genericMonitor struct {
	addr string
}

func newGeneric(cfg *config.Config) (Monitor, error) {
	port := cfg.DBPort
	if port == "" {
		port = "5432"
	}
	addr := net.JoinHostPort(cfg.DBHost, port)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("generic TCP dial %s: %w", addr, err)
	}
	conn.Close()
	return &genericMonitor{addr: addr}, nil
}

func (g *genericMonitor) Sessions() ([]Session, error) {
	// Cannot introspect sessions without a known driver.
	// Return empty — the dashboard will show "reachable, no session data".
	return nil, nil
}

func (g *genericMonitor) Terminate(_ string) error {
	return fmt.Errorf("terminate not supported for generic monitor")
}

func (g *genericMonitor) Close() error { return nil }
