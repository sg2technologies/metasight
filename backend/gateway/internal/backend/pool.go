// Package backend manages the gateway's own connection pools to the real
// Postgres DataSources it fronts. Clients authenticate to the gateway with
// a GatewayCredential (see internal/client) — they never see these
// credentials, which the gateway fetches from the MetaSight backend's
// internal-only /gateway/backend-credentials endpoint (itself backed by
// Vault/encrypted_config, same precedence pam_jit.py already uses).
package backend

import (
	"context"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/metasight/gateway/internal/client"
)

type PoolManager struct {
	mu       sync.Mutex
	pools    map[int]*pgxpool.Pool
	client   *client.Client
	maxConns int32
}

func NewPoolManager(c *client.Client, maxConns int32) *PoolManager {
	return &PoolManager{
		pools:    make(map[int]*pgxpool.Pool),
		client:   c,
		maxConns: maxConns,
	}
}

// Get returns the pool for a DataSource, creating it lazily on first use.
func (m *PoolManager) Get(ctx context.Context, sourceID int) (*pgxpool.Pool, error) {
	m.mu.Lock()
	if pool, ok := m.pools[sourceID]; ok {
		m.mu.Unlock()
		return pool, nil
	}
	m.mu.Unlock()

	creds, err := m.client.BackendCredentials(sourceID)
	if err != nil {
		return nil, fmt.Errorf("resolving backend credentials for source %d: %w", sourceID, err)
	}

	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s",
		creds.Host, creds.Port, creds.Username, creds.Password, creds.Database)

	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parsing backend connection config for source %d: %w", sourceID, err)
	}
	poolCfg.MaxConns = m.maxConns

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("opening backend pool for source %d: %w", sourceID, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.pools[sourceID]; ok {
		// Lost a race with another connection resolving the same pool first.
		pool.Close()
		return existing, nil
	}
	m.pools[sourceID] = pool
	return pool, nil
}

// Invalidate drops a cached pool (e.g. after a credential rotation) so the
// next Get() re-resolves fresh credentials and opens fresh connections.
func (m *PoolManager) Invalidate(sourceID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if pool, ok := m.pools[sourceID]; ok {
		pool.Close()
		delete(m.pools, sourceID)
	}
}

func (m *PoolManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = make(map[int]*pgxpool.Pool)
}
