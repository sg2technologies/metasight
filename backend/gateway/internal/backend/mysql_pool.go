// MySQL counterpart to pool.go's Postgres PoolManager — same
// per-DataSource lazy-pool pattern, same /gateway/backend-credentials
// resolution, built on database/sql + go-sql-driver/mysql instead of pgx.
package backend

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/go-sql-driver/mysql" // registers the "mysql" database/sql driver
	"github.com/metasight/gateway/internal/client"
)

type MySQLPoolManager struct {
	mu       sync.Mutex
	pools    map[int]*sql.DB
	client   *client.Client
	maxConns int
}

func NewMySQLPoolManager(c *client.Client, maxConns int32) *MySQLPoolManager {
	return &MySQLPoolManager{
		pools:    make(map[int]*sql.DB),
		client:   c,
		maxConns: int(maxConns),
	}
}

// Get returns the pool for a DataSource, creating it lazily on first use.
func (m *MySQLPoolManager) Get(ctx context.Context, sourceID int) (*sql.DB, error) {
	m.mu.Lock()
	if db, ok := m.pools[sourceID]; ok {
		m.mu.Unlock()
		return db, nil
	}
	m.mu.Unlock()

	creds, err := m.client.BackendCredentials(sourceID)
	if err != nil {
		return nil, fmt.Errorf("resolving backend credentials for source %d: %w", sourceID, err)
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		creds.Username, creds.Password, creds.Host, creds.Port, creds.Database)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening backend pool for source %d: %w", sourceID, err)
	}
	db.SetMaxOpenConns(m.maxConns)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to backend for source %d: %w", sourceID, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.pools[sourceID]; ok {
		// Lost a race with another connection resolving the same pool first.
		db.Close()
		return existing, nil
	}
	m.pools[sourceID] = db
	return db, nil
}

// Invalidate drops a cached pool (e.g. after a credential rotation) so the
// next Get() re-resolves fresh credentials and opens fresh connections.
func (m *MySQLPoolManager) Invalidate(sourceID int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if db, ok := m.pools[sourceID]; ok {
		db.Close()
		delete(m.pools, sourceID)
	}
}

func (m *MySQLPoolManager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, db := range m.pools {
		db.Close()
	}
	m.pools = make(map[int]*sql.DB)
}
