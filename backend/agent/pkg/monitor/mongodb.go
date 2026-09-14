package monitor

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/metasight/agent/pkg/config"
)

type mongoMonitor struct {
	client *mongo.Client
}

func newMongoDB(cfg *config.Config) (Monitor, error) {
	dsn := cfg.DSN
	if dsn == "" {
		port := cfg.DBPort
		if port == "" {
			port = "27017"
		}
		if cfg.DBUser != "" {
			dsn = fmt.Sprintf("mongodb://%s:%s@%s:%s/%s?authSource=admin&connectTimeoutMS=5000",
				cfg.DBUser, cfg.DBPassword, cfg.DBHost, port, cfg.DBName)
		} else {
			dsn = fmt.Sprintf("mongodb://%s:%s/%s?connectTimeoutMS=5000",
				cfg.DBHost, port, cfg.DBName)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dsn))
	if err != nil {
		return nil, fmt.Errorf("mongodb connect: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("mongodb ping: %w", err)
	}
	return &mongoMonitor{client: client}, nil
}

// Sessions runs the currentOp admin command to list active operations.
func (m *mongoMonitor) Sessions() ([]Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := m.client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "currentOp", Value: 1},
		{Key: "active", Value: true},
	})
	if result.Err() != nil {
		return nil, fmt.Errorf("currentOp: %w", result.Err())
	}

	var doc struct {
		InProg []struct {
			OpID      interface{} `bson:"opid"`
			Client    string      `bson:"client"`
			EffUser   struct {
				User string `bson:"user"`
			} `bson:"effectiveUsers"`
			Op          string `bson:"op"`
			NS          string `bson:"ns"`
			Description string `bson:"desc"`
		} `bson:"inprog"`
	}
	if err := result.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode currentOp: %w", err)
	}

	var sessions []Session
	for _, op := range doc.InProg {
		s := Session{
			PID:        fmt.Sprintf("%v", op.OpID),
			DBUser:     op.EffUser.User,
			ClientAddr: op.Client,
			ClientIP:   extractIP(op.Client),
			AppName:    op.Description,
			Database:   op.NS,
			State:      op.Op,
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

func (m *mongoMonitor) Terminate(pid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := m.client.Database("admin").RunCommand(ctx, bson.D{
		{Key: "killOp", Value: 1},
		{Key: "op", Value: pid},
	})
	return result.Err()
}

func (m *mongoMonitor) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.client.Disconnect(ctx)
}
