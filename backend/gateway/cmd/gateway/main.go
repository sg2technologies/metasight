// MetaSight Gateway — a real database wire-protocol listener applications,
// users, and BI/ETL tools connect through with their normal driver/psql/
// mysql client, no code change required (unlike metasight_sdk, which stays
// an Enterprise-only fallback for engines/apps that can't sit behind a
// network gateway, e.g. Oracle). One process, one credential/audit surface,
// one listener per supported protocol — the MySQL listener only starts if
// GATEWAY_MYSQL_PORT is set (see internal/config).
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"

	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	mysqlserver "github.com/go-mysql-org/go-mysql/server"
	"github.com/metasight/gateway/internal/backend"
	"github.com/metasight/gateway/internal/client"
	"github.com/metasight/gateway/internal/config"
	"github.com/metasight/gateway/internal/mysqlgw"
	"github.com/metasight/gateway/internal/session"
)

func main() {
	cfg := config.Load()

	if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
		log.Fatal("GATEWAY_TLS_CERT and GATEWAY_TLS_KEY must be set — TLS is mandatory (see DEPLOYMENT.md)")
	}
	if cfg.InternalAPIKey == "" {
		log.Fatal("GATEWAY_INTERNAL_API_KEY must be set — required to resolve backend DB credentials")
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		log.Fatalf("loading TLS certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	apiClient := client.New(cfg.APIBaseURL, cfg.InternalAPIKey)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		servePostgres(ctx, cfg, tlsConfig, apiClient)
	}()

	if cfg.MySQLListenPort != 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveMySQL(ctx, cfg, tlsConfig, apiClient)
		}()
	} else {
		log.Println("GATEWAY_MYSQL_PORT not set — MySQL listener disabled")
	}

	wg.Wait()
}

func servePostgres(ctx context.Context, cfg config.Config, tlsConfig *tls.Config, apiClient *client.Client) {
	pools := backend.NewPoolManager(apiClient, cfg.MaxBackendConns)
	defer pools.CloseAll()

	addr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.ListenPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("postgres: listening on %s: %v", addr, err)
	}
	log.Printf("MetaSight Gateway (PostgreSQL) listening on %s", addr)

	go func() {
		<-ctx.Done()
		log.Println("MetaSight Gateway (PostgreSQL) shutting down...")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("postgres: accept error: %v", err)
				continue
			}
		}
		sess := session.New(conn, tlsConfig, apiClient, pools)
		go sess.Run(ctx)
	}
}

func serveMySQL(ctx context.Context, cfg config.Config, tlsConfig *tls.Config, apiClient *client.Client) {
	pools := backend.NewMySQLPoolManager(apiClient, cfg.MaxBackendConns)
	defer pools.CloseAll()

	authProvider := mysqlgw.NewAuthProvider(apiClient)
	mysqlSrv := mysqlserver.NewServerWithAuth(
		"8.0.11 (MetaSight Gateway)", gomysql.DEFAULT_COLLATION_ID,
		gomysql.AUTH_CLEAR_PASSWORD, nil, tlsConfig, authProvider,
	)

	addr := net.JoinHostPort(cfg.ListenHost, strconv.Itoa(cfg.MySQLListenPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("mysql: listening on %s: %v", addr, err)
	}
	log.Printf("MetaSight Gateway (MySQL) listening on %s", addr)

	go func() {
		<-ctx.Done()
		log.Println("MetaSight Gateway (MySQL) shutting down...")
		listener.Close()
	}()

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("mysql: accept error: %v", err)
				continue
			}
		}
		go handleMySQLConn(ctx, rawConn, mysqlSrv, authProvider, apiClient, pools)
	}
}

func handleMySQLConn(
	ctx context.Context,
	rawConn net.Conn,
	mysqlSrv *mysqlserver.Server,
	authProvider *mysqlgw.AuthProvider,
	apiClient *client.Client,
	pools *backend.MySQLPoolManager,
) {
	clientIP := ""
	if addr, ok := rawConn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	handler := mysqlgw.NewHandler(apiClient, pools, clientIP)
	conn, err := mysqlSrv.NewCustomizedConn(rawConn, authProvider, handler)
	if err != nil {
		// NewCustomizedConn already closed rawConn and sent an error packet
		// on handshake/auth failure — nothing more to do.
		log.Printf("mysql gateway: handshake failed (peer=%s): %v", clientIP, err)
		return
	}
	defer conn.Close()

	authResult, ok := authProvider.TakeResult(conn.ConnectionID())
	if !ok {
		log.Printf("mysql gateway: no auth result for connection %d (peer=%s) — closing", conn.ConnectionID(), clientIP)
		return
	}
	handler.Finalize(authResult, conn.Attributes()["program_name"])

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err := conn.HandleCommand(); err != nil {
			return
		}
	}
}
