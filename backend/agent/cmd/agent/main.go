/*
MetaSight DB Agent — monitors database activity and reports unauthorized
direct-access sessions to the MetaSight control plane.

Access-control policy (allowed_ips, allowed_users, blocked_ops, block_mode)
is seeded from CLI flags but kept live by polling GET /agents/config
every 30 s. Changes made in the MetaSight UI take effect within one poll cycle
without restarting the agent.

Usage:
  agent-windows-amd64.exe --mode db \
    --server    https://metasight.company.com \
    --api-key   <key-from-metasight-agents-page> \
    --db-type   postgres \
    --db-host   localhost \
    --db-user   metasight_monitor \
    --db-password <password> \
    --db-name   your_db \
    --authorized-users metasight_gateway,app_readonly \
    --authorized-ips   10.0.0.0/8,192.168.1.50 \
    --blocked-ops      DROP,TRUNCATE,GRANT,REVOKE \
    --interval  30s
*/
package main

import (
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/metasight/agent/pkg/config"
	"github.com/metasight/agent/pkg/monitor"
	"github.com/metasight/agent/pkg/reporter"
)

const version = "1.1.0"

// livePolicy holds the mutable access-control policy updated from the server.
type livePolicy struct {
	mu            sync.RWMutex
	allowedIPs    []string
	allowedUsers  []string
	blockedOps    []string
	blockMode     bool
	alertOnBypass bool
}

func (p *livePolicy) apply(cfg *reporter.LiveConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedIPs    = cfg.AllowedIPs
	p.allowedUsers  = cfg.AllowedUsers
	p.blockedOps    = cfg.BlockedOps
	p.blockMode     = cfg.BlockMode
	p.alertOnBypass = cfg.AlertOnBypass
}

func (p *livePolicy) snapshot() (ips, users, ops []string, block, alert bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allowedIPs, p.allowedUsers, p.blockedOps, p.blockMode, p.alertOnBypass
}

func main() {
	mode := "db"
	for i := 0; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--mode" || os.Args[i] == "-mode" {
			mode = strings.ToLower(strings.TrimSpace(os.Args[i+1]))
			break
		}
	}

	if mode == "pam" {
		log.Fatal("--mode pam is an Enterprise-edition capability (endpoint screen/clipboard/USB " +
			"monitoring) and isn't built into this Community binary. See enterprise/agent/ " +
			"for the PAM endpoint agent.")
	}

	cfg := config.Parse()

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			log.Fatalf("cannot open log file %s: %v", cfg.LogFile, err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	log.Printf("MetaSight Agent v%s — db=%s host=%s interval=%s",
		version, cfg.DBType, cfg.DBHost, cfg.Interval)

	rep := reporter.New(cfg.ServerURL, cfg.APIKey)

	// Seed policy from CLI flags
	policy := &livePolicy{
		allowedIPs:    cfg.AuthorizedIPs,
		allowedUsers:  cfg.AuthorizedUsers,
		blockedOps:    cfg.BlockedOps,
		blockMode:     cfg.Block,
		alertOnBypass: cfg.AlertOnBypass,
	}

	// Initial config fetch (best-effort — don't fail startup if server is slow)
	if lc, err := rep.FetchLiveConfig(); err == nil {
		policy.apply(lc)
		log.Printf("Live config loaded: %d allowed IPs, %d allowed users, %d blocked ops, block=%v",
			len(lc.AllowedIPs), len(lc.AllowedUsers), len(lc.BlockedOps), lc.BlockMode)
	} else {
		log.Printf("Could not fetch live config (using CLI flags): %v", err)
	}

	// Connect to DB with retry
	var mon monitor.Monitor
	for attempt := 1; attempt <= 5; attempt++ {
		var err error
		mon, err = monitor.New(cfg)
		if err == nil {
			break
		}
		log.Printf("monitor init attempt %d/5: %v", attempt, err)
		if attempt == 5 {
			log.Fatalf("cannot connect to DB after 5 attempts")
		}
		time.Sleep(time.Duration(attempt*5) * time.Second)
	}
	defer mon.Close()
	log.Printf("Connected to %s — monitoring started", cfg.DBType)

	checkTicker  := time.NewTicker(cfg.Interval)
	hbTicker     := time.NewTicker(60 * time.Second)
	cfgTicker    := time.NewTicker(5 * time.Second) // live config poll (reduced to 5s for fast testing)
	defer checkTicker.Stop()
	defer hbTicker.Stop()
	defer cfgTicker.Stop()

	for {
		select {
		case <-checkTicker.C:
			sessions, _ := mon.Sessions()
			runCheck(sessions, policy, mon, rep, cfg)

		case <-hbTicker.C:
			sessions, _ := mon.Sessions()
			_ = rep.SendHeartbeat(reporter.HeartbeatPayload{
				AgentName:      cfg.AgentName,
				DBType:         cfg.DBType,
				SourceID:       cfg.SourceID,
				ActiveSessions: len(sessions),
			})

		case <-cfgTicker.C:
			if lc, err := rep.FetchLiveConfig(); err == nil {
				policy.apply(lc)
			} else {
				log.Printf("[config] poll failed (keeping current policy): %v", err)
			}
		}
	}
}

func runCheck(sessions []monitor.Session, policy *livePolicy, mon monitor.Monitor,
	rep *reporter.Reporter, cfg *config.Config) {

	allowedIPs, allowedUsers, blockedOps, blockMode, alertOnBypass := policy.snapshot()

	for _, sess := range sessions {
		userOK := isUserAllowed(sess.DBUser, allowedUsers)
		ipOK   := isIPAllowed(sess.ClientIP, allowedIPs)
		opRisk := isBlockedOp(sess.CurrentSQL, blockedOps)

		// Localhost connections by the postgres user are always authorized to avoid self-blocking the backend
		isLocalPostgres := strings.EqualFold(sess.DBUser, "postgres") &&
			(sess.ClientIP == "127.0.0.1" || sess.ClientIP == "::1" ||
			 strings.HasPrefix(sess.ClientIP, "127.0.0.1") || strings.HasPrefix(sess.ClientIP, "::1"))
		authorized := (userOK && ipOK) || isLocalPostgres

		if authorized && !opRisk {
			continue // session is clean
		}

		reason := describeViolation(userOK, ipOK, opRisk, sess)
		log.Printf("POLICY VIOLATION — %s | user=%q ip=%q db=%q pid=%s",
			reason, sess.DBUser, sess.ClientIP, sess.Database, sess.PID)

		if opRisk {
			// Do NOT take a screenshot on this server machine (uvicorn/DB host).
			// Instead, send a SCREENSHOT_REQUESTED event to the backend.
			// The PAM agent running on the user's workstation polls for these triggers
			// and captures the user's actual screen (Oracle SQL client, DBeaver, etc.).
			log.Println("[agent] Blocked query detected — requesting PAM agent screenshot from user workstation")
			_ = rep.SendPAMEvent(reporter.PAMEvent{
				AgentName: cfg.AgentName,
				EventType: "SCREENSHOT_REQUESTED",
				RiskFlag:  true,
				Payload: map[string]any{
					"reason":      "Blocked SQL operation detected by DB agent",
					"current_sql": sess.CurrentSQL,
					"db_user":     sess.DBUser,
					"client_ip":   sess.ClientIP,
					"database":    sess.Database,
				},
			})
		}

		if !alertOnBypass && !authorized {
			// Bypass alerts suppressed — still log but don't report
			continue
		}

		blocked := false
		if blockMode || (!authorized && blockMode) {
			if err := mon.Terminate(sess.PID); err != nil {
				log.Printf("  terminate pid=%s: %v", sess.PID, err)
			} else {
				log.Printf("  BLOCKED pid=%s", sess.PID)
				blocked = true
			}
		}

		_ = rep.SendEvent(reporter.Event{
			AgentName:  cfg.AgentName,
			DBType:     cfg.DBType,
			SourceID:   cfg.SourceID,
			SessionPID: sess.PID,
			DBUser:     sess.DBUser,
			ClientIP:   sess.ClientIP,
			ClientAddr: sess.ClientAddr,
			AppName:    sess.AppName,
			Database:   sess.Database,
			CurrentSQL: sess.CurrentSQL,
			State:      sess.State,
			Blocked:    blocked,
		})
	}
}

// isUserAllowed returns true if the DB user is in the allow-list (or list is empty).
func isUserAllowed(dbUser string, allowedUsers []string) bool {
	if len(allowedUsers) == 0 {
		return true
	}
	for _, u := range allowedUsers {
		if strings.EqualFold(dbUser, u) {
			return true
		}
	}
	return false
}

// isIPAllowed returns true if clientIP matches any entry in the CIDR allow-list.
// An empty list means "any IP is allowed".
func isIPAllowed(clientIP string, allowedIPs []string) bool {
	if len(allowedIPs) == 0 {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(clientIP))
	if ip == nil {
		return false
	}
	for _, entry := range allowedIPs {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(ip) {
				return true
			}
		} else {
			if net.ParseIP(entry).Equal(ip) {
				return true
			}
		}
	}
	return false
}

// isBlockedOp returns true when the current SQL starts with a blocked operation keyword.
//
// This is a best-effort keyword heuristic, not a SQL parser — it strips leading
// comments/whitespace/semicolons before matching (defeating the simplest bypass:
// `/* x */DROP TABLE t` or `-- note\nDROP TABLE t`), but it does NOT defeat a
// statement wrapped in a block (`DO $$ BEGIN EXECUTE 'DROP TABLE t'; END $$;`)
// or a dangerous statement that isn't the *first* one in a `;`-separated batch
// (`BEGIN; DROP TABLE t; COMMIT;`). Real enforcement against a direct-DB-access
// threat model belongs at the database grant level (don't grant DROP/TRUNCATE/
// GRANT/REVOKE to accounts this agent is meant to police) — this check is a
// tripwire for the common case, not a security boundary on its own.
func isBlockedOp(sql string, blockedOps []string) bool {
	if len(blockedOps) == 0 || sql == "" {
		return false
	}
	upper := strings.ToUpper(stripLeadingNoise(sql))
	for _, op := range blockedOps {
		if strings.HasPrefix(upper, strings.ToUpper(op)) {
			return true
		}
	}
	return false
}

// stripLeadingNoise removes leading whitespace, `--` line comments, `/* */`
// block comments, and stray leading semicolons, so a comment prepended to a
// blocked keyword doesn't hide it from isBlockedOp's prefix match.
func stripLeadingNoise(sql string) string {
	s := sql
	for {
		before := s
		s = strings.TrimLeft(s, " \t\r\n;")
		if strings.HasPrefix(s, "--") {
			if idx := strings.IndexByte(s, '\n'); idx >= 0 {
				s = s[idx+1:]
			} else {
				s = ""
			}
		} else if strings.HasPrefix(s, "/*") {
			if idx := strings.Index(s, "*/"); idx >= 0 {
				s = s[idx+2:]
			} else {
				s = ""
			}
		}
		if s == before {
			return s
		}
	}
}

func describeViolation(userOK, ipOK, opRisk bool, sess monitor.Session) string {
	switch {
	case !userOK && !ipOK:
		return "unauthorized user + IP"
	case !userOK:
		return "unauthorized DB user"
	case !ipOK:
		return "IP not in allow-list (possible bypass)"
	case opRisk:
		return "blocked SQL operation from authorized session"
	default:
		return "policy violation"
	}
}
