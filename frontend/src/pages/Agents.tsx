import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Bot, Plus, RefreshCw, Copy, Check, Trash2, Key, RotateCcw,
  ChevronRight, Activity, AlertTriangle, Shield, Database,
  Cpu, Clipboard, Usb, Camera, Search, Terminal, X,
  Monitor, Server, Wifi, WifiOff, Clock, Zap, Eye, EyeOff,
  Download, BookOpen, ChevronDown, Circle, Lock, Network,
  UserCheck, Ban, ToggleLeft, ToggleRight, Info, MapPin, Play,
} from 'lucide-react';
import { api, isAdmin } from '../api';
import { cn } from '../lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Agent {
  id: number;
  name: string;
  db_type: string;
  mode: 'db' | 'pam';
  source_id: number | null;
  api_key: string | null;
  last_seen: string | null;
  active_sessions: number;
  created_at: string;
  online: boolean;
  events_today: number;
  running?: boolean;
  // Policy / access-control
  agent_ip: string | null;
  config_pulled_at: string | null;
  allowed_ips: string[];
  allowed_users: string[];
  blocked_ops: string[];
  block_mode: boolean;
  alert_on_bypass: boolean;
}

// DB-mode agents are registered/managed by Community (/agents) — plain
// database session monitoring, always available. PAM-mode agents (endpoint
// screen/clipboard/USB monitoring) are Enterprise-only (/pam/agents) — those
// calls simply fail if metasight_enterprise isn't installed alongside this
// backend, same as every other Enterprise-only API call in the app.
const agentBase = (mode: 'db' | 'pam') => (mode === 'pam' ? '/pam/agents' : '/agents');

interface AgentEvent {
  id: number;
  session_id: string | null;
  event_type: string;
  occurred_at: string;
  risk_flag: boolean;
  payload: Record<string, unknown> | null;
}

interface AgentStats {
  total_events: number;
  events_today: number;
  risk_events: number;
  risk_today: number;
  by_type_today: Record<string, number>;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtRelative(ts: string | null): string {
  if (!ts) return 'Never';
  const d = new Date(ts);
  const sec = Math.floor((Date.now() - d.getTime()) / 1000);
  if (sec < 5)   return 'Just now';
  if (sec < 60)  return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function fmtTs(ts: string): string {
  return new Date(ts).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

const DB_TYPES = ['postgres','mysql','mssql','oracle','mongodb'];

const EVENT_META: Record<string, { color: string; label: string }> = {
  CLIPBOARD:      { color: '#818CF8', label: 'Clipboard' },
  USB_INSERT:     { color: '#F59E0B', label: 'USB In' },
  USB_REMOVE:     { color: '#6B7280', label: 'USB Out' },
  APP_DETECTED:   { color: '#34D399', label: 'App' },
  APP_BLOCKED:    { color: '#EF4444', label: 'Blocked' },
  PROCESS_END:    { color: '#9CA3AF', label: 'Proc End' },
  DB_SESSION:     { color: '#38BDF8', label: 'DB Session' },
  UNAUTHORIZED:   { color: '#F87171', label: 'Unauth' },
  HEARTBEAT:      { color: '#4ADE80', label: 'Heartbeat' },
};

const MODE_CAPABILITIES = {
  db: [
    { icon: Database,  label: 'Session Monitoring',  desc: 'Captures direct database sessions in real-time.' },
    { icon: Search,    label: 'SQL Interception',     desc: 'Records queries, rows affected, execution time.' },
    { icon: Shield,    label: 'Unauthorized Detection', desc: 'Flags connections outside allowed users/IP ranges.' },
    { icon: Zap,       label: 'Auto-Termination',     desc: 'Instantly kills unauthorized connections (--block mode).' },
    { icon: Activity,  label: 'Heartbeat Telemetry',  desc: 'Reports active session counts and agent health.' },
    { icon: Server,    label: 'Multi-DB Support',     desc: 'PostgreSQL, MySQL, MSSQL, Oracle, and MongoDB.' },
  ],
  pam: [
    { icon: Camera,    label: 'Screen Recording',     desc: 'Captures periodic screenshots during sessions.' },
    { icon: Clipboard, label: 'Clipboard Monitoring', desc: 'Detects copy commands of sensitive structured data.' },
    { icon: Usb,       label: 'USB Detection & Block', desc: 'Identifies removable drives and optionally ejects.' },
    { icon: Cpu,       label: 'Process Monitoring',   desc: 'Flags DB administrative tools and remote shell programs.' },
    { icon: Shield,    label: 'Policy Enforcement',   desc: 'Enforces local session profiles during connections.' },
    { icon: Monitor,   label: 'Session Lifecycle',    desc: 'Auto-stops client monitoring when privileges expire.' },
  ],
};

// ── Copy Button ───────────────────────────────────────────────────────────────

function CopyBtn({ text, className = '' }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <button onClick={copy} className={cn("p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors", className)} title="Copy">
      {copied
        ? <Check size={13} className="text-emerald-500" />
        : <Copy size={13} className="text-slate-400 dark:text-slate-500 hover:text-slate-650 dark:hover:text-slate-200" />
      }
    </button>
  );
}

// ── Code Block ────────────────────────────────────────────────────────────────

function CodeBlock({ code, lang = '' }: { code: string; lang?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <div className="relative rounded-xl overflow-hidden border border-slate-250 dark:border-slate-800 bg-slate-950">
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-200/10 bg-slate-900/60">
        <span className="text-[10px] font-mono font-bold tracking-widest text-slate-500 uppercase">{lang || 'shell'}</span>
        <button onClick={copy} className="flex items-center gap-1.5 text-[11px] text-slate-400 hover:text-white transition-colors">
          {copied ? <><Check size={11} className="text-emerald-450" /><span className="text-emerald-450 font-medium">Copied!</span></> : <><Copy size={11} /><span>Copy</span></>}
        </button>
      </div>
      <pre className="px-4 py-4 text-xs font-mono text-slate-350 overflow-x-auto whitespace-pre-wrap leading-relaxed select-text">
        {code}
      </pre>
    </div>
  );
}

// ── Status Badge ──────────────────────────────────────────────────────────────

function StatusDot({ online }: { online: boolean }) {
  return (
    <span className="relative flex h-2.5 w-2.5">
      {online && (
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 bg-emerald-400" />
      )}
      <span className={cn("relative inline-flex rounded-full h-2.5 w-2.5", online ? "bg-emerald-500" : "bg-slate-400 dark:bg-slate-600")} />
    </span>
  );
}

// ── DB Type Badge ─────────────────────────────────────────────────────────────

const DB_COLORS: Record<string, [string, string]> = {
  postgres:  ['text-brand-blue', 'bg-blue-50 dark:bg-blue-950/20 border-blue-100 dark:border-blue-900/10'],
  mysql:     ['text-brand-orange', 'bg-amber-50 dark:bg-amber-950/20 border-amber-100 dark:border-amber-900/10'],
  mssql:     ['text-brand-indigo', 'bg-indigo-50 dark:bg-indigo-950/20 border-indigo-100 dark:border-indigo-900/10'],
  oracle:    ['text-brand-red', 'bg-rose-50 dark:bg-rose-950/20 border-rose-100 dark:border-rose-900/10'],
  mongodb:   ['text-brand-green', 'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-100 dark:border-emerald-900/10'],
  pam:       ['text-brand-purple', 'bg-purple-50 dark:bg-purple-950/20 border-purple-100 dark:border-purple-900/10'],
};

function TypeBadge({ type, mode }: { type: string; mode: string }) {
  const key = mode === 'pam' ? 'pam' : type;
  const [fg, bg] = DB_COLORS[key] ?? ['text-slate-600 dark:text-slate-400', 'bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700'];
  return (
    <span className={cn("text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border font-sans", fg, bg)}>
      {mode === 'pam' ? 'PAM Endpoint' : type}
    </span>
  );
}

// ── Register Modal ────────────────────────────────────────────────────────────

function RegisterModal({ onClose, onCreated, pamAvailable }: { onClose: () => void; onCreated: (a: Agent) => void; pamAvailable: boolean }) {
  const [name, setName]       = useState('');
  const [mode, setMode]       = useState<'db' | 'pam'>('db');
  const [dbType, setDbType]   = useState('postgres');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const [created, setCreated] = useState<Agent | null>(null);
  const [keyVisible, setKeyVisible] = useState(false);

  const submit = async () => {
    if (!name.trim()) { setError('Agent name is required'); return; }
    // Belt-and-suspenders: the picker below already prevents mode from
    // becoming 'pam' when PAM isn't available, but guard the actual
    // submit too rather than trust UI state alone against a stale prop.
    if (mode === 'pam' && !pamAvailable) {
      setError('PAM endpoint agents require MetaSight Enterprise — not installed on this server.');
      return;
    }
    setLoading(true); setError('');
    try {
      const { data } = await api.post<Agent>(`${agentBase(mode)}/`, {
        name: name.trim(),
        mode,
        db_type: mode === 'pam' ? 'pam' : dbType,
      });
      setCreated(data);
      onCreated(data);
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(msg || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 backdrop-blur-sm p-4 animate-fade-in">
      <div className="relative w-full max-w-lg rounded-2xl overflow-hidden shadow-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 animate-scale-up">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4.5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">Register MetaSight Agent</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Generate a secure credential key for an infrastructure agent</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
            <X size={16} />
          </button>
        </div>

        {!created ? (
          <div className="p-6 space-y-5">
            {/* Mode selector */}
            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-450 dark:text-slate-555 uppercase tracking-wider block">Agent Deployment Mode</label>
              <div className="grid grid-cols-2 gap-3">
                {(['db', 'pam'] as const).map(m => {
                  const locked = m === 'pam' && !pamAvailable;
                  return (
                    <button key={m} onClick={() => !locked && setMode(m)} disabled={locked}
                      title={locked ? 'Requires MetaSight Enterprise — not installed on this server' : undefined}
                      className={cn(
                        "p-4 rounded-xl text-left border transition-all duration-150",
                        locked
                          ? 'bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 opacity-50 cursor-not-allowed'
                          : mode === m
                            ? 'bg-brand-indigo/5 border-brand-indigo ring-1 ring-brand-indigo'
                            : 'bg-slate-50 hover:bg-slate-100/80 dark:bg-slate-900/60 dark:hover:bg-slate-850/60 border-slate-200 dark:border-slate-800'
                      )}>
                      <div className="flex items-center gap-2 mb-1.5">
                        {m === 'db' ? <Database size={15} className="text-brand-blue" /> : <Monitor size={15} className="text-brand-purple" />}
                        <span className="text-sm font-bold text-slate-900 dark:text-white">{m === 'db' ? 'Database Agent' : 'PAM endpoint'}</span>
                        {locked && <Lock size={11} className="text-slate-400 dark:text-slate-500 ml-auto" />}
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed font-medium">
                        {m === 'db'
                          ? 'Monitors native database direct logins, transactions & schemas.'
                          : locked
                            ? 'Enterprise only — not installed on this server.'
                            : 'Records user workspace, keystrokes, screenshots & blocklists.'}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Agent name */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Identifier Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && submit()}
                placeholder={mode === 'db' ? 'e.g. production-postgres-agent' : 'e.g. developer-jumpbox-pam'}
                className="premium-input font-medium"
              />
            </div>

            {/* DB type */}
            {mode === 'db' && (
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Target DBMS Engine</label>
                <div className="flex flex-wrap gap-2">
                  {DB_TYPES.map(t => (
                    <button key={t} onClick={() => setDbType(t)}
                      className={cn(
                        "px-3 py-1.5 rounded-lg text-xs font-bold border transition-all",
                        dbType === t
                          ? 'bg-brand-indigo/5 border-brand-indigo text-brand-indigo ring-1 ring-brand-indigo'
                          : 'bg-white dark:bg-slate-900 text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 border-slate-200 dark:border-slate-800'
                      )}>
                      {t}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {error && (
              <p className="text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1.5 font-semibold">
                <AlertTriangle size={12} /> {error}
              </p>
            )}

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-slate-800">
              <button onClick={onClose} className="premium-btn-secondary">
                Cancel
              </button>
              <button onClick={submit} disabled={loading} className="premium-btn-primary disabled:opacity-50">
                {loading ? 'Registering Agent…' : 'Register & Generate API Key'}
              </button>
            </div>
          </div>
        ) : (
          // Success Key Display
          <div className="p-6 space-y-5">
            <div className="flex items-start gap-3.5 p-4 rounded-xl border border-emerald-100 dark:border-emerald-950 bg-emerald-50/20 dark:bg-emerald-950/10">
              <Check size={18} className="text-emerald-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-bold text-emerald-800 dark:text-emerald-400">Agent credential registered!</p>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Make sure to copy the API key below. You will not be able to retrieve it later.</p>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">API Key Token</label>
              <div className="flex items-center gap-2 p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950">
                <code className="flex-1 text-xs font-mono text-amber-600 dark:text-amber-300 break-all select-all font-semibold">
                  {keyVisible ? created.api_key : '•'.repeat(Math.min(created.api_key?.length ?? 0, 32))}
                </code>
                <button onClick={() => setKeyVisible(v => !v)} className="text-slate-400 hover:text-slate-650 dark:hover:text-slate-200 transition-colors ml-1" title="Toggle visibility">
                  {keyVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <CopyBtn text={created.api_key ?? ''} />
              </div>
            </div>

            {/* Platform-specific quick-start */}
            {(() => {
              const server = `${window.location.protocol}//${window.location.hostname}:8000`;
              const key = created.api_key ?? 'YOUR_API_KEY';
              const isPAM = created.mode === 'pam';
              const dbType = created.db_type === 'pam' ? '' : created.db_type;

              const linuxCmd = isPAM ? '' : [
                `curl -sSL ${server}/downloads/install-agent.sh | \\`,
                `  MS_SERVER=${server} \\`,
                `  MS_API_KEY=${key} \\`,
                `  MS_DB_TYPE=${dbType} \\`,
                `  MS_DB_HOST=YOUR_DB_HOST \\`,
                `  MS_DB_USER=metasight_monitor \\`,
                `  MS_DB_PASSWORD=YOUR_PASSWORD \\`,
                `  bash`,
              ].join('\n');

              const winCmd = isPAM
                ? [
                    `# Download PAM agent (run as the monitored user, NOT as admin)`,
                    `Invoke-WebRequest -Uri "${server}/downloads/metasight-agent-windows-amd64.exe" \``,
                    `  -OutFile "$env:USERPROFILE\\Downloads\\metasight-agent.exe"`,
                    ``,
                    `# Run PAM agent`,
                    `& "$env:USERPROFILE\\Downloads\\metasight-agent.exe" \``,
                    `  --mode pam \``,
                    `  --server ${server} \``,
                    `  --api-key ${key} \``,
                    `  --record-screen --record-clipboard --monitor-usb`,
                  ].join('\n')
                : [
                    `# Download DB agent`,
                    `Invoke-WebRequest -Uri "${server}/downloads/metasight-agent-windows-amd64.exe" \``,
                    `  -OutFile "C:\\MetaSight\\metasight-agent.exe"`,
                    ``,
                    `# Run`,
                    `& "C:\\MetaSight\\metasight-agent.exe" \``,
                    `  --mode db --server ${server} --api-key ${key} \``,
                    `  --db-type ${dbType} --db-host YOUR_HOST \``,
                    `  --db-user metasight_monitor --db-password YOUR_PASSWORD`,
                  ].join('\n');

              return (
                <div className="space-y-3">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-slate-600 dark:text-slate-300">
                    <Terminal size={13} />
                    {isPAM ? 'PAM Agent — Windows desktop deployment' : 'DB Agent — server deployment'}
                  </div>

                  {isPAM ? (
                    // PAM = Windows only
                    <div className="space-y-1.5">
                      <div className="flex items-center gap-1.5 text-[10px] font-semibold text-slate-500">
                        <Monitor size={11} /> Windows (PowerShell)
                      </div>
                      <CodeBlock code={winCmd} lang="powershell" />
                      <p className="text-[10px] text-slate-400">
                        Run on the user's Windows workstation — not on a server. Captures screenshots, clipboard and USB events.
                      </p>
                    </div>
                  ) : (
                    // DB = show both tabs
                    <div className="space-y-3">
                      <div className="space-y-1.5">
                        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-400">
                          <Terminal size={11} /> Linux — one-liner installer
                          <span className="text-[9px] text-slate-400 font-normal">(recommended)</span>
                        </div>
                        <CodeBlock code={linuxCmd} lang="bash" />
                      </div>
                      <div className="space-y-1.5">
                        <div className="flex items-center gap-1.5 text-[10px] font-semibold text-slate-500">
                          <Monitor size={11} /> Windows — PowerShell
                        </div>
                        <CodeBlock code={winCmd} lang="powershell" />
                      </div>
                    </div>
                  )}

                  <p className="text-[10px] text-slate-400 flex items-center gap-1.5">
                    <Info size={11} />
                    Open the agent row below for a full interactive installer with all parameters.
                  </p>
                </div>
              );
            })()}

            <button onClick={onClose} className="w-full premium-btn-primary">
              Done — View Agents
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Default ports per DB type ─────────────────────────────────────────────────

const DB_DEFAULT_PORTS: Record<string, string> = {
  postgres: '5432', mysql: '3306', mssql: '1433',
  oracle: '1521', oracledb: '1521', mongodb: '27017',
};

const DB_DEFAULT_NAMES: Record<string, string> = {
  postgres: 'postgres', mysql: 'mydb', mssql: 'master',
  oracle: 'ORCL', oracledb: 'ORCL', mongodb: 'admin',
};

// ── Agent Installer Wizard ────────────────────────────────────────────────────

function InstallGuide({ agent }: { agent: Agent }) {
  const serverOrigin = (() => {
    const { protocol, hostname } = window.location;
    return `${protocol}//${hostname}:8000`;
  })();

  // DB agents run on servers (default Linux); PAM agents run on user desktops (default Windows)
  // 'aix' = PowerPC/AIX — Oracle E-Business Suite database tiers etc.
  const [os,     setOs]     = useState<'linux' | 'windows' | 'aix'>(agent.mode === 'pam' ? 'windows' : 'linux');
  const [arch,   setArch]   = useState<'amd64' | 'arm64'>('amd64');
  const [tab,    setTab]    = useState<'oneliner' | 'manual' | 'service'>('oneliner');
  const [pwShow, setPwShow] = useState(false);

  // Connection fields
  const [host,     setHost]     = useState('');
  const [port,     setPort]     = useState(DB_DEFAULT_PORTS[agent.db_type] ?? '5432');
  const [dbName,   setDbName]   = useState(DB_DEFAULT_NAMES[agent.db_type] ?? '');
  const [dbUser,   setDbUser]   = useState('metasight_monitor');
  const [dbPass,   setDbPass]   = useState('');
  // Policy fields
  const [authUsers, setAuthUsers] = useState(dbUser);
  const [authIPs,   setAuthIPs]   = useState('');
  const [blockedOps, setBlockedOps] = useState('DROP,TRUNCATE,GRANT,REVOKE');
  const [blockMode, setBlockMode] = useState(false);

  // Sync authUsers with dbUser when dbUser changes
  React.useEffect(() => { setAuthUsers(dbUser); }, [dbUser]);
  // Sync port/name when db_type changes
  React.useEffect(() => {
    setPort(DB_DEFAULT_PORTS[agent.db_type] ?? '');
    setDbName(DB_DEFAULT_NAMES[agent.db_type] ?? '');
  }, [agent.db_type]);
  // Reset to sensible tab when switching OS
  React.useEffect(() => {
    setTab(os === 'linux' ? 'oneliner' : 'manual');
  }, [os]);

  const key    = agent.api_key ?? 'YOUR_API_KEY';
  const server = serverOrigin;

  // ── Command builders ────────────────────────────────────────────────────────

  const cliArgs = [
    `--mode ${agent.mode}`,
    `--server ${server}`,
    `--api-key ${key}`,
    agent.mode === 'db' && `--db-type ${agent.db_type}`,
    agent.mode === 'db' && host   && `--db-host ${host}`,
    agent.mode === 'db' && port   && `--db-port ${port}`,
    agent.mode === 'db' && dbName && `--db-name ${dbName}`,
    agent.mode === 'db' && dbUser && `--db-user ${dbUser}`,
    agent.mode === 'db' && dbPass && `--db-password '${dbPass}'`,
    agent.mode === 'db' && authUsers && `--authorized-users "${authUsers}"`,
    agent.mode === 'db' && authIPs   && `--authorized-ips "${authIPs}"`,
    agent.mode === 'db' && blockedOps && `--blocked-ops "${blockedOps}"`,
    agent.mode === 'db' && blockMode  && `--block`,
    `--name "${agent.name}"`,
  ].filter(Boolean) as string[];

  const envVars: [string, string][] = [
    ['MS_SERVER',           server],
    ['MS_API_KEY',          key],
    ['MS_DB_TYPE',          agent.db_type],
    ['MS_DB_HOST',          host || 'YOUR_DB_HOST'],
    ['MS_DB_PORT',          port],
    ['MS_DB_NAME',          dbName || 'YOUR_DB_NAME'],
    ['MS_DB_USER',          dbUser],
    ['MS_DB_PASSWORD',      dbPass || 'YOUR_PASSWORD'],
    ['MS_AUTHORIZED_USERS', authUsers || dbUser],
    ...(authIPs   ? [['MS_AUTHORIZED_IPS',  authIPs]  as [string,string]] : []),
    ...(blockedOps ? [['MS_BLOCKED_OPS',    blockedOps] as [string,string]] : []),
    ['MS_AGENT_NAME',       agent.name],
  ];

  const linuxBinaryUrl   = `${server}/downloads/metasight-agent-linux-${arch}`;
  const windowsBinaryUrl = `${server}/downloads/metasight-agent-windows-amd64.exe`;

  const curlOneliner = [
    `curl -sSL ${server}/downloads/install-agent.sh | \\`,
    ...envVars.map(([k, v], i) =>
      `  ${k}=${v.includes(' ') ? `'${v}'` : v}${i < envVars.length - 1 ? ' \\' : ' \\'}`
    ),
    `  bash`,
  ].join('\n');

  const linuxManual = [
    `# 1. Download binary`,
    `curl -fsSL -o /usr/local/bin/metasight-agent \\`,
    `  ${linuxBinaryUrl}`,
    `chmod +x /usr/local/bin/metasight-agent`,
    ``,
    `# 2. Run`,
    `/usr/local/bin/metasight-agent \\`,
    ...cliArgs.map((a, i) => `  ${a}${i < cliArgs.length - 1 ? ' \\' : ''}`),
  ].join('\n');

  const linuxService = [
    `# 1. Download binary`,
    `curl -fsSL -o /usr/local/bin/metasight-agent \\`,
    `  ${linuxBinaryUrl}`,
    `chmod +x /usr/local/bin/metasight-agent`,
    ``,
    `# 2. Create systemd unit`,
    `cat > /etc/systemd/system/metasight-agent.service <<'EOF'`,
    `[Unit]`,
    `Description=MetaSight DB Agent (${agent.db_type})`,
    `After=network.target`,
    ``,
    `[Service]`,
    `Type=simple`,
    `ExecStart=/usr/local/bin/metasight-agent ${cliArgs.join(' ')}`,
    `Restart=on-failure`,
    `RestartSec=15s`,
    `NoNewPrivileges=true`,
    `ProtectSystem=strict`,
    ``,
    `[Install]`,
    `WantedBy=multi-user.target`,
    `EOF`,
    ``,
    `# 3. Enable & start`,
    `systemctl daemon-reload`,
    `systemctl enable --now metasight-agent`,
    `journalctl -u metasight-agent -f`,
  ].join('\n');

  // ── AIX (PowerPC) — Oracle E-Business Suite DB tiers ─────────────────────────
  // AIX has no systemd; the agent registers as an /etc/inittab "respawn" entry
  // instead, which init restarts if it ever exits. Only one arch exists (ppc64).
  const aixBinaryUrl = `${server}/downloads/metasight-agent-aix-ppc64`;

  const aixOneliner = [
    `curl -sSL ${server}/downloads/install-agent-aix.sh | \\`,
    ...envVars.map(([k, v], i) =>
      `  ${k}=${v.includes(' ') ? `'${v}'` : v}${i < envVars.length - 1 ? ' \\' : ' \\'}`
    ),
    `  sh`,
  ].join('\n');

  const aixManual = [
    `# 1. Download binary (PowerPC / ppc64)`,
    `curl -fsSL -o /usr/local/bin/metasight-agent \\`,
    `  ${aixBinaryUrl}`,
    `chmod 755 /usr/local/bin/metasight-agent`,
    ``,
    `# 2. Run`,
    `/usr/local/bin/metasight-agent \\`,
    ...cliArgs.map((a, i) => `  ${a}${i < cliArgs.length - 1 ? ' \\' : ''}`),
  ].join('\n');

  const aixService = [
    `# 1. Download binary (PowerPC / ppc64)`,
    `curl -fsSL -o /usr/local/bin/metasight-agent \\`,
    `  ${aixBinaryUrl}`,
    `chmod 755 /usr/local/bin/metasight-agent`,
    ``,
    `# 2. Register as an inittab "respawn" entry (AIX has no systemd —`,
    `#    init restarts this if it ever exits, same idea as Restart=on-failure)`,
    `cat > /usr/local/bin/metasight-agent-run.sh <<'EOF'`,
    `#!/bin/sh`,
    `exec /usr/local/bin/metasight-agent ${cliArgs.join(' ')}`,
    `EOF`,
    `chmod 755 /usr/local/bin/metasight-agent-run.sh`,
    `mkdir -p /var/log/metasight-agent`,
    `mkitab "metasight:2:respawn:/usr/local/bin/metasight-agent-run.sh >>/var/log/metasight-agent/agent.log 2>&1"`,
    ``,
    `# 3. Start now (without a reboot) and verify`,
    `telinit q`,
    `ps -ef | grep metasight-agent`,
    `tail -f /var/log/metasight-agent/agent.log`,
  ].join('\n');

  const winDownload = [
    `# Download binary`,
    `$dest = "$env:ProgramFiles\\MetaSight\\metasight-agent.exe"`,
    `New-Item -ItemType Directory -Force "$env:ProgramFiles\\MetaSight" | Out-Null`,
    `Invoke-WebRequest -Uri "${windowsBinaryUrl}" -OutFile $dest`,
    ``,
    `# Run (interactive)`,
    `& $dest ${cliArgs.join(' ')}`,
  ].join('\n');

  const winService = [
    `# Requires NSSM (https://nssm.cc)  — run as Administrator`,
    `$dest = "$env:ProgramFiles\\MetaSight\\metasight-agent.exe"`,
    `New-Item -ItemType Directory -Force "$env:ProgramFiles\\MetaSight" | Out-Null`,
    `Invoke-WebRequest -Uri "${windowsBinaryUrl}" -OutFile $dest`,
    ``,
    `nssm install MetaSightAgent $dest`,
    `nssm set MetaSightAgent AppParameters "${cliArgs.join(' ')}"`,
    `nssm set MetaSightAgent AppStdout "$env:ProgramFiles\\MetaSight\\agent.log"`,
    `nssm set MetaSightAgent AppStderr "$env:ProgramFiles\\MetaSight\\agent-err.log"`,
    `nssm start MetaSightAgent`,
    `# View service status`,
    `nssm status MetaSightAgent`,
  ].join('\n');

  type LinuxTab = 'oneliner' | 'manual' | 'service';
  type WinTab   = 'manual' | 'service';

  const linuxTabs: { key: LinuxTab; label: string }[] = [
    { key: 'oneliner', label: 'One-liner (curl)' },
    { key: 'manual',   label: 'Manual' },
    { key: 'service',  label: 'Systemd Service' },
  ];
  const aixTabs: { key: LinuxTab; label: string }[] = [
    { key: 'oneliner', label: 'One-liner (curl)' },
    { key: 'manual',   label: 'Manual' },
    { key: 'service',  label: 'Inittab Service' },
  ];
  const winTabs: { key: WinTab; label: string }[] = [
    { key: 'manual',   label: 'PowerShell Run' },
    { key: 'service',  label: 'NSSM Service' },
  ];

  const currentCode = (agent.mode === 'pam' || os === 'windows')
    ? (tab === 'service' ? winService : winDownload)
    : os === 'aix'
      ? (tab === 'oneliner' ? aixOneliner : tab === 'manual' ? aixManual : aixService)
      : (tab === 'oneliner' ? curlOneliner : tab === 'manual' ? linuxManual : linuxService);

  // Oracle prereq note
  const isOracle = agent.db_type === 'oracle' || agent.db_type === 'oracledb';

  const Field = ({ label, value, onChange, placeholder, type = 'text', hint = '' }: {
    label: string; value: string; onChange: (v: string) => void;
    placeholder?: string; type?: string; hint?: string;
  }) => (
    <div className="space-y-1">
      <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</label>
      <input
        type={type} value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 outline-none focus:border-brand-indigo transition-colors font-mono"
        autoComplete="off"
      />
      {hint && <p className="text-[10px] text-slate-400">{hint}</p>}
    </div>
  );

  return (
    <div className="space-y-5">
      {/* ── OS / Arch selector ── */}
      <div className="flex items-center gap-3 flex-wrap">
        {agent.mode === 'db' ? (
          <>
            <div className="flex gap-1 p-1 bg-slate-100 dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
              {(['linux', 'windows', 'aix'] as const).map(o => (
                <button key={o} onClick={() => setOs(o)}
                  className={cn(
                    'flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all',
                    os === o ? 'bg-brand-indigo text-white shadow-sm' : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300',
                  )}>
                  {o === 'linux' ? <Terminal size={12} /> : o === 'windows' ? <Monitor size={12} /> : <Server size={12} />}
                  {o === 'linux' ? 'Linux Server' : o === 'windows' ? 'Windows Server' : 'AIX (PowerPC)'}
                </button>
              ))}
            </div>
            {os === 'linux' && (
              <div className="flex gap-1 p-1 bg-slate-100 dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800">
                {(['amd64', 'arm64'] as const).map(a => (
                  <button key={a} onClick={() => setArch(a)}
                    className={cn(
                      'px-3 py-1.5 rounded-lg text-xs font-semibold transition-all',
                      arch === a ? 'bg-brand-indigo text-white shadow-sm' : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-300',
                    )}>
                    {a === 'amd64' ? 'x86-64' : 'ARM64 / Graviton'}
                  </button>
                ))}
              </div>
            )}
            {os === 'aix' && (
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-500">
                <Cpu size={12} /> ppc64 (only arch AIX runs on)
              </div>
            )}
          </>
        ) : (
          /* PAM agent — Windows workstations only */
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-900/30">
            <Monitor size={13} className="text-blue-600 dark:text-blue-400" />
            <span className="text-xs font-semibold text-blue-700 dark:text-blue-300">
              PAM Agent — Windows desktop deployment
            </span>
            <span className="text-[10px] text-blue-500 dark:text-blue-400">
              (Run on the user's workstation, not on a server)
            </span>
          </div>
        )}

        {/* Direct download link */}
        <a
          href={agent.mode === 'pam' ? windowsBinaryUrl : os === 'linux' ? linuxBinaryUrl : os === 'aix' ? aixBinaryUrl : windowsBinaryUrl}
          download
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/30 hover:bg-emerald-100 dark:hover:bg-emerald-950/40 transition-colors"
        >
          <Download size={12} />
          Download Binary
        </a>
      </div>

      {/* ── Inputs panel ── */}
      {agent.mode === 'db' && (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 bg-slate-50 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800">
            <Database size={13} className="text-brand-indigo" />
            <span className="text-xs font-bold text-slate-700 dark:text-slate-300">Connection Details</span>
            <span className="ml-auto text-[10px] text-slate-400 italic">Command updates live as you type</span>
          </div>
          <div className="p-4 grid grid-cols-2 gap-3">
            <Field label="DB Host / IP" value={host} onChange={setHost}
              placeholder={`e.g. ${agent.db_type === 'oracle' ? 'oracle-prod.company.com' : 'localhost'}`}
              hint="Hostname or IP of the target database server"
            />
            <Field label="Port" value={port} onChange={setPort}
              placeholder={DB_DEFAULT_PORTS[agent.db_type] ?? '5432'}
            />
            <Field label={agent.db_type === 'oracle' || agent.db_type === 'oracledb' ? 'Service Name / SID' : 'Database Name'}
              value={dbName} onChange={setDbName}
              placeholder={DB_DEFAULT_NAMES[agent.db_type] ?? 'mydb'}
              hint={isOracle ? 'Oracle service name or SID (e.g. ORCL, XEPDB1)' : ''}
            />
            <Field label="DB Username" value={dbUser} onChange={setDbUser}
              placeholder="metasight_monitor"
            />
            <div className="col-span-2 space-y-1">
              <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">DB Password</label>
              <div className="relative">
                <input
                  type={pwShow ? 'text' : 'password'}
                  value={dbPass} onChange={e => setDbPass(e.target.value)}
                  placeholder="Enter password"
                  className="w-full px-2.5 py-1.5 pr-8 text-xs rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-200 outline-none focus:border-brand-indigo transition-colors font-mono"
                  autoComplete="new-password"
                />
                <button
                  onClick={() => setPwShow(v => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                >
                  {pwShow ? <EyeOff size={12} /> : <Eye size={12} />}
                </button>
              </div>
            </div>
          </div>

          {/* Policy */}
          <div className="border-t border-slate-200 dark:border-slate-800 px-4 py-3 bg-slate-50/40 dark:bg-slate-900/30 space-y-3">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
              <Shield size={11} /> Access Policy
            </p>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Authorized DB Users" value={authUsers} onChange={setAuthUsers}
                placeholder="metasight_monitor,app_user"
                hint="Comma-separated — connections from other users trigger alerts"
              />
              <Field label="Authorized IP Ranges" value={authIPs} onChange={setAuthIPs}
                placeholder="10.0.0.0/8,192.168.1.50"
                hint="Leave blank to allow all IPs"
              />
              <Field label="Blocked SQL Operations" value={blockedOps} onChange={setBlockedOps}
                placeholder="DROP,TRUNCATE,GRANT,REVOKE"
                hint="Comma-separated SQL keywords to flag/block"
              />
              <div className="space-y-1">
                <label className="text-[10px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Block Mode</label>
                <button
                  onClick={() => setBlockMode(v => !v)}
                  className={cn(
                    'flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all',
                    blockMode
                      ? 'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-900/30 text-red-700 dark:text-red-400'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-700 text-slate-500',
                  )}
                >
                  {blockMode ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
                  {blockMode ? 'Blocking enabled' : 'Alert-only (safe)'}
                </button>
                <p className="text-[10px] text-slate-400">When on, unauthorized sessions are terminated immediately</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Oracle prereqs */}
      {isOracle && agent.mode === 'db' && (
        <div className="flex items-start gap-2.5 p-3 rounded-xl border border-amber-200 dark:border-amber-900/40 bg-amber-50 dark:bg-amber-950/10">
          <Info size={13} className="text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
          <div className="text-[11px] text-amber-800 dark:text-amber-300 space-y-1">
            <p className="font-bold">Oracle prerequisites — run on the Oracle server as SYSDBA:</p>
            <pre className="font-mono bg-amber-100/60 dark:bg-amber-950/30 rounded px-2 py-1.5 whitespace-pre-wrap">
{`GRANT SELECT ON V_$SESSION TO ${dbUser || 'metasight_monitor'};
GRANT SELECT ON V_$SQL     TO ${dbUser || 'metasight_monitor'};`}
            </pre>
            <p className="text-amber-600 dark:text-amber-400">No Oracle Instant Client needed — pure Go driver (go-ora) is used, thin-mode only.</p>
            {os === 'aix' && (
              <>
                <p className="text-amber-700 dark:text-amber-300 font-semibold pt-1">Oracle E-Business Suite on AIX:</p>
                <p>
                  <strong>Service Name / SID</strong> above should usually just be the EBS instance's SID —
                  Oracle's listener almost always auto-registers the SID as a matching service name too.
                  If you get ORA-12514, run <code className="font-mono">lsnrctl status</code> on the DB tier
                  to confirm the exact name.
                </p>
                <p>
                  Leave <strong>Block Mode</strong> off until you've watched the agent in alert-only mode
                  for a while — on an EBS DB tier, terminating the wrong session can kill a concurrent-manager
                  connection, not just an ad hoc client.
                </p>
              </>
            )}
          </div>
        </div>
      )}

      {/* ── Tab switcher ── */}
      <div className="flex gap-1 bg-slate-100 dark:bg-slate-900 p-1 rounded-xl border border-slate-200 dark:border-slate-800">
        {(agent.mode === 'pam' || os === 'windows' ? winTabs : os === 'aix' ? aixTabs : linuxTabs).map(t => (
          <button key={t.key} onClick={() => setTab(t.key as LinuxTab)}
            className={cn(
              'flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all',
              tab === t.key
                ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-sm'
                : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200',
            )}>
            {t.label}
          </button>
        ))}
      </div>

      <CodeBlock code={currentCode} lang={agent.mode === 'pam' || os === 'windows' ? 'powershell' : 'bash'} />

      {/* ── Validation hints ── */}
      {(!host || !dbPass) && agent.mode === 'db' && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-50 dark:bg-amber-950/10 border border-amber-200 dark:border-amber-900/30 text-[11px] text-amber-700 dark:text-amber-400 font-medium">
          <AlertTriangle size={12} className="flex-shrink-0" />
          Fill in <strong>DB Host</strong> and <strong>Password</strong> above — the command above uses placeholder values until then.
        </div>
      )}
    </div>
  );
}

// ── Event Feed ────────────────────────────────────────────────────────────────

function EventFeed({ agentId, mode }: { agentId: number; mode: 'db' | 'pam' }) {
  const [events, setEvents]     = useState<AgentEvent[]>([]);
  const [loading, setLoading]   = useState(true);
  const [filter, setFilter]     = useState('');
  const [expandedEventId, setExpandedEventId] = useState<number | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    try {
      const { data } = await api.get<AgentEvent[]>(`${agentBase(mode)}/${agentId}/events?limit=80`);
      setEvents(data);
    } catch {
      // silently ignore
    } finally {
      setLoading(false);
    }
  }, [agentId, mode]);

  useEffect(() => {
    load();
    intervalRef.current = setInterval(load, 8000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [load]);

  const filtered = filter
    ? events.filter(e => e.event_type.toLowerCase().includes(filter.toLowerCase()) || e.session_id?.toLowerCase().includes(filter.toLowerCase()))
    : events;

  if (loading) return (
    <div className="flex items-center justify-center py-12">
      <RefreshCw size={18} className="animate-spin text-slate-400" />
    </div>
  );

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
        <input
          value={filter} 
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter live logs by event type or session..."
          className="premium-input pl-8 py-1.5 text-xs"
        />
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-16 text-slate-400 dark:text-slate-500 border border-dashed border-slate-200 dark:border-slate-800 rounded-xl">
          No agent activity logged.
        </div>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {filtered.map(e => {
            const meta = EVENT_META[e.event_type] ?? { color: '#6B7280', label: e.event_type };
            const isExpanded = expandedEventId === e.id;
            return (
              <div 
                key={e.id} 
                onClick={() => setExpandedEventId(isExpanded ? null : e.id)}
                className="p-3 bg-white dark:bg-slate-900 border border-slate-150 dark:border-slate-800/80 rounded-xl hover:border-slate-300 dark:hover:border-slate-700 transition-all cursor-pointer space-y-2 animate-scale-up"
              >
                <div className="flex items-center justify-between gap-3 text-xs">
                  <div className="flex items-center gap-2">
                    <Circle size={7} className="fill-current" style={{ color: meta.color }} />
                    <span className="font-bold uppercase tracking-wider" style={{ color: meta.color }}>
                      {meta.label}
                    </span>
                    {e.risk_flag && (
                      <span className="premium-badge text-[8px] bg-rose-50 dark:bg-rose-950/30 text-brand-red dark:text-red-400 border border-rose-100 dark:border-rose-900/20 font-bold">
                        CRITICAL RISK
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-slate-400 dark:text-slate-500 font-medium">
                    {fmtTs(e.occurred_at)}
                  </span>
                </div>

                {e.session_id && (
                  <p className="text-[10px] font-mono text-slate-450 dark:text-slate-500">
                    session: <span className="font-semibold text-slate-700 dark:text-slate-350">{e.session_id}</span>
                  </p>
                )}

                {e.payload && Object.keys(e.payload).length > 0 && !isExpanded && (
                  <p className="text-[10px] text-slate-550 dark:text-slate-400 font-mono truncate bg-slate-50 dark:bg-slate-950/40 p-1.5 rounded border border-slate-100 dark:border-slate-850">
                    {Object.entries(e.payload).slice(0, 3).map(([k, v]) => `${k}: ${String(v)}`).join(' · ')}
                  </p>
                )}

                {isExpanded && e.payload && (
                  <div 
                    onClick={(evt) => evt.stopPropagation()}
                    className="p-3 bg-slate-950 border border-slate-800/60 rounded-lg text-[10px] text-slate-300 font-mono space-y-1.5 leading-relaxed select-text"
                  >
                    {Object.entries(e.payload).map(([k, v]) => {
                      if (k === 'current_sql' && v) {
                        return (
                          <div key={k} className="flex flex-col gap-1 mt-1 border-t border-slate-900 pt-1.5">
                            <span className="text-slate-500 font-bold uppercase tracking-wider text-[9px]">{k}:</span>
                            <pre className="bg-slate-900 border border-slate-800 rounded p-2 text-amber-200 whitespace-pre-wrap break-all text-[11px] font-mono select-text">{String(v)}</pre>
                          </div>
                        );
                      }
                      return (
                        <div key={k} className="flex items-start gap-2 py-0.5 border-b border-slate-900/30 last:border-0">
                          <span className="text-slate-500 font-bold min-w-[90px] uppercase tracking-wider text-[9px]">{k}:</span>
                          <span className="text-slate-200 break-all select-text">{String(v)}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Policy Tab ────────────────────────────────────────────────────────────────

const ALL_OPS = ['SELECT','INSERT','UPDATE','DELETE','DROP','TRUNCATE','ALTER','CREATE','GRANT','REVOKE','EXEC'];
const OP_RISK: Record<string, 'low'|'medium'|'high'|'critical'> = {
  SELECT: 'low', INSERT: 'medium', UPDATE: 'medium', DELETE: 'high',
  DROP: 'critical', TRUNCATE: 'high', ALTER: 'high', CREATE: 'medium',
  GRANT: 'critical', REVOKE: 'high', EXEC: 'high',
};
const OP_COLORS = { low: '#10B981', medium: '#F59E0B', high: '#F97316', critical: '#EF4444' };

function PolicyTab({ agent, onSaved }: { agent: Agent; onSaved: (updated: Partial<Agent>) => void }) {
  const [allowedIPs,    setAllowedIPs]    = useState<string[]>(agent.allowed_ips    ?? []);
  const [allowedUsers,  setAllowedUsers]  = useState<string[]>(agent.allowed_users  ?? []);
  const [blockedOps,    setBlockedOps]    = useState<string[]>(agent.blocked_ops    ?? []);
  const [blockMode,     setBlockMode]     = useState<boolean>(agent.block_mode      ?? false);
  const [alertBypass,   setAlertBypass]   = useState<boolean>(agent.alert_on_bypass ?? true);
  const [ipInput,       setIpInput]       = useState('');
  const [userInput,     setUserInput]     = useState('');
  const [saving,        setSaving]        = useState(false);
  const [saved,         setSaved]         = useState(false);
  const [error,         setError]         = useState('');

  const addIP = () => {
    const v = ipInput.trim();
    if (!v) return;
    if (!allowedIPs.includes(v)) setAllowedIPs(p => [...p, v]);
    setIpInput('');
  };

  const addUser = () => {
    const v = userInput.trim().toLowerCase();
    if (!v || allowedUsers.includes(v)) return;
    setAllowedUsers(p => [...p, v]);
    setUserInput('');
  };

  const toggleOp = (op: string) =>
    setBlockedOps(p => p.includes(op) ? p.filter(o => o !== op) : [...p, op]);

  const save = async () => {
    setSaving(true); setError('');
    try {
      const { data } = await api.patch(`${agentBase(agent.mode)}/${agent.id}/config`, {
        allowed_ips:     allowedIPs,
        allowed_users:   allowedUsers,
        blocked_ops:     blockedOps,
        block_mode:      blockMode,
        alert_on_bypass: alertBypass,
      });
      onSaved({
        allowed_ips: data.allowed_ips,
        allowed_users: data.allowed_users,
        blocked_ops: data.blocked_ops,
        block_mode: data.block_mode,
        alert_on_bypass: data.alert_on_bypass,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 2500);
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(msg || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Agent's own IP */}
      <div className="p-4 rounded-xl border border-sky-100 dark:border-sky-950 bg-sky-50/20 dark:bg-sky-950/10 space-y-2">
        <div className="flex items-center gap-2">
          <MapPin size={13} className="text-sky-500" />
          <span className="text-xs font-bold text-sky-850 dark:text-sky-400 uppercase tracking-wider">Agent Host Connection Status</span>
        </div>
        <div className="flex items-center gap-3">
          <code className="text-sm font-mono font-bold text-slate-800 dark:text-white bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 px-2 py-0.5 rounded">
            {agent.agent_ip || 'No heartbeat registered yet'}
          </code>
          {agent.agent_ip && <CopyBtn text={agent.agent_ip} />}
        </div>
        <p className="text-[10px] text-slate-500 dark:text-slate-450">
          Heartbeat occurs every 60s. Add this IP to target credentials to restrict access bypass.
          {agent.config_pulled_at && (
            <> · Last pulled config: <strong className="text-slate-700 dark:text-slate-300">{fmtRelative(agent.config_pulled_at)}</strong></>
          )}
        </p>
      </div>

      {/* IP Allow-list */}
      <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3 shadow-sm">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Network size={13} className="text-brand-indigo" />
            <span className="text-xs font-bold text-slate-900 dark:text-white">Client IP Allowlist</span>
          </div>
          <span className="text-[10px] text-slate-400 dark:text-slate-500">CIDR/Wildcard formats accepted. Empty allows any IP.</span>
        </div>

        <div className="flex gap-2">
          <input 
            value={ipInput} 
            onChange={e => setIpInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addIP()}
            placeholder="e.g. 192.168.1.0/24 or 10.10.29.3"
            className="premium-input py-1.5 text-xs font-mono" 
          />
          <button 
            type="button"
            onClick={addIP}
            className="premium-btn-primary py-1.5 px-3.5 text-xs font-bold shrink-0"
          >
            Add IP
          </button>
        </div>

        {agent.agent_ip && !allowedIPs.includes(agent.agent_ip) && (
          <button 
            type="button"
            onClick={() => setAllowedIPs(p => [...p, agent.agent_ip!])}
            className="flex items-center gap-1.5 text-[10px] font-bold text-brand-indigo hover:underline"
          >
            <Plus size={11} /> Trust Agent's Heartbeat IP ({agent.agent_ip})
          </button>
        )}

        <div className="flex flex-wrap gap-1.5 pt-1">
          {allowedIPs.length === 0 ? (
            <span className="text-xs text-slate-400 italic">No entries configured — all client IPs trusted.</span>
          ) : (
            allowedIPs.map(ip => (
              <span key={ip} className="premium-badge text-[11px] px-2 py-0.5 bg-blue-50 dark:bg-blue-950/20 text-brand-blue dark:text-blue-400 border border-blue-100 dark:border-blue-900/10 font-mono font-bold">
                {ip}
                <button onClick={() => setAllowedIPs(p => p.filter(x => x !== ip))} className="ml-1 hover:text-red-500 transition-colors">
                  <X size={10} />
                </button>
              </span>
            ))
          )}
        </div>
      </div>

      {/* DB User Allow-list */}
      <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3 shadow-sm">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <UserCheck size={13} className="text-brand-green" />
            <span className="text-xs font-bold text-slate-900 dark:text-white">Database User Allowlist</span>
          </div>
          <span className="text-[10px] text-slate-400 dark:text-slate-500">Only matches direct DB connections. Empty allows all.</span>
        </div>

        <div className="flex gap-2">
          <input 
            value={userInput} 
            onChange={e => setUserInput(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addUser()}
            placeholder="e.g. app_server_runtime"
            className="premium-input py-1.5 text-xs font-mono" 
          />
          <button 
            type="button"
            onClick={addUser}
            className="premium-btn-primary py-1.5 px-3.5 text-xs font-bold shrink-0"
          >
            Add User
          </button>
        </div>

        <div className="flex flex-wrap gap-1.5 pt-1">
          {allowedUsers.length === 0 ? (
            <span className="text-xs text-slate-400 italic">No entries configured — all database users trusted.</span>
          ) : (
            allowedUsers.map(u => (
              <span key={u} className="premium-badge text-[11px] px-2 py-0.5 bg-emerald-50 dark:bg-emerald-950/20 text-brand-green dark:text-emerald-450 border border-emerald-100 dark:border-emerald-900/10 font-mono font-bold">
                {u}
                <button onClick={() => setAllowedUsers(p => p.filter(x => x !== u))} className="ml-1 hover:text-red-500 transition-colors">
                  <X size={10} />
                </button>
              </span>
            ))
          )}
        </div>
      </div>

      {/* Blocked SQL Operations */}
      <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3 shadow-sm">
        <div className="flex items-center gap-2">
          <Ban size={13} className="text-brand-red" />
          <span className="text-xs font-bold text-slate-900 dark:text-white">Blocked SQL Statements</span>
          <span className="ml-auto text-[10px] text-slate-400 dark:text-slate-500 font-medium">Auto-flagged even from allowed clients</span>
        </div>
        
        <div className="flex flex-wrap gap-2">
          {ALL_OPS.map(op => {
            const active = blockedOps.includes(op);
            const risk   = OP_RISK[op] ?? 'low';
            const color  = OP_COLORS[risk];
            return (
              <button 
                key={op} 
                onClick={() => toggleOp(op)}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono transition-all border",
                  active 
                    ? 'shadow-sm' 
                    : 'bg-slate-50 dark:bg-slate-900 text-slate-400 dark:text-slate-550 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                )}
                style={active ? { borderColor: color, color: color, background: `${color}0A` } : {}}
              >
                {active && <span className="mr-1">✓</span>}
                {op}
              </button>
            );
          })}
        </div>
        <div className="flex gap-3 pt-1 text-xs">
          <button 
            type="button"
            onClick={() => setBlockedOps(['DROP','TRUNCATE','GRANT','REVOKE','ALTER'])}
            className="text-[10px] font-bold text-brand-orange hover:underline"
          >
            Recommended presets (DDL/Admin block)
          </button>
          <span className="text-slate-300 dark:text-slate-700">|</span>
          <button 
            type="button"
            onClick={() => setBlockedOps([])}
            className="text-[10px] font-bold text-slate-450 hover:underline"
          >
            Clear all values
          </button>
        </div>
      </div>

      {/* Enforcement & Bypass toggles */}
      <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-4 shadow-sm">
        <div className="flex items-center gap-2 border-b border-slate-100 dark:border-slate-800/80 pb-2">
          <Lock size={13} className="text-brand-purple" />
          <span className="text-xs font-bold text-slate-900 dark:text-white">Active Enforcement Actions</span>
        </div>

        {/* Block mode */}
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-bold text-slate-900 dark:text-white">Auto-Terminate Bypass Sessions</p>
            <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1 leading-relaxed">
              Agent kills direct TCP connection to DBMS immediately upon policy exception. Requires DBMS administrative privileges.
            </p>
          </div>
          <button onClick={() => setBlockMode(v => !v)} className="shrink-0 transition-all hover:scale-105 active:scale-95">
            {blockMode
              ? <ToggleRight size={28} className="text-brand-red fill-rose-500/10" />
              : <ToggleLeft  size={28} className="text-slate-300 dark:text-slate-700" />}
          </button>
        </div>

        {/* Alert on bypass */}
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0 flex-1">
            <p className="text-xs font-bold text-slate-900 dark:text-white">Flag Security Incidents on Bypass</p>
            <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-1 leading-relaxed">
              Raise a critical risk event inside MetaSight Dashboard whenever connection is detected outside allowed clients.
            </p>
          </div>
          <button onClick={() => setAlertBypass(v => !v)} className="shrink-0 transition-all hover:scale-105 active:scale-95">
            {alertBypass
              ? <ToggleRight size={28} className="text-brand-green fill-emerald-500/10" />
              : <ToggleLeft  size={28} className="text-slate-300 dark:text-slate-700" />}
          </button>
        </div>
      </div>

      {/* Bypass Info Guideline block */}
      <div className="p-3.5 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800 flex items-start gap-2.5">
        <Info size={13} className="text-brand-indigo flex-shrink-0 mt-0.5" />
        <p className="text-[10px] text-slate-500 dark:text-slate-400 leading-relaxed font-medium">
          A <strong className="text-slate-700 dark:text-slate-300">Bypass</strong> is mapped when client direct queries connect outside allowed IP endpoints (e.g. connecting via CLI tools directly to DBMS, bypassing gateway logs). IP allowlist should include app servers, gateways, and authorized jumpbox addresses.
        </p>
      </div>

      {error && (
        <p className="text-xs text-brand-red flex items-center gap-1.5 font-semibold">
          <AlertTriangle size={12} />
          {error}
        </p>
      )}

      {/* Save Policy Button */}
      <button 
        onClick={save} 
        disabled={saving}
        className={cn(
          "w-full py-2.5 rounded-xl text-xs font-bold text-white transition-all flex items-center justify-center gap-2",
          saved 
            ? 'bg-brand-green shadow-lg shadow-emerald-500/10' 
            : 'bg-brand-indigo hover:bg-brand-indigo/90 shadow-lg shadow-brand-indigo/10'
        )}
      >
        {saved ? (
          <><Check size={14} className="stroke-[3]" /> Configurations Saved successfully (reloaded in &lt;10s)</>
        ) : (
          saving ? 'Syncing Configurations...' : <><Lock size={13} /> Save Sync Policy</>
        )}
      </button>
    </div>
  );
}

// ── Detail Panel ──────────────────────────────────────────────────────────────

function DetailPanel({
  agent, stats, onClose, onDelete, onRotateKey, onPolicySaved,
}: {
  agent: Agent;
  stats: AgentStats | null;
  onClose: () => void;
  onDelete: (id: number) => void;
  onRotateKey: (id: number) => void;
  onPolicySaved: (patch: Partial<Agent>) => void;
}) {
  const [tab, setTab] = useState<'overview' | 'events' | 'install' | 'capabilities' | 'policy'>('overview');
  const [confirming, setConfirming] = useState(false);
  const [togglingAgent, setTogglingAgent] = useState(false);

  const handleToggleAgent = async (id: number, action: 'start' | 'stop') => {
    setTogglingAgent(true);
    try {
      const { data } = await api.post<Agent>(`${agentBase(agent.mode)}/${id}/${action}`);
      // Merge ALL returned fields (including running status) back into selected & list
      onPolicySaved(data);
    } catch (e: any) {
      alert(e.response?.data?.detail || `Failed to ${action} agent`);
    } finally {
      setTogglingAgent(false);
    }
  };

  const TABS = [
    { key: 'overview',     label: 'Overview',      icon: Activity },
    { key: 'policy',       label: 'Policy Settings', icon: Lock },
    { key: 'events',       label: 'Live Events Feed',   icon: Zap },
    { key: 'install',      label: 'Setup Guide', icon: Terminal },
    { key: 'capabilities', label: 'Features',  icon: Shield },
  ] as const;

  const topTypes = stats
    ? Object.entries(stats.by_type_today).sort((a, b) => b[1] - a[1]).slice(0, 5)
    : [];

  return (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 animate-slide-up">
      {/* Panel header */}
      <div className="flex-shrink-0 px-5 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className={cn(
              "flex-shrink-0 w-9 h-9 rounded-xl flex items-center justify-center",
              agent.mode === 'pam' ? 'bg-purple-50 dark:bg-purple-950/40 text-brand-purple' : 'bg-blue-50 dark:bg-blue-950/40 text-brand-blue'
            )}>
              {agent.mode === 'pam' ? <Monitor size={16} /> : <Database size={16} />}
            </div>
            <div className="min-w-0">
              <h3 className="text-sm font-bold text-slate-900 dark:text-white truncate">{agent.name}</h3>
              <div className="flex items-center gap-2 mt-0.5">
                <StatusDot online={agent.online} />
                <span className="text-[11px] text-slate-400 dark:text-slate-550 font-semibold">{agent.online ? 'Online' : 'Offline'}</span>
                <TypeBadge type={agent.db_type} mode={agent.mode} />
              </div>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-450 hover:text-slate-700 dark:hover:text-slate-200 transition-colors flex-shrink-0">
            <X size={15} />
          </button>
        </div>

        {/* Detail Tabs */}
        <div className="flex gap-1.5 mt-4 overflow-x-auto pr-2 scrollbar-none">
          {TABS.map(t => {
            const Icon = t.icon;
            const isActive = tab === t.key;
            return (
              <button 
                key={t.key} 
                onClick={() => setTab(t.key)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-bold whitespace-nowrap transition-all border",
                  isActive 
                    ? 'bg-brand-indigo/5 border-brand-indigo/25 text-brand-indigo' 
                    : 'bg-white hover:bg-slate-50 dark:bg-slate-900 dark:hover:bg-slate-850/60 border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400'
                )}
              >
                <Icon size={11} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Panel body */}
      <div className="flex-1 overflow-y-auto px-5 py-4">
        {tab === 'overview' && (
          <div className="space-y-4">
            {/* Quick stats grid */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Events Today',   value: stats?.events_today ?? 0,  color: 'text-brand-blue' },
                { label: 'Risk Flags Today',    value: stats?.risk_today   ?? 0,  color: 'text-brand-red' },
                { label: 'Total Logs',   value: stats?.total_events ?? 0,  color: 'text-brand-indigo' },
                { label: 'Active Sessions',value: agent.active_sessions,     color: 'text-brand-green' },
              ].map(s => (
                <div key={s.label} className="p-3 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl">
                  <p className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider">{s.label}</p>
                  <p className={cn("text-xl font-bold mt-1 tracking-tight", s.color)}>{s.value}</p>
                </div>
              ))}
            </div>

            {/* Agent metadata parameters */}
            <div className="p-4 bg-slate-50 dark:bg-slate-900/60 border border-slate-250 dark:border-slate-800 rounded-xl space-y-2.5">
              {[
                { label: 'Register ID',   value: `#${agent.id}` },
                { label: 'Operational Mode',       value: agent.mode === 'db' ? 'DB Interception' : 'PAM endpoint' },
                { label: 'Target Database type',    value: agent.db_type },
                { label: 'Last seen status',  value: fmtRelative(agent.last_seen) },
                { label: 'Registration Date', value: fmtTs(agent.created_at) },
              ].map(r => (
                <div key={r.label} className="flex items-center justify-between text-xs">
                  <span className="text-slate-450 dark:text-slate-500 font-semibold">{r.label}</span>
                  <span className="text-slate-700 dark:text-slate-350 font-mono font-bold">{r.value}</span>
                </div>
              ))}
            </div>

            {/* Today's event breakdown */}
            {topTypes.length > 0 && (
              <div className="p-4 bg-slate-50 dark:bg-slate-900/60 border border-slate-250 dark:border-slate-800 rounded-xl space-y-3">
                <p className="text-[10px] text-slate-450 dark:text-slate-500 font-bold uppercase tracking-wider">Hourly Event Breakdown</p>
                {topTypes.map(([type, count]) => {
                  const meta = EVENT_META[type] ?? { color: '#6B7280', label: type };
                  const max = topTypes[0][1];
                  return (
                    <div key={type} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold" style={{ color: meta.color }}>{meta.label}</span>
                        <span className="text-slate-700 dark:text-slate-300 font-bold">{count}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-850">
                        <div className="h-1.5 rounded-full transition-all duration-500"
                          style={{ width: `${(count / max) * 100}%`, background: meta.color }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Local Agent Process Control */}
            <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl space-y-3 shadow-sm">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {agent.mode === 'pam' ? <Monitor size={14} className="text-brand-purple" /> : <Cpu size={14} className="text-brand-indigo" />}
                  <span className="text-xs font-bold text-slate-900 dark:text-white">
                    {agent.mode === 'pam' ? 'PAM Endpoint Agent' : 'Local DB Agent Runner'}
                  </span>
                </div>
                <span className={cn(
                  "premium-badge text-[10px] font-bold",
                  agent.running
                    ? "bg-emerald-50 dark:bg-emerald-950/30 text-brand-green border-emerald-100 dark:border-emerald-900/20"
                    : "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700"
                )}>
                  {agent.running ? "RUNNING" : "STOPPED"}
                </span>
              </div>

              {/* PAM Agent Note */}
              {agent.mode === 'pam' && (
                <div className="p-2.5 rounded-lg bg-purple-50 dark:bg-purple-950/20 border border-purple-100 dark:border-purple-900/20">
                  <p className="text-[10px] text-purple-700 dark:text-purple-300 leading-relaxed">
                    <span className="font-bold">Screenshot source:</span> The PAM agent runs on the <span className="font-bold">user&apos;s workstation</span> and captures their Oracle/DB client screen — not this server.
                    When the DB agent detects a blocked query, it signals this PAM agent to take an on-demand screenshot of the user&apos;s actual session.
                  </p>
                </div>
              )}

              <div className="flex gap-2">
                {agent.running ? (
                  <button
                    onClick={() => handleToggleAgent(agent.id, 'stop')}
                    disabled={!isAdmin() || togglingAgent}
                    className="flex-1 py-2 rounded-xl text-xs font-bold text-white bg-rose-600 hover:bg-rose-700 shadow-md shadow-rose-500/10 disabled:opacity-50 transition-all flex items-center justify-center gap-1.5"
                  >
                    <Circle size={8} className="fill-current text-white animate-pulse" />
                    Stop Agent Process
                  </button>
                ) : (
                  <button
                    onClick={() => handleToggleAgent(agent.id, 'start')}
                    disabled={!isAdmin() || togglingAgent}
                    className={cn(
                      "flex-1 py-2 rounded-xl text-xs font-bold text-white shadow-md disabled:opacity-50 transition-all flex items-center justify-center gap-1.5",
                      agent.mode === 'pam'
                        ? 'bg-brand-purple hover:bg-purple-700 shadow-purple-500/10'
                        : 'bg-brand-indigo hover:bg-brand-indigo/90 shadow-brand-indigo/10'
                    )}
                  >
                    {togglingAgent ? <span className="animate-spin">&#9696;</span> : <Play size={12} className="fill-current text-white" />}
                    {togglingAgent ? 'Starting...' : `Start ${agent.mode === 'pam' ? 'PAM' : 'DB'} Agent`}
                  </button>
                )}
              </div>
              {!isAdmin() && (
                <p className="text-[10px] text-slate-450 dark:text-slate-550 italic text-center">
                  * Admin privileges required to manage background agent processes.
                </p>
              )}
            </div>

            {/* Danger zone */}
            {isAdmin() && (
              <div className="p-4 rounded-xl border border-rose-100 dark:border-rose-950/40 bg-rose-50/20 dark:bg-rose-950/10 space-y-3">
                <p className="text-[10px] text-brand-red font-bold uppercase tracking-wider">Infrastructure Actions (Danger zone)</p>
                <button
                  onClick={() => onRotateKey(agent.id)}
                  className="w-full py-2.5 rounded-xl text-xs font-bold text-amber-600 hover:text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/20 border border-amber-250 dark:border-amber-900/10 transition-all flex items-center justify-center gap-2"
                >
                  <RotateCcw size={13} /> 
                  Rotate Authorization API Key
                </button>
                {!confirming ? (
                  <button 
                    onClick={() => setConfirming(true)}
                    className="w-full py-2.5 rounded-xl text-xs font-bold text-rose-600 hover:text-rose-700 bg-rose-50 dark:bg-rose-950/20 border border-rose-250 dark:border-rose-900/10 transition-all flex items-center justify-center gap-2"
                  >
                    <Trash2 size={13} /> 
                    Decommission Agent
                  </button>
                ) : (
                  <div className="flex gap-2 animate-scale-up">
                    <button 
                      onClick={() => { setConfirming(false); onDelete(agent.id); }}
                      className="flex-1 py-2 rounded-xl text-xs font-bold text-white bg-rose-600 hover:bg-rose-700 shadow-sm"
                    >
                      Confirm Decommission
                    </button>
                    <button 
                      onClick={() => setConfirming(false)}
                      className="flex-1 py-2 rounded-xl text-xs font-bold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-300"
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {tab === 'events' && <EventFeed agentId={agent.id} mode={agent.mode} />}

        {tab === 'install' && <InstallGuide agent={agent} />}

        {tab === 'policy' && (
          <PolicyTab agent={agent} onSaved={onPolicySaved} />
        )}

        {tab === 'capabilities' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-450 dark:text-slate-500 leading-relaxed font-semibold">
              {agent.mode === 'db'
                ? 'DB Monitor — intercepting direct database connection commands, TCP handshakes, and logins.'
                : 'PAM Endpoint Monitor — workstation surveillance matching active privileged workflows.'}
            </p>
            {MODE_CAPABILITIES[agent.mode].map((cap) => {
              const Icon = cap.icon;
              return (
                <div key={cap.label} className="flex items-start gap-3 p-4 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl shadow-sm">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 bg-indigo-50 dark:bg-indigo-950/40 text-brand-indigo">
                    <Icon size={15} />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-slate-900 dark:text-white">{cap.label}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed font-medium">{cap.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Agent Card ────────────────────────────────────────────────────────────────

function AgentCard({ agent, selected, onClick }: { agent: Agent; selected: boolean; onClick: () => void }) {
  return (
    <button 
      onClick={onClick}
      className={cn(
        "w-full text-left p-4 rounded-xl transition-all duration-150 border",
        selected 
          ? 'bg-brand-indigo/5 border-brand-indigo ring-1 ring-brand-indigo shadow-sm' 
          : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-350 dark:hover:border-slate-700 hover:bg-slate-50/50 dark:hover:bg-slate-900/50'
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className={cn(
            "w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0",
            agent.mode === 'pam' ? 'bg-purple-50 dark:bg-purple-950/40 text-brand-purple' : 'bg-blue-50 dark:bg-blue-950/40 text-brand-blue'
          )}>
            {agent.mode === 'pam' ? <Monitor size={14} /> : <Database size={14} />}
          </div>
          <div className="min-w-0">
            <p className="text-sm font-bold text-slate-900 dark:text-white truncate">{agent.name}</p>
            <div className="mt-0.5"><TypeBadge type={agent.db_type} mode={agent.mode} /></div>
          </div>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <StatusDot online={agent.online} />
          <ChevronRight size={14} className="text-slate-400 dark:text-slate-600" />
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2 text-center text-xs">
        <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-150/40 dark:border-slate-850">
          <p className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase">Events</p>
          <p className="text-sm font-bold text-brand-blue mt-0.5">{agent.events_today}</p>
        </div>
        <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-150/40 dark:border-slate-850">
          <p className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase">Sessions</p>
          <p className="text-sm font-bold text-brand-purple mt-0.5">{agent.active_sessions}</p>
        </div>
        <div className="p-2 rounded-lg bg-slate-50 dark:bg-slate-950/60 border border-slate-150/40 dark:border-slate-850 flex flex-col justify-between">
          <p className="text-[9px] font-bold text-slate-400 dark:text-slate-500 uppercase">Heartbeat</p>
          <p className={cn("text-[9px] font-bold mt-0.5 truncate", agent.online ? "text-brand-green" : "text-slate-400 dark:text-slate-550")}>
            {fmtRelative(agent.last_seen)}
          </p>
        </div>
      </div>
    </button>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export function Agents() {
  const [agents, setAgents]         = useState<Agent[]>([]);
  const [selected, setSelected]     = useState<Agent | null>(null);
  const [stats, setStats]           = useState<AgentStats | null>(null);
  const [loading, setLoading]       = useState(true);
  const [showRegister, setShowRegister] = useState(false);
  const [search, setSearch]         = useState('');
  const [modeFilter, setModeFilter] = useState<'all' | 'db' | 'pam'>('all');
  const [newKey, setNewKey]         = useState<{ name: string; key: string } | null>(null);
  // Whether metasight_enterprise is actually installed on this backend —
  // derived from the same /pam/agents probe loadAgents already makes below,
  // not a separate call. Defaults to false (locked) until proven otherwise,
  // so a slow/failed first load never briefly offers PAM mode in Community.
  const [pamAvailable, setPamAvailable] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadAgents = useCallback(async () => {
    // DB-mode agents (/agents) are always available. PAM-mode (/pam/agents)
    // only exists when metasight_enterprise is installed — request both and
    // tolerate the PAM one failing (404/network) rather than losing the DB
    // list because Enterprise isn't present.
    const [dbRes, pamRes] = await Promise.allSettled([
      api.get<Agent[]>('/agents/'),
      api.get<Agent[]>('/pam/agents/'),
    ]);
    const dbAgents  = dbRes.status  === 'fulfilled' ? dbRes.value.data  : [];
    const pamAgents = pamRes.status === 'fulfilled' ? pamRes.value.data : [];
    setAgents([...dbAgents, ...pamAgents]);
    setPamAvailable(pamRes.status === 'fulfilled');
    setLoading(false);
  }, []);

  const loadStats = useCallback(async (id: number, mode: 'db' | 'pam') => {
    try {
      const { data } = await api.get<AgentStats>(`${agentBase(mode)}/${id}/stats`);
      setStats(data);
    } catch {
      setStats(null);
    }
  }, []);

  useEffect(() => {
    loadAgents();
    intervalRef.current = setInterval(loadAgents, 15000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [loadAgents]);

  useEffect(() => {
    if (selected) loadStats(selected.id, selected.mode);
  }, [selected, loadStats]);

  const handleCreated = (a: Agent) => {
    setAgents(prev => [a, ...prev]);
    setSelected(a);
    setShowRegister(false);
  };

  const handleDelete = async (id: number) => {
    const target = agents.find(a => a.id === id);
    try {
      await api.delete(`${agentBase(target?.mode ?? 'db')}/${id}`);
      setAgents(prev => prev.filter(a => a.id !== id));
      if (selected?.id === id) setSelected(null);
    } catch {
      alert('Failed to delete agent');
    }
  };

  const handleRotateKey = async (id: number) => {
    const target = agents.find(a => a.id === id);
    try {
      const { data } = await api.post<Agent>(`${agentBase(target?.mode ?? 'db')}/${id}/rotate-key`);
      setAgents(prev => prev.map(a => a.id === id ? { ...a } : a));
      setNewKey({ name: data.name, key: data.api_key ?? '' });
    } catch {
      alert('Failed to rotate key');
    }
  };

  const filtered = agents.filter(a => {
    const matchSearch = !search || a.name.toLowerCase().includes(search.toLowerCase()) || a.db_type.includes(search.toLowerCase());
    const matchMode   = modeFilter === 'all' || a.mode === modeFilter;
    return matchSearch && matchMode;
  });

  const totalOnline   = agents.filter(a => a.online).length;
  const totalOffline  = agents.length - totalOnline;
  const totalEvents   = agents.reduce((s, a) => s + a.events_today, 0);
  const totalSessions = agents.reduce((s, a) => s + a.active_sessions, 0);

  return (
    <div className="flex flex-col -mx-8 -my-6 h-[calc(100vh-56px)] bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100">
      
      {/* Rotated key toast */}
      {newKey && (
        <div className="fixed top-4 right-4 z-50 p-5 rounded-2xl shadow-2xl max-w-sm bg-white dark:bg-slate-900 border border-amber-300 dark:border-amber-800 animate-scale-up">
          <div className="flex items-start justify-between gap-3 mb-3">
            <div>
              <p className="text-sm font-bold text-amber-700 dark:text-amber-400">Credentials Rotated Successfully</p>
              <p className="text-[10px] text-slate-450 dark:text-slate-500 font-semibold uppercase mt-0.5">Agent: {newKey.name}</p>
            </div>
            <button onClick={() => setNewKey(null)} className="text-slate-400 hover:text-slate-650 dark:hover:text-slate-200">
              <X size={14} />
            </button>
          </div>
          <div className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950">
            <code className="text-xs font-mono text-amber-600 dark:text-amber-300 flex-1 break-all select-all font-semibold">{newKey.key}</code>
            <CopyBtn text={newKey.key} />
          </div>
          <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-2">The previous API key is immediately invalidated and rejected.</p>
        </div>
      )}

      {/* Page header */}
      <div className="flex-shrink-0 px-8 py-5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center bg-indigo-50 dark:bg-indigo-950/40 text-brand-indigo">
                <Bot size={16} />
              </div>
              <h1 className="text-xl font-bold text-slate-900 dark:text-white">Agent Infrastructure Management</h1>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 ml-11">
              Configure, audit, and provision MetaSight monitoring agents across servers and workstations.
            </p>
          </div>
          
          <div className="flex items-center gap-2 ml-11 md:ml-0">
            <button 
              onClick={loadAgents}
              className="premium-btn-secondary py-2 text-xs gap-1.5"
              title="Refresh Agents"
            >
              <RefreshCw size={13} />
            </button>
            {isAdmin() && (
              <button 
                onClick={() => setShowRegister(true)}
                className="premium-btn-primary py-2 text-xs gap-1.5 shadow-indigo-500/10"
              >
                <Plus size={13} /> 
                Register New Agent
              </button>
            )}
          </div>
        </div>

        {/* System telemetry stats row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: 'Registered Agents', value: agents.length, icon: Bot,      color: 'text-brand-indigo bg-brand-indigo/5 dark:bg-brand-indigo/10' },
            { label: 'Active Online',           value: totalOnline,   icon: Wifi,     color: 'text-brand-green bg-emerald-50 dark:bg-emerald-950/20' },
            { label: 'Offline / Decommissioned',          value: totalOffline,  icon: WifiOff,  color: 'text-slate-400 bg-slate-100 dark:bg-slate-800' },
            { label: 'Risk Events Today',     value: totalEvents,   icon: Zap,      color: 'text-brand-orange bg-amber-50 dark:bg-amber-950/20' },
          ].map(s => {
            const Icon = s.icon;
            return (
              <div key={s.label} className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl">
                <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0", s.color)}>
                  <Icon size={14} />
                </div>
                <div>
                  <p className="text-[10px] text-slate-450 dark:text-slate-500 font-bold uppercase tracking-wider">{s.label}</p>
                  <p className="text-lg font-bold text-slate-800 dark:text-white mt-0.5">{s.value}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Content area splitting */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left pane: Agent list */}
        <div className="flex flex-col w-80 flex-shrink-0 overflow-hidden border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/50">
          
          {/* Search filter bar */}
          <div className="flex-shrink-0 p-3 space-y-2 border-b border-slate-200/60 dark:border-slate-800">
            <div className="relative">
              <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                value={search} 
                onChange={e => setSearch(e.target.value)}
                placeholder="Search registered agents…"
                className="premium-input pl-8 py-1.5 text-xs"
              />
            </div>
            
            <div className="flex gap-1 p-0.5 bg-slate-100 dark:bg-slate-900/80 rounded-xl border border-slate-200/65 dark:border-slate-800/80">
              {(['all', 'db', 'pam'] as const).map(m => (
                <button 
                  key={m} 
                  onClick={() => setModeFilter(m)}
                  className={cn(
                    "flex-1 py-1 rounded-lg text-[10px] font-bold transition-all",
                    modeFilter === m 
                      ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-white shadow-sm' 
                      : 'text-slate-450 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-350'
                  )}
                >
                  {m === 'all' ? 'All' : m === 'db' ? 'DB Mode' : 'PAM Mode'}
                </button>
              ))}
            </div>
          </div>

          {/* Cards List container */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {loading ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <RefreshCw size={16} className="animate-spin text-slate-400" />
                <span className="text-xs text-slate-400">Loading infrastructure list...</span>
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center px-4">
                <Bot size={28} className="text-slate-400 dark:text-slate-600 mb-3 opacity-60" />
                <p className="text-xs font-bold text-slate-700 dark:text-slate-300">No agents registered</p>
                <p className="text-[11px] text-slate-400 dark:text-slate-500 mt-1 leading-relaxed">
                  {agents.length === 0 
                    ? 'Register your first database or user workstation agent to start audits.' 
                    : 'No agents match your current query or filters.'}
                </p>
                {agents.length === 0 && isAdmin() && (
                  <button 
                    onClick={() => setShowRegister(true)}
                    className="mt-4 premium-btn-primary py-1.5 px-3 text-xs"
                  >
                    + Register First Agent
                  </button>
                )}
              </div>
            ) : (
              filtered.map(a => (
                <AgentCard 
                  key={a.id} 
                  agent={a} 
                  selected={selected?.id === a.id}
                  onClick={() => { setSelected(a); setStats(null); }} 
                />
              ))
            )}
          </div>

          {/* Left panel footer */}
          {agents.length > 0 && (
            <div className="flex-shrink-0 px-4 py-2 border-t border-slate-200 dark:border-slate-800 text-center bg-slate-50/50 dark:bg-slate-900/30">
              <span className="text-[10px] font-semibold text-slate-400 dark:text-slate-500">
                Displaying {filtered.length} of {agents.length} agents · {totalSessions} session(s) active
              </span>
            </div>
          )}
        </div>

        {/* Right pane: Agent info details display */}
        <div className="flex-1 overflow-hidden">
          {selected ? (
            <DetailPanel
              agent={selected}
              stats={stats}
              onClose={() => setSelected(null)}
              onDelete={handleDelete}
              onRotateKey={handleRotateKey}
              onPolicySaved={(patch) => {
                setSelected(prev => {
                  if (prev) {
                    setAgents(agentsPrev => agentsPrev.map(a => a.id === prev.id ? { ...a, ...patch } : a));
                    return { ...prev, ...patch };
                  }
                  return prev;
                });
              }}
            />
          ) : (
            /* Welcome / Unselected view */
            <div className="flex flex-col items-center justify-center h-full text-center px-8 bg-white dark:bg-slate-900">
              <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-5 bg-indigo-50 dark:bg-indigo-950/20 border border-indigo-100 dark:border-indigo-900/10 text-brand-indigo">
                <Bot size={28} />
              </div>
              <h2 className="text-base font-bold text-slate-900 dark:text-white mb-2">No Agent Selected</h2>
              <p className="text-xs text-slate-450 dark:text-slate-500 max-w-xs leading-relaxed mb-6 font-medium">
                Select an agent from the side panel to view config policies, download binaries, inspect live events, and configure security rules.
              </p>

              {/* Capability Grid overview card */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-xl w-full">
                {[
                  { 
                    mode: 'Database Agents', 
                    icon: Database, 
                    items: ['Direct session intercepts', 'SQL DDL statement blocking', 'IP & user allowlists', 'Bypass alarm triggers'], 
                    color: 'text-brand-blue bg-blue-50 dark:bg-blue-950/20' 
                  },
                  { 
                    mode: 'PAM Workstation Endpoint', 
                    icon: Monitor, 
                    items: ['Workstation screenshot feeds', 'USB drive monitor & block', 'Workplace keystroke logging', 'Blacklisted application check'], 
                    color: 'text-brand-purple bg-purple-50 dark:bg-purple-950/20' 
                  },
                ].map(g => {
                  const Icon = g.icon;
                  return (
                    <div key={g.mode} className="p-4 bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-xl text-left shadow-sm">
                      <div className="flex items-center gap-2 mb-3">
                        <span className={cn("p-1.5 rounded-lg text-xs", g.color)}>
                          <Icon size={14} />
                        </span>
                        <span className="text-xs font-bold text-slate-800 dark:text-white">{g.mode}</span>
                      </div>
                      <div className="space-y-2">
                        {g.items.map(item => (
                          <div key={item} className="flex items-center gap-2 text-[10px] text-slate-500 dark:text-slate-400 font-medium">
                            <Check size={12} className="text-brand-green shrink-0 stroke-[3]" />
                            <span>{item}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>

      {showRegister && (
        <RegisterModal onClose={() => setShowRegister(false)} onCreated={handleCreated} pamAvailable={pamAvailable} />
      )}
    </div>
  );
}
