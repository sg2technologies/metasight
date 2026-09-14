import React, { useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import {
  Settings2, Palette, Shield, Zap, EyeOff, ClipboardList, Bell,
  Save, RotateCcw, Mail, CheckCircle, XCircle, Loader2, Info,
  KeyRound, AlertTriangle, RefreshCw, Lock,
} from 'lucide-react';
import { cn } from '../lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

interface BrandingCfg {
  platform_name: string; tagline: string; logo_url: string | null;
  primary_color: string; accent_color: string;
  support_email: string | null; docs_url: string | null;
}
interface SecurityCfg {
  session_timeout_minutes: number; max_login_attempts: number;
  lockout_duration_minutes: number; ip_allowlist: string[];
  require_mfa: boolean; password_min_length: number;
  password_require_uppercase: boolean; password_require_number: boolean;
  password_require_special: boolean; jwt_expire_minutes: number;
}
interface QueryGatewayCfg {
  max_rows_per_query: number; default_limit: number;
  rate_limit_per_minute: number; risk_threshold_medium: number;
  risk_threshold_high: number; risk_threshold_critical: number;
  approval_ttl_hours: number; allow_ddl: boolean;
  allow_dml: boolean; require_table_policy: boolean;
}
interface MaskingCfg {
  role_levels: Record<string, string>;
  partial_mask_char: string; partial_visible_chars: number;
}
interface AuditCfg {
  retention_days: number; log_successful_queries: boolean;
  log_denied_queries: boolean; log_policy_changes: boolean;
  log_login_events: boolean;
}
interface NotificationsCfg {
  smtp_host: string | null; smtp_port: number;
  smtp_user: string | null; smtp_password: string | null;
  smtp_from: string | null; smtp_tls: boolean;
  alert_on_critical_risk: boolean; alert_on_approval_request: boolean;
  alert_emails: string[]; slack_webhook_url: string | null;
  teams_webhook_url: string | null;
}
interface FullConfig {
  branding: BrandingCfg;
  security: SecurityCfg;
  query_gateway: QueryGatewayCfg;
  masking: MaskingCfg;
  audit: AuditCfg;
  notifications: NotificationsCfg;
}

// ── Tab definitions ───────────────────────────────────────────────────────────

const TABS = [
  { id: 'branding',      label: 'Branding',       icon: Palette       },
  { id: 'security',      label: 'Security',        icon: Shield        },
  { id: 'query_gateway', label: 'Query Gateway',   icon: Zap           },
  { id: 'masking',       label: 'Data Masking',    icon: EyeOff        },
  { id: 'audit',         label: 'Audit & Logs',    icon: ClipboardList },
  { id: 'notifications', label: 'Notifications',   icon: Bell          },
  { id: 'vault',         label: 'Vault',           icon: KeyRound      },
] as const;

type TabId = typeof TABS[number]['id'];

// ── Small UI helpers ──────────────────────────────────────────────────────────

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500 mb-4 mt-6 first:mt-0 font-display">
      {children}
    </h3>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="mb-5">
      <label className="block text-sm font-semibold text-slate-700 dark:text-slate-350 mb-1">{label}</label>
      {hint && <p className="text-xs text-slate-400 dark:text-slate-500 mb-2 leading-relaxed">{hint}</p>}
      {children}
    </div>
  );
}

const inputCls = "w-full px-3 py-2 text-sm border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500/25 focus:border-indigo-500 transition-all duration-150";
const toggleCls = (on: boolean) =>
  cn("relative inline-flex h-5 w-9 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200",
    on ? "bg-brand-indigo" : "bg-slate-200 dark:bg-slate-850");

function Toggle({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) {
  return (
    <button type="button" className={toggleCls(value)} onClick={() => onChange(!value)} role="switch" aria-checked={value}>
      <span
        className={cn("pointer-events-none block h-4 w-4 rounded-full bg-white shadow ring-0 transition-transform duration-200",
          value ? "translate-x-4" : "translate-x-0")}
      />
    </button>
  );
}

function NumberInput({ value, onChange, min, max }: { value: number; onChange: (v: number) => void; min?: number; max?: number }) {
  return (
    <input
      type="number"
      className={inputCls}
      value={value}
      min={min}
      max={max}
      onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(Number(e.target.value))}
    />
  );
}

function TextInput({ value, onChange, placeholder, type = 'text' }: { value: string; onChange: (v: string) => void; placeholder?: string; type?: string }) {
  return (
    <input
      type={type}
      className={inputCls}
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e: React.ChangeEvent<HTMLInputElement>) => onChange(e.target.value)}
    />
  );
}

function TagInput({ values, onChange, placeholder }: { values: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const v = draft.trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setDraft('');
  };
  return (
    <div>
      <div className="flex flex-wrap gap-1.5 mb-2 min-h-[28px]">
        {values.map(v => (
          <span key={v} className="inline-flex items-center gap-1.5 px-2 py-0.5 text-xs rounded-lg bg-indigo-55/60 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-400 border border-indigo-100 dark:border-indigo-900/60 font-semibold font-mono">
            {v}
            <button type="button" onClick={() => onChange(values.filter(x => x !== v))} className="hover:text-red-500 font-bold">×</button>
          </span>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          className={inputCls}
          value={draft}
          placeholder={placeholder}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); }}}
        />
        <button type="button" onClick={add} className="px-3.5 py-2 text-xs font-semibold text-indigo-700 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/20 border border-indigo-200 dark:border-indigo-900/60 rounded-lg hover:bg-indigo-100 dark:hover:bg-indigo-950/40 transition active:scale-[0.98]">Add</button>
      </div>
    </div>
  );
}

function SelectInput({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <select
      className={inputCls}
      value={value}
      onChange={(e: React.ChangeEvent<HTMLSelectElement>) => onChange(e.target.value)}
    >
      {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}

// ── Vault tab ─────────────────────────────────────────────────────────────────

function VaultTab() {
  const [status, setStatus] = useState<{ configured: boolean; reachable: boolean; vault_addr: string } | null>(null);
  const [checking, setChecking] = useState(false);
  const [vaultSources, setVaultSources] = useState<any[]>([]);

  const checkStatus = async () => {
    setChecking(true);
    try {
      const [statusRes, sourcesRes] = await Promise.all([
        api.get('/settings/vault/status'),
        api.get('/sources'),
      ]);
      setStatus(statusRes.data);
      setVaultSources((sourcesRes.data.items || []).filter((s: any) => s.vault_path));
    } catch {
      setStatus(null);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => { checkStatus(); }, []);

  return (
    <div className="space-y-6">
      <SectionTitle>HashiCorp Vault Integration</SectionTitle>

      {/* Status card */}
      <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-5 bg-slate-50 dark:bg-slate-900/40">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-brand-purple" />
            <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">Vault Connection Status</span>
          </div>
          <button
            onClick={checkStatus}
            disabled={checking}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 dark:text-slate-350 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/60 disabled:opacity-50 transition active:scale-[0.97]"
          >
            <RefreshCw className={cn('h-3.5 w-3.5', checking && 'animate-spin')} />
            Refresh
          </button>
        </div>

        {status === null ? (
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <Loader2 className="h-4 w-4 animate-spin text-brand-indigo" />
            Checking status…
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className={cn(
                'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold',
                status.configured
                  ? 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-400 border border-emerald-250 dark:border-emerald-900/60'
                  : 'bg-slate-100 dark:bg-slate-800/40 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700/60'
              )}>
                {status.configured
                  ? <><CheckCircle className="h-3.5 w-3.5 text-brand-green" /> Configured</>
                  : <><XCircle className="h-3.5 w-3.5 text-slate-400" /> Not configured</>}
              </div>
              {status.configured && (
                <div className={cn(
                  'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold',
                  status.reachable
                    ? 'bg-emerald-50 dark:bg-emerald-950/20 text-emerald-700 dark:text-emerald-400 border border-emerald-250 dark:border-emerald-900/60'
                    : 'bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/60'
                )}>
                  {status.reachable
                    ? <><CheckCircle className="h-3.5 w-3.5 text-brand-green" /> Authenticated</>
                    : <><AlertTriangle className="h-3.5 w-3.5 text-brand-orange" /> Unreachable</>}
                </div>
              )}
            </div>
            {status.vault_addr && (
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Server: <code className="bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300 font-mono">{status.vault_addr}</code>
              </p>
            )}
          </div>
        )}
      </div>

      {/* Setup instructions */}
      {(!status?.configured) && (
        <div className="border border-amber-200 dark:border-amber-900/50 rounded-xl p-5 bg-amber-50 dark:bg-amber-950/20">
          <div className="flex items-start gap-2 mb-3">
            <Info className="h-4 w-4 text-amber-600 dark:text-amber-500 mt-0.5 flex-shrink-0" />
            <span className="text-sm font-semibold text-amber-800 dark:text-amber-300 font-display">How to enable HashiCorp Vault</span>
          </div>
          <p className="text-xs text-amber-750 dark:text-amber-400 mb-3 leading-relaxed">
            Add the following variables to <code className="bg-amber-100 dark:bg-slate-800 px-1 rounded font-mono text-slate-800 dark:text-slate-205">backend/.env</code> and restart the backend service:
          </p>
          <pre className="bg-white dark:bg-slate-950 border border-amber-200 dark:border-slate-800 rounded-lg px-4 py-3 text-xs text-slate-750 dark:text-slate-300 font-mono overflow-x-auto leading-relaxed">
{`# HashiCorp Vault
VAULT_ADDR=http://your-vault-server:8200
VAULT_TOKEN=your-root-or-approle-token`}
          </pre>
          <p className="mt-3 text-xs text-amber-700 dark:text-amber-400 leading-relaxed font-medium">
            Vault KV v2 secrets engine is required. Each secret must contain the same keys as the
            connector's JSON config (e.g. <code className="bg-amber-100 dark:bg-slate-800 px-1 rounded font-mono font-bold">host</code>,{' '}
            <code className="bg-amber-100 dark:bg-slate-800 px-1 rounded font-mono font-bold">port</code>,{' '}
            <code className="bg-amber-100 dark:bg-slate-800 px-1 rounded font-mono font-bold">username</code>,{' '}
            <code className="bg-amber-100 dark:bg-slate-800 px-1 rounded font-mono font-bold">password</code>).
          </p>
        </div>
      )}

      {/* How to use on a data source */}
      <div className="border border-slate-200 dark:border-slate-800 rounded-xl p-5 bg-white dark:bg-slate-900">
        <div className="flex items-start gap-2 mb-3">
          <Lock className="h-4 w-4 text-brand-purple mt-0.5 flex-shrink-0" />
          <span className="text-sm font-semibold text-slate-700 dark:text-slate-350 font-display">Using Vault with Data Sources</span>
        </div>
        <p className="text-xs text-slate-650 dark:text-slate-400 mb-3 leading-relaxed">
          When a data source has a Vault path set, credentials are fetched from Vault at runtime instead of
          using the encrypted config stored in MetaSight. This eliminates secrets from the database entirely.
        </p>
        <ol className="text-xs text-slate-650 dark:text-slate-400 space-y-2 list-decimal list-inside leading-relaxed">
          <li>Store the database credentials in Vault under a KV v2 path, e.g.<br/>
            <code className="bg-slate-100 dark:bg-slate-950 px-2 py-0.5 rounded block mt-1 ml-4 font-mono text-slate-700 dark:text-slate-300 border border-slate-200/50 dark:border-slate-800">vault kv put secret/datasources/prod-pg host=db.example.com port=5432 username=app password=s3cr3t dbname=prod</code>
          </li>
          <li>Go to <strong>Data Sources</strong>, edit a connection, and set the <strong>Vault Path</strong> to that path.</li>
          <li>MetaSight will fetch credentials from Vault on each connection, falling back to the encrypted config if Vault is unreachable.</li>
        </ol>
      </div>

      {/* Data sources using Vault */}
      <div className="space-y-3">
        <SectionTitle>Data Sources Using Vault ({vaultSources.length})</SectionTitle>
        {vaultSources.length === 0 ? (
          <p className="text-sm text-slate-400 dark:text-slate-550 italic">No data sources have a Vault path configured yet.</p>
        ) : (
          <div className="divide-y divide-slate-100 dark:divide-slate-800/60 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
            {vaultSources.map((s: any) => (
              <div key={s.id} className="flex items-center gap-3 px-4 py-3 bg-white dark:bg-slate-900 hover:bg-slate-50/50 dark:hover:bg-slate-800/20 transition-colors">
                <KeyRound className="h-4 w-4 text-brand-purple flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-slate-750 dark:text-slate-200 truncate">{s.name}</p>
                  <p className="text-xs text-slate-450 dark:text-slate-500 font-mono truncate">{s.vault_path}</p>
                </div>
                <span className="text-xs text-slate-450 dark:text-slate-550 font-bold font-mono uppercase">{s.type}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab panels ────────────────────────────────────────────────────────────────

function BrandingTab({ cfg, set }: { cfg: BrandingCfg; set: (p: Partial<BrandingCfg>) => void }) {
  return (
    <div>
      <SectionTitle>Platform Identity</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Platform Name">
          <TextInput value={cfg.platform_name} onChange={v => set({ platform_name: v })} placeholder="MetaSight" />
        </Field>
        <Field label="Tagline">
          <TextInput value={cfg.tagline} onChange={v => set({ tagline: v })} placeholder="Data Governance Platform" />
        </Field>
        <Field label="Logo URL" hint="Leave empty to use the built-in MetaSight logo.">
          <TextInput value={cfg.logo_url ?? ''} onChange={v => set({ logo_url: v || null })} placeholder="https://your-cdn.com/logo.svg" />
        </Field>
        <Field label="Support Email">
          <TextInput value={cfg.support_email ?? ''} onChange={v => set({ support_email: v || null })} placeholder="support@company.com" type="email" />
        </Field>
        <Field label="Docs URL">
          <TextInput value={cfg.docs_url ?? ''} onChange={v => set({ docs_url: v || null })} placeholder="https://docs.company.com" />
        </Field>
      </div>
      <SectionTitle>Colors</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Primary Color" hint="Used for active nav, buttons, badges.">
          <div className="flex items-center gap-3">
            <input type="color" value={cfg.primary_color} onChange={(e: React.ChangeEvent<HTMLInputElement>) => set({ primary_color: e.target.value })} className="h-9 w-14 rounded border border-slate-200 cursor-pointer p-0.5" />
            <TextInput value={cfg.primary_color} onChange={v => set({ primary_color: v })} placeholder="#818CF8" />
          </div>
        </Field>
        <Field label="Accent Color" hint="Used for highlights and gradients.">
          <div className="flex items-center gap-3">
            <input type="color" value={cfg.accent_color} onChange={(e: React.ChangeEvent<HTMLInputElement>) => set({ accent_color: e.target.value })} className="h-9 w-14 rounded border border-slate-200 cursor-pointer p-0.5" />
            <TextInput value={cfg.accent_color} onChange={v => set({ accent_color: v })} placeholder="#38BDF8" />
          </div>
        </Field>
      </div>
    </div>
  );
}

function SecurityTab({ cfg, set }: { cfg: SecurityCfg; set: (p: Partial<SecurityCfg>) => void }) {
  return (
    <div>
      <SectionTitle>Session & Tokens</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="JWT / Session Timeout (minutes)" hint="Users are logged out after this many idle minutes.">
          <NumberInput value={cfg.jwt_expire_minutes} onChange={v => set({ jwt_expire_minutes: v, session_timeout_minutes: v })} min={5} />
        </Field>
      </div>
      <SectionTitle>Login Lockout</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Max Login Attempts" hint="Account locks after this many consecutive failures.">
          <NumberInput value={cfg.max_login_attempts} onChange={v => set({ max_login_attempts: v })} min={1} max={20} />
        </Field>
        <Field label="Lockout Duration (minutes)">
          <NumberInput value={cfg.lockout_duration_minutes} onChange={v => set({ lockout_duration_minutes: v })} min={1} />
        </Field>
      </div>
      <SectionTitle>Password Policy</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Minimum Length">
          <NumberInput value={cfg.password_min_length} onChange={v => set({ password_min_length: v })} min={6} max={128} />
        </Field>
      </div>
      <div className="flex flex-col gap-3 mt-1">
        {([
          ['password_require_uppercase', 'Require uppercase letter'],
          ['password_require_number',    'Require number'],
          ['password_require_special',   'Require special character'],
          ['require_mfa',               'Require MFA (future)'],
        ] as [keyof SecurityCfg, string][]).map(([key, label]) => (
          <div key={key} className="flex items-center justify-between py-2 border-b border-slate-100 last:border-0">
            <span className="text-sm text-slate-700">{label}</span>
            <Toggle value={cfg[key] as boolean} onChange={v => set({ [key]: v } as Partial<SecurityCfg>)} />
          </div>
        ))}
      </div>
      <SectionTitle>Network</SectionTitle>
      <Field label="IP Allowlist" hint="Restrict platform access to specific IPs / CIDRs. Leave empty to allow all.">
        <TagInput values={cfg.ip_allowlist} onChange={v => set({ ip_allowlist: v })} placeholder="192.168.1.0/24" />
      </Field>
    </div>
  );
}

function QueryGatewayTab({ cfg, set }: { cfg: QueryGatewayCfg; set: (p: Partial<QueryGatewayCfg>) => void }) {
  return (
    <div>
      <SectionTitle>Row Limits</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Max Rows Per Query" hint="Hard cap; queries will be truncated.">
          <NumberInput value={cfg.max_rows_per_query} onChange={v => set({ max_rows_per_query: v })} min={1} />
        </Field>
        <Field label="Default Limit" hint="Applied when the query has no LIMIT clause.">
          <NumberInput value={cfg.default_limit} onChange={v => set({ default_limit: v })} min={1} />
        </Field>
      </div>
      <SectionTitle>Rate Limiting</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Queries Per Minute (per user)">
          <NumberInput value={cfg.rate_limit_per_minute} onChange={v => set({ rate_limit_per_minute: v })} min={1} />
        </Field>
      </div>
      <SectionTitle>Risk Thresholds</SectionTitle>
      <div className="grid grid-cols-3 gap-x-6">
        <Field label="Medium (≥ score)">
          <NumberInput value={cfg.risk_threshold_medium} onChange={v => set({ risk_threshold_medium: v })} min={0} max={100} />
        </Field>
        <Field label="High (≥ score)">
          <NumberInput value={cfg.risk_threshold_high} onChange={v => set({ risk_threshold_high: v })} min={0} max={100} />
        </Field>
        <Field label="Critical (≥ score)" hint="Triggers approval workflow.">
          <NumberInput value={cfg.risk_threshold_critical} onChange={v => set({ risk_threshold_critical: v })} min={0} max={100} />
        </Field>
      </div>
      <SectionTitle>Approval Workflow</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Approval Token TTL (hours)" hint="How long an approval is valid after an admin grants it.">
          <NumberInput value={cfg.approval_ttl_hours} onChange={v => set({ approval_ttl_hours: v })} min={1} max={168} />
        </Field>
      </div>
      <SectionTitle>Allowed Operations</SectionTitle>
      <div className="flex flex-col gap-3 mt-1">
        {([
          ['allow_ddl',              'Allow DDL statements (CREATE, DROP, ALTER)'],
          ['allow_dml',              'Allow DML statements (INSERT, UPDATE, DELETE)'],
          ['require_table_policy',   'Block queries on tables without a policy'],
        ] as [keyof QueryGatewayCfg, string][]).map(([key, label]) => (
          <div key={key} className="flex items-center justify-between py-2 border-b border-slate-100 last:border-0">
            <span className="text-sm text-slate-700">{label}</span>
            <Toggle value={cfg[key] as boolean} onChange={v => set({ [key]: v } as Partial<QueryGatewayCfg>)} />
          </div>
        ))}
      </div>
    </div>
  );
}

const MASKING_OPTIONS = [
  { value: 'raw',     label: 'Raw — no masking' },
  { value: 'partial', label: 'Partial — show last N chars' },
  { value: 'full',    label: 'Full — maximum protection' },
];

function MaskingTab({ cfg, set }: { cfg: MaskingCfg; set: (p: Partial<MaskingCfg>) => void }) {
  const roles = ['admin', 'manager', 'analyst', 'viewer'];
  return (
    <div>
      <SectionTitle>Role → Masking Level</SectionTitle>
      <p className="text-xs text-slate-400 mb-4">
        Controls how PII columns are presented to each role when executing queries.
      </p>
      <div className="flex flex-col gap-3">
        {roles.map(role => (
          <div key={role} className="flex items-center gap-4">
            <span className="w-24 text-sm font-medium text-slate-700 capitalize">{role}</span>
            <div className="flex-1 max-w-xs">
              <SelectInput
                value={cfg.role_levels[role] ?? 'full'}
                onChange={v => set({ role_levels: { ...cfg.role_levels, [role]: v } })}
                options={MASKING_OPTIONS}
              />
            </div>
          </div>
        ))}
      </div>
      <SectionTitle>Partial Masking</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Mask Character">
          <TextInput value={cfg.partial_mask_char} onChange={v => set({ partial_mask_char: v.charAt(0) || '*' })} placeholder="*" />
        </Field>
        <Field label="Visible Characters" hint="Number of characters shown at the end of the value.">
          <NumberInput value={cfg.partial_visible_chars} onChange={v => set({ partial_visible_chars: v })} min={1} max={10} />
        </Field>
      </div>
    </div>
  );
}

function AuditTab({ cfg, set }: { cfg: AuditCfg; set: (p: Partial<AuditCfg>) => void }) {
  return (
    <div>
      <SectionTitle>Retention</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Retention Period (days)" hint="Audit logs older than this are eligible for cleanup.">
          <NumberInput value={cfg.retention_days} onChange={v => set({ retention_days: v })} min={1} />
        </Field>
      </div>
      <SectionTitle>What to Log</SectionTitle>
      <div className="flex flex-col gap-3 mt-1">
        {([
          ['log_successful_queries', 'Log successful queries'],
          ['log_denied_queries',     'Log denied / policy-blocked queries'],
          ['log_policy_changes',     'Log policy create / update / delete'],
          ['log_login_events',       'Log login attempts (success & failure)'],
        ] as [keyof AuditCfg, string][]).map(([key, label]) => (
          <div key={key} className="flex items-center justify-between py-2 border-b border-slate-100 last:border-0">
            <span className="text-sm text-slate-700">{label}</span>
            <Toggle value={cfg[key] as boolean} onChange={v => set({ [key]: v } as Partial<AuditCfg>)} />
          </div>
        ))}
      </div>
    </div>
  );
}

function NotificationsTab({
  cfg, set, onTestSmtp, testState,
}: {
  cfg: NotificationsCfg;
  set: (p: Partial<NotificationsCfg>) => void;
  onTestSmtp: () => void;
  testState: 'idle' | 'loading' | 'ok' | 'error';
}) {
  return (
    <div>
      <SectionTitle>SMTP Configuration</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="SMTP Host">
          <TextInput value={cfg.smtp_host ?? ''} onChange={v => set({ smtp_host: v || null })} placeholder="smtp.company.com" />
        </Field>
        <Field label="SMTP Port">
          <NumberInput value={cfg.smtp_port} onChange={v => set({ smtp_port: v })} min={1} max={65535} />
        </Field>
        <Field label="SMTP Username">
          <TextInput value={cfg.smtp_user ?? ''} onChange={v => set({ smtp_user: v || null })} placeholder="alerts@company.com" />
        </Field>
        <Field label="SMTP Password">
          <TextInput value={cfg.smtp_password ?? ''} onChange={v => set({ smtp_password: v || null })} placeholder="••••••••" type="password" />
        </Field>
        <Field label="From Address">
          <TextInput value={cfg.smtp_from ?? ''} onChange={v => set({ smtp_from: v || null })} placeholder="MetaSight <alerts@company.com>" />
        </Field>
      </div>
      <div className="flex items-center justify-between py-2 border-b border-slate-100">
        <span className="text-sm text-slate-700">Use TLS (STARTTLS)</span>
        <Toggle value={cfg.smtp_tls} onChange={v => set({ smtp_tls: v })} />
      </div>
      <div className="mt-4">
        <button
          type="button"
          onClick={onTestSmtp}
          disabled={testState === 'loading'}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition disabled:opacity-50"
        >
          {testState === 'loading' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />}
          Send Test Email
          {testState === 'ok'    && <CheckCircle className="h-4 w-4 text-green-500" />}
          {testState === 'error' && <XCircle className="h-4 w-4 text-red-500" />}
        </button>
      </div>

      <SectionTitle>Alert Recipients</SectionTitle>
      <Field label="Alert Emails" hint="Press Enter or click Add to add each address.">
        <TagInput values={cfg.alert_emails} onChange={v => set({ alert_emails: v })} placeholder="admin@company.com" />
      </Field>

      <SectionTitle>Alert Triggers</SectionTitle>
      <div className="flex flex-col gap-3 mt-1">
        {([
          ['alert_on_critical_risk',      'Alert on CRITICAL risk queries'],
          ['alert_on_approval_request',   'Alert admins when approval is requested'],
        ] as [keyof NotificationsCfg, string][]).map(([key, label]) => (
          <div key={key} className="flex items-center justify-between py-2 border-b border-slate-100 last:border-0">
            <span className="text-sm text-slate-700">{label}</span>
            <Toggle value={cfg[key] as boolean} onChange={v => set({ [key]: v } as Partial<NotificationsCfg>)} />
          </div>
        ))}
      </div>

      <SectionTitle>Webhook Integrations</SectionTitle>
      <div className="grid grid-cols-2 gap-x-6">
        <Field label="Slack Webhook URL">
          <TextInput value={cfg.slack_webhook_url ?? ''} onChange={v => set({ slack_webhook_url: v || null })} placeholder="https://hooks.slack.com/services/..." />
        </Field>
        <Field label="Microsoft Teams Webhook URL">
          <TextInput value={cfg.teams_webhook_url ?? ''} onChange={v => set({ teams_webhook_url: v || null })} placeholder="https://outlook.office.com/webhook/..." />
        </Field>
      </div>
    </div>
  );
}

// ── Main Settings page ────────────────────────────────────────────────────────

export function Settings() {
  const [activeTab, setActiveTab] = useState<TabId>('branding');
  const [config, setConfig] = useState<FullConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);
  const [smtpTest, setSmtpTest] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle');

  const showToast = (type: 'success' | 'error', msg: string) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 3500);
  };

  useEffect(() => {
    api.get('/settings')
      .then(r => setConfig(r.data))
      .catch(() => showToast('error', 'Failed to load settings'))
      .finally(() => setLoading(false));
  }, []);

  const patch = useCallback((section: keyof FullConfig, partial: object) => {
    setConfig(prev => prev ? { ...prev, [section]: { ...prev[section], ...partial } } : prev);
  }, []);

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    try {
      const r = await api.put('/settings', config);
      setConfig(r.data);
      showToast('success', 'Settings saved successfully.');
    } catch {
      showToast('error', 'Failed to save settings.');
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    if (!window.confirm('Reset all settings to platform defaults? This cannot be undone.')) return;
    try {
      const r = await api.post('/settings/reset');
      setConfig(r.data.config);
      showToast('success', 'Settings reset to defaults.');
    } catch {
      showToast('error', 'Failed to reset settings.');
    }
  };

  const handleSmtpTest = async () => {
    setSmtpTest('loading');
    try {
      await api.post('/settings/smtp/test');
      setSmtpTest('ok');
    } catch {
      setSmtpTest('error');
    } finally {
      setTimeout(() => setSmtpTest('idle'), 4000);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-indigo-400" />
      </div>
    );
  }

  if (!config) return null;

  const renderPanel = () => {
    switch (activeTab) {
      case 'branding':
        return <BrandingTab cfg={config.branding} set={p => patch('branding', p)} />;
      case 'security':
        return <SecurityTab cfg={config.security} set={p => patch('security', p)} />;
      case 'query_gateway':
        return <QueryGatewayTab cfg={config.query_gateway} set={p => patch('query_gateway', p)} />;
      case 'masking':
        return <MaskingTab cfg={config.masking} set={p => patch('masking', p)} />;
      case 'audit':
        return <AuditTab cfg={config.audit} set={p => patch('audit', p)} />;
      case 'notifications':
        return (
          <NotificationsTab
            cfg={config.notifications}
            set={p => patch('notifications', p)}
            onTestSmtp={handleSmtpTest}
            testState={smtpTest}
          />
        );
      case 'vault':
        return <VaultTab />;
    }
  };

  return (
    <div className="space-y-6 animate-fade-in text-slate-800 dark:text-slate-100">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-100 dark:border-slate-800/80 pb-5">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center shadow-lg" style={{ background: 'linear-gradient(135deg,#818CF8,#A855F7)' }}>
            <Settings2 className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-550 font-display">System Settings</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Configure platform identity, query gates, policies, and integrations.</p>
          </div>
        </div>
        {activeTab !== 'vault' && (
          <div className="flex items-center gap-2.5">
            <button
              onClick={handleReset}
              className="premium-btn premium-btn-secondary gap-1.5"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Reset Defaults
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="premium-btn premium-btn-primary gap-1.5 shadow-indigo-500/10"
              style={{ background: 'linear-gradient(135deg,#6366F1,#7C3AED)' }}
            >
              {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
              Save Changes
            </button>
          </div>
        )}
      </div>

      {/* Toast */}
      {toast && (
        <div className={cn(
          "fixed bottom-5 right-5 z-55 flex items-center gap-2 px-4.5 py-3 rounded-xl shadow-xl text-sm font-semibold text-white animate-slide-up",
          toast.type === 'success' ? "bg-brand-green shadow-emerald-500/10" : "bg-brand-red shadow-red-500/10"
        )}>
          {toast.type === 'success' ? <CheckCircle className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
          {toast.msg}
        </div>
      )}

      {/* Info banner */}
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl bg-sky-50/70 dark:bg-sky-950/20 border border-sky-200/60 dark:border-sky-900/50 text-xs text-sky-700 dark:text-sky-400 leading-relaxed shadow-sm animate-scale-up">
        <Info className="h-4 w-4 mt-0.5 flex-shrink-0 text-sky-500" />
        <span>
          Settings are stored per-tenant and take effect immediately. Some core parameter changes (IP allowlists, query rates, session lifetimes) require backend agent re-sync or service restart to apply.
        </span>
      </div>

      {/* Layout */}
      <div className="flex flex-col md:flex-row gap-6 items-start">
        {/* Sidebar tabs */}
        <nav className="w-full md:w-52 flex-shrink-0 flex flex-row md:flex-col gap-1 overflow-x-auto pb-2 md:pb-0">
          {TABS.map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  "flex items-center gap-2.5 px-3 py-2.5 text-xs font-semibold rounded-lg transition text-left border whitespace-nowrap active:scale-[0.98]",
                  active
                    ? "text-brand-indigo bg-indigo-50/50 dark:bg-indigo-950/30 border-indigo-200/60 dark:border-indigo-900/60 font-bold"
                    : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/30 border-transparent"
                )}
              >
                <Icon className={cn("h-4 w-4 flex-shrink-0", active ? "text-brand-indigo" : "text-slate-400")} />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Panel */}
        <div className="flex-1 w-full bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 min-h-[580px] shadow-sm">
          {renderPanel()}
        </div>
      </div>
    </div>
  );
}
