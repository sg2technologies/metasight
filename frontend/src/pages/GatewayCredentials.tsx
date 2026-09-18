import { useState, useEffect, useCallback } from 'react';
import {
  Network, Plus, X, Check, Copy, Eye, EyeOff, Trash2, RotateCw,
  ShieldOff, ShieldCheck, AlertTriangle, Database,
} from 'lucide-react';
import { api } from '../api';
import { cn } from '../lib/utils';

interface GatewayCredential {
  id: number;
  data_source_id: number;
  user_id: number | null;
  gateway_username: string;
  display_name: string;
  role_override: string | null;
  department_id_override: number | null;
  region_override: string | null;
  status: 'ACTIVE' | 'REVOKED' | 'DISABLED';
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  secret?: string | null;
}

interface DataSource {
  id: number;
  name: string;
  type: string;
}

const STATUS_STYLES: Record<string, string> = {
  ACTIVE: 'bg-green-50 dark:bg-green-950/30 text-brand-green dark:text-green-400 border border-green-200 dark:border-green-900/10',
  REVOKED: 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700',
  DISABLED: 'bg-amber-50 dark:bg-amber-950/30 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-900/20',
};

// Engines the MetaSight Gateway can front today — keep in sync with
// backend/gateway/'s actual listeners (see DEPLOYMENT.md). MySQL exists in
// code but hasn't been verified against a real client yet — still listed
// here since credential creation itself works the same way regardless.
// MongoDB isn't built (no mature Go server-side wire-protocol library).
const GATEWAY_SUPPORTED_PREFIXES = ['postgres', 'mysql', 'mariadb'];

function fmt(d: string | null) {
  if (!d) return '—';
  return new Date(d).toLocaleString();
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <button onClick={copy} className="p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" title="Copy">
      {copied
        ? <Check size={13} className="text-emerald-500" />
        : <Copy size={13} className="text-slate-400 dark:text-slate-500 hover:text-slate-650 dark:hover:text-slate-200" />}
    </button>
  );
}

// ── Create modal ───────────────────────────────────────────────────────────────

function CreateModal({
  sources, onClose, onCreated,
}: {
  sources: DataSource[];
  onClose: () => void;
  onCreated: (c: GatewayCredential) => void;
}) {
  const [displayName, setDisplayName] = useState('');
  const [gatewayUsername, setGatewayUsername] = useState('');
  const [dataSourceId, setDataSourceId] = useState<number | ''>(sources[0]?.id ?? '');
  const [roleOverride, setRoleOverride] = useState('viewer');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState<GatewayCredential | null>(null);
  const [secretVisible, setSecretVisible] = useState(false);

  const submit = async () => {
    if (!displayName.trim() || !gatewayUsername.trim() || !dataSourceId) {
      setError('Display name, gateway username, and data source are required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const { data } = await api.post<GatewayCredential>('/gateway/credentials', {
        display_name: displayName.trim(),
        gateway_username: gatewayUsername.trim(),
        data_source_id: dataSourceId,
        role_override: roleOverride.trim() || undefined,
      });
      setCreated(data);
      onCreated(data);
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setError(msg || 'Failed to create gateway credential');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 backdrop-blur-sm p-4 animate-fade-in">
      <div className="relative w-full max-w-lg rounded-2xl overflow-hidden shadow-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 animate-scale-up">
        <div className="flex items-center justify-between px-6 py-4.5 border-b border-slate-200 dark:border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-white">New Gateway Credential</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              A wire-protocol identity real database clients (psql, BI tools, applications) connect
              to the gateway with — never the target database's own password.
            </p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 transition-colors">
            <X size={16} />
          </button>
        </div>

        {!created ? (
          <div className="p-6 space-y-5">
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Display Name</label>
              <input
                value={displayName}
                onChange={e => setDisplayName(e.target.value)}
                placeholder="e.g. Metabase reporting service"
                className="premium-input font-medium"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Gateway Username</label>
              <input
                value={gatewayUsername}
                onChange={e => setGatewayUsername(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && submit()}
                placeholder="e.g. gw_metabase"
                className="premium-input font-mono"
              />
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                What the client puts in its database connection string's username field. Must be
                unique across the whole deployment.
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Data Source</label>
              <select
                value={dataSourceId}
                onChange={e => setDataSourceId(Number(e.target.value))}
                className="premium-input font-medium"
              >
                {sources.length === 0 && <option value="">No supported data sources found</option>}
                {sources.map(s => (
                  <option key={s.id} value={s.id}>{s.name} ({s.type})</option>
                ))}
              </select>
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                This credential connects to exactly one target database — unlike an SDK credential,
                a wire listener naturally maps one username to one database.
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Policy Role</label>
              <input
                value={roleOverride}
                onChange={e => setRoleOverride(e.target.value)}
                placeholder="viewer"
                className="premium-input font-medium"
              />
              <p className="text-[11px] text-slate-400 dark:text-slate-500">
                The role used to evaluate masking/policy decisions for this credential's queries.
              </p>
            </div>

            {error && (
              <p className="text-xs text-rose-600 dark:text-rose-400 flex items-center gap-1.5 font-semibold">
                <AlertTriangle size={12} /> {error}
              </p>
            )}

            <div className="flex justify-end gap-3 pt-3 border-t border-slate-100 dark:border-slate-800">
              <button onClick={onClose} className="premium-btn-secondary">Cancel</button>
              <button onClick={submit} disabled={loading} className="premium-btn-primary disabled:opacity-50">
                {loading ? 'Creating…' : 'Create & Generate Secret'}
              </button>
            </div>
          </div>
        ) : (
          <div className="p-6 space-y-5">
            <div className="flex items-start gap-3.5 p-4 rounded-xl border border-emerald-100 dark:border-emerald-950 bg-emerald-50/20 dark:bg-emerald-950/10">
              <Check size={18} className="text-emerald-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-bold text-emerald-800 dark:text-emerald-400">Gateway credential created!</p>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                  Copy the secret below now — it will not be shown again. Use it as the password in
                  the connecting client's connection string (e.g. via the gateway's host/port with
                  <code>sslmode=require</code>).
                </p>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Gateway Username</label>
              <div className="flex items-center gap-2 p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950">
                <code className="flex-1 text-xs font-mono text-slate-700 dark:text-slate-300 break-all">{created.gateway_username}</code>
                <CopyBtn text={created.gateway_username} />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-455 dark:text-slate-555 uppercase tracking-wider block">Secret</label>
              <div className="flex items-center gap-2 p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950">
                <code className="flex-1 text-xs font-mono text-amber-600 dark:text-amber-300 break-all select-all font-semibold">
                  {secretVisible ? created.secret : '•'.repeat(Math.min(created.secret?.length ?? 0, 32))}
                </code>
                <button onClick={() => setSecretVisible(v => !v)} className="text-slate-400 hover:text-slate-650 dark:hover:text-slate-200 transition-colors" title="Toggle visibility">
                  {secretVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <CopyBtn text={created.secret ?? ''} />
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-100 dark:border-slate-800">
              <button onClick={onClose} className="premium-btn-primary">Done</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ────────────────────────────────────────────────────────────────

export function GatewayCredentials() {
  const [creds, setCreds] = useState<GatewayCredential[]>([]);
  const [sources, setSources] = useState<DataSource[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [credsRes, sourcesRes] = await Promise.all([
        api.get<GatewayCredential[]>('/gateway/credentials'),
        api.get('/sources'),
      ]);
      setCreds(credsRes.data);
      const items: DataSource[] = sourcesRes.data.items || sourcesRes.data || [];
      setSources(items.filter(s => GATEWAY_SUPPORTED_PREFIXES.some(p => s.type?.toLowerCase().startsWith(p))));
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const revoke = async (id: number) => {
    if (!confirm('Revoke this gateway credential? Takes effect immediately, even on already-open connections — the next query on this credential will be rejected.')) return;
    setBusyId(id);
    try {
      await api.post(`/gateway/credentials/${id}/revoke`);
      await load();
    } catch {}
    setBusyId(null);
  };

  const rotate = async (id: number) => {
    setBusyId(id);
    try {
      const { data } = await api.post<GatewayCredential>(`/gateway/credentials/${id}/rotate-secret`);
      await load();
      alert(`New secret (copy now, shown only once):\n\n${data.secret}`);
    } catch {}
    setBusyId(null);
  };

  const remove = async (id: number) => {
    if (!confirm('Permanently delete this gateway credential? This cannot be undone.')) return;
    setBusyId(id);
    try {
      await api.delete(`/gateway/credentials/${id}`);
      await load();
    } catch {}
    setBusyId(null);
  };

  return (
    <div className="space-y-6 animate-fade-in text-slate-800 dark:text-slate-100">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-150 dark:border-slate-850">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-3">
            <Network className="w-8 h-8 text-brand-indigo" />
            <span>Gateway Credentials</span>
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Identities for the MetaSight Gateway — a transparent database proxy. Applications,
            users, and BI/ETL tools connect through it with their normal DB driver/psql/mysql
            client, no code change required. Current scope: PostgreSQL and MySQL, Simple Query
            protocol only — MySQL support is new and not yet verified against a real client, see
            DEPLOYMENT.md.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="premium-btn-primary gap-2 text-xs px-3.5 py-2 self-start sm:self-auto"
        >
          <Plus size={14} /> New Credential
        </button>
      </div>

      <div className="premium-card overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-sm text-slate-400">Loading…</div>
        ) : creds.length === 0 ? (
          <div className="p-8 text-center text-sm text-slate-400">
            No gateway credentials yet. Create one to let a client connect through the gateway.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 dark:bg-slate-900/60 text-[10px] font-bold uppercase tracking-widest text-slate-450 dark:text-slate-500">
              <tr>
                <th className="text-left px-4 py-3">Name</th>
                <th className="text-left px-4 py-3">Gateway Username</th>
                <th className="text-left px-4 py-3">Data Source</th>
                <th className="text-left px-4 py-3">Role</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Last Used</th>
                <th className="text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-850">
              {creds.map(c => (
                <tr key={c.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-900/40">
                  <td className="px-4 py-3 font-semibold text-slate-800 dark:text-slate-200">{c.display_name}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500 dark:text-slate-400">{c.gateway_username}</td>
                  <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 flex items-center gap-1.5">
                    <Database size={12} className="text-slate-350 dark:text-slate-600" />
                    {sources.find(s => s.id === c.data_source_id)?.name ?? `#${c.data_source_id}`}
                  </td>
                  <td className="px-4 py-3 text-slate-500 dark:text-slate-400">{c.role_override || '—'}</td>
                  <td className="px-4 py-3">
                    <span className={cn("px-1.5 py-0.5 text-[9px] font-bold rounded uppercase", STATUS_STYLES[c.status])}>
                      {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-450 dark:text-slate-500">{fmt(c.last_used_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end items-center gap-1">
                      {c.status === 'ACTIVE' ? (
                        <button
                          onClick={() => revoke(c.id)}
                          disabled={busyId === c.id}
                          title="Revoke"
                          className="p-1.5 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30 text-slate-400 hover:text-brand-red disabled:opacity-50"
                        >
                          <ShieldOff size={14} />
                        </button>
                      ) : (
                        <ShieldCheck size={14} className="text-slate-300 dark:text-slate-700 mx-1.5" />
                      )}
                      <button
                        onClick={() => rotate(c.id)}
                        disabled={busyId === c.id}
                        title="Rotate secret"
                        className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-650 dark:hover:text-slate-200 disabled:opacity-50"
                      >
                        <RotateCw size={14} />
                      </button>
                      <button
                        onClick={() => remove(c.id)}
                        disabled={busyId === c.id}
                        title="Delete"
                        className="p-1.5 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30 text-slate-400 hover:text-brand-red disabled:opacity-50"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showCreate && (
        <CreateModal
          sources={sources}
          onClose={() => setShowCreate(false)}
          onCreated={() => load()}
        />
      )}
    </div>
  );
}
