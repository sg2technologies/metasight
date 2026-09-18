import React, { useEffect, useState, useCallback } from 'react';
import { Navigate } from 'react-router-dom';
import {
  Search, History, ShieldAlert, Video, ChevronDown, ChevronUp,
  ArrowRight, RefreshCw, Eye, EyeOff, Tag, Lock, Check, X, Shield, Activity, Download
} from 'lucide-react';
import { api, isAdmin } from '../api';
import { cn } from '../lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Summary {
  change_count: number;
  privileged_activity_count: number;
  active_session_count: number;
  replay_available_count: number;
}

interface ChangeAudit {
  id: number;
  entity: string;
  entity_id: string | null;
  table_name: string | null;
  record_pk: string | null;
  column_name: string;
  old_value: string | null;
  new_value: string | null;
  changed_by: string;
  changed_role: string | null;
  changed_at: string;
  operation_type: string;
  approval_status: string | null;
  session_id: string | null;
  details: Record<string, any>;
}

interface PrivilegedActivity {
  id: number;
  actor_email: string;
  actor_role: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  description: string | null;
  risk_level: string;
  occurred_at: string;
  session_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  details: Record<string, any>;
}

interface SessionRecording {
  id: number;
  session_id: string;
  user_email: string;
  role: string;
  replay_provider: string;
  recording_url: string | null;
  started_at: string;
  ended_at: string | null;
  status: string;
  details: Record<string, any>;
}

type Tab = 'changes' | 'activity' | 'sessions';

// ── Shared style helpers ────────────────────────────────────────────────────

const OP_COLORS: Record<string, string> = {
  CREATE: 'bg-emerald-100 dark:bg-emerald-950/40 text-emerald-800 dark:text-emerald-450 border border-emerald-200 dark:border-emerald-900/40',
  UPDATE: 'bg-blue-100 dark:bg-blue-950/40 text-blue-800 dark:text-blue-450 border border-blue-200 dark:border-blue-900/40',
  DELETE: 'bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-450 border border-red-200 dark:border-red-900/40',
};

const RISK_COLORS: Record<string, string> = {
  LOW: 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700',
  MEDIUM: 'bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-200 dark:border-amber-900/40',
  HIGH: 'bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-400 border border-red-200 dark:border-red-900/40',
  CRITICAL: 'bg-red-200 dark:bg-red-905/60 text-red-950 dark:text-red-300 border border-red-300 dark:border-red-900/60',
};

function SummaryCard({ label, value, icon: Icon, accent }: { label: string; value: number; icon: any; accent: string }) {
  return (
    <div className="premium-card p-5 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
      <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 shadow-sm" style={{ background: accent }}>
        <Icon className="h-5 w-5 text-white" />
      </div>
      <div>
        <p className="text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold text-slate-900 dark:text-white mt-0.5">{value}</p>
      </div>
    </div>
  );
}

function truncate(v: string | null, n = 60) {
  if (!v) return '—';
  return v.length > n ? v.slice(0, n) + '…' : v;
}

// ── Main component ──────────────────────────────────────────────────────────

export function GovernanceAuditCenter() {
  if (!isAdmin()) return <Navigate to="/" replace />;

  const [tab, setTab] = useState<Tab>('changes');
  const [summary, setSummary] = useState<Summary | null>(null);

  const [changes, setChanges] = useState<ChangeAudit[]>([]);
  const [changesTotal, setChangesTotal] = useState(0);
  const [activities, setActivities] = useState<PrivilegedActivity[]>([]);
  const [activitiesTotal, setActivitiesTotal] = useState(0);
  const [sessions, setSessions] = useState<SessionRecording[]>([]);
  const [sessionsTotal, setSessionsTotal] = useState(0);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState<number | null>(null);
  const [expandedActivityId, setExpandedActivityId] = useState<number | null>(null);
  const [expandedSessionId, setExpandedSessionId] = useState<number | null>(null);
  const [screenshots, setScreenshots] = useState<Record<string, any[]>>({});
  const [selectedScreenshot, setSelectedScreenshot] = useState<any | null>(null);

  const fetchSessionScreenshots = async (sessionId: string) => {
    try {
      const res = await api.get(`/pam/sessions/${sessionId}/screenshots`);
      setScreenshots(prev => ({ ...prev, [sessionId]: res.data }));
    } catch (err) {
      // Enterprise-only endpoint (session screenshots) — 404s in Community.
      // Resolve to "no screenshots" rather than leaving this session stuck
      // on "Loading screenshots..." forever.
      setScreenshots(prev => ({ ...prev, [sessionId]: [] }));
    }
  };

  const [entityFilter, setEntityFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [page, setPage] = useState(0);
  const limit = 50;

  const [exportingCompliance, setExportingCompliance] = useState(false);
  const handleExportCompliance = async () => {
    setExportingCompliance(true);
    try {
      const res = await api.get('/audit/compliance/summary/export', {
        params: { format: 'csv' },
        responseType: 'blob',
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = `metasight_compliance_summary_${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      setError('Failed to export compliance summary.');
    } finally {
      setExportingCompliance(false);
    }
  };

  const fetchSummary = useCallback(async () => {
    try {
      const res = await api.get('/audit/governance/summary');
      setSummary(res.data);
    } catch {
      /* non-fatal */
    }
  }, []);

  const fetchChanges = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = { skip: page * limit, limit };
      if (entityFilter) params.entity = entityFilter;
      const res = await api.get('/audit/governance/changes', { params });
      setChanges(res.data.items || []);
      setChangesTotal(res.data.total || 0);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch change audits');
    } finally {
      setLoading(false);
    }
  }, [page, entityFilter]);

  const fetchActivities = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = { skip: page * limit, limit };
      if (actorFilter) params.actor_email = actorFilter;
      if (riskFilter) params.risk_level = riskFilter;
      const res = await api.get('/audit/governance/privileged-activities', { params });
      setActivities(res.data.items || []);
      setActivitiesTotal(res.data.total || 0);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch privileged activities');
    } finally {
      setLoading(false);
    }
  }, [page, actorFilter, riskFilter]);

  const fetchSessions = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = { skip: page * limit, limit };
      if (actorFilter) params.user_email = actorFilter;
      const res = await api.get('/audit/governance/sessions', { params });
      // Sessions endpoint outputs paginated object, parse items
      setSessions(res.data.items || []);
      setSessionsTotal(res.data.total || 0);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch session recordings');
    } finally {
      setLoading(false);
    }
  }, [page, actorFilter]);

  useEffect(() => {
    fetchSummary();
  }, [fetchSummary]);

  useEffect(() => {
    setExpanded(null);
    setExpandedActivityId(null);
    setExpandedSessionId(null);
    if (tab === 'changes') fetchChanges();
    else if (tab === 'activity') fetchActivities();
    else if (tab === 'sessions') fetchSessions();
  }, [tab, page, entityFilter, actorFilter, riskFilter, fetchChanges, fetchActivities, fetchSessions]);

  const handleTabChange = (t: Tab) => {
    setTab(t);
    setPage(0);
    setEntityFilter('');
    setActorFilter('');
    setRiskFilter('');
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Governance Audit Center</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Supervise schema overrides, review high-risk commands, and watch session activity replays.
          </p>
        </div>
        <button
          onClick={handleExportCompliance}
          disabled={exportingCompliance}
          className="flex-shrink-0 flex items-center gap-2 px-3.5 py-2 text-xs font-bold rounded-lg bg-slate-900 text-white hover:bg-slate-800 dark:bg-slate-800 dark:hover:bg-slate-700 disabled:opacity-50 transition-colors"
          title="Download a summary of query, data-change, privileged-activity, and security event history for a selected period"
        >
          <Download className="h-3.5 w-3.5" />
          {exportingCompliance ? 'Exporting…' : 'Export Compliance Summary'}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-650 dark:text-red-400 px-4 py-3 rounded-lg text-sm">{error}</div>
      )}

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <SummaryCard label="Change Audits" value={summary.change_count} icon={History} accent="linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)" />
          <SummaryCard label="Privileged Actions" value={summary.privileged_activity_count} icon={ShieldAlert} accent="linear-gradient(135deg, #f59e0b 0%, #d97706 100%)" />
          <SummaryCard label="Active Sessions" value={summary.active_session_count} icon={Video} accent="linear-gradient(135deg, #22c55e 0%, #16a34a 100%)" />
          <SummaryCard label="Recorded Sessions" value={summary.replay_available_count} icon={Video} accent="linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)" />
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="bg-slate-100 dark:bg-slate-800/60 p-1 rounded-xl flex gap-1 border border-slate-200 dark:border-slate-800 max-w-md">
        <button
          onClick={() => handleTabChange('changes')}
          className={cn(
            'flex-1 py-2 text-xs font-bold rounded-lg uppercase tracking-wider transition-colors',
            tab === 'changes'
              ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm border border-slate-205 dark:border-slate-700/60'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 border border-transparent'
          )}
        >
          Changes
        </button>
        <button
          onClick={() => handleTabChange('activity')}
          className={cn(
            'flex-1 py-2 text-xs font-bold rounded-lg uppercase tracking-wider transition-colors',
            tab === 'activity'
              ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm border border-slate-205 dark:border-slate-700/60'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 border border-transparent'
          )}
        >
          Activities
        </button>
        <button
          onClick={() => handleTabChange('sessions')}
          className={cn(
            'flex-1 py-2 text-xs font-bold rounded-lg uppercase tracking-wider transition-colors',
            tab === 'sessions'
              ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-sm border border-slate-205 dark:border-slate-700/60'
              : 'text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 border border-transparent'
          )}
        >
          Recordings
        </button>
      </div>

      {/* ── Changes list ─────────────────────────────────────────────────── */}
      {tab === 'changes' && (
        <div className="space-y-4 animate-slide-up">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative max-w-xs flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Filter by entity..."
                value={entityFilter}
                onChange={(e) => { setEntityFilter(e.target.value); setPage(0); }}
                className="premium-input pl-9"
              />
            </div>
          </div>

          <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
            {loading ? (
              <div className="p-8 text-center text-slate-500 dark:text-slate-400">
                <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
                <p className="text-sm">Loading change audits…</p>
              </div>
            ) : changes.length === 0 ? (
              <div className="p-12 text-center text-slate-400 dark:text-slate-500">
                <History className="h-12 w-12 mx-auto mb-3 opacity-30 animate-pulse" />
                <p className="font-semibold text-slate-850 dark:text-slate-200">No schema changes discovered.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
                    <tr className="text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="px-4 py-3 text-left">Time</th>
                      <th className="px-4 py-3 text-left">User</th>
                      <th className="px-4 py-3 text-left">Entity</th>
                      <th className="px-4 py-3 text-left">Column</th>
                      <th className="px-4 py-3 text-left">Operation</th>
                      <th className="px-4 py-3 text-left">Old Value</th>
                      <th className="px-4 py-3 text-left">New Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-150 dark:divide-slate-800/50">
                    {changes.map((c) => (
                      <React.Fragment key={c.id}>
                        <tr
                          className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20 cursor-pointer transition-colors"
                          onClick={() => setExpanded(expanded === c.id ? null : c.id)}
                        >
                          <td className="px-4 py-3 text-xs text-slate-500 font-mono whitespace-nowrap">{new Date(c.changed_at).toLocaleString()}</td>
                          <td className="px-4 py-3 text-xs font-semibold text-slate-800 dark:text-slate-200">{c.changed_by}</td>
                          <td className="px-4 py-3 text-xs font-semibold text-slate-700 dark:text-slate-300 font-mono">{c.entity}{c.entity_id ? `#${c.entity_id}` : ''}</td>
                          <td className="px-4 py-3 text-xs font-mono text-brand-indigo dark:text-indigo-400">{c.column_name}</td>
                          <td className="px-4 py-3">
                            <span className={cn('inline-flex px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider', OP_COLORS[c.operation_type] ?? 'bg-slate-150 text-slate-700')}>
                              {c.operation_type}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-slate-400 dark:text-slate-500 font-mono truncate max-w-[120px]" title={c.old_value ?? ''}>{truncate(c.old_value, 20)}</td>
                          <td className="px-4 py-3 text-xs text-slate-750 dark:text-slate-350 font-mono truncate max-w-[120px]" title={c.new_value ?? ''}>
                            <div className="flex items-center gap-1.5 justify-between">
                              <span className="truncate">{truncate(c.new_value, 20)}</span>
                              {expanded === c.id ? <ChevronUp className="h-3.5 w-3.5 text-slate-400 flex-shrink-0" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-405 flex-shrink-0" />}
                            </div>
                          </td>
                        </tr>
                        {expanded === c.id && (
                          <tr className="bg-slate-50/30 dark:bg-slate-900/30">
                            <td colSpan={7} className="px-5 py-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs animate-slide-up">
                                <div>
                                  <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Values Comparison</p>
                                  <div className="space-y-3 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 font-mono text-xs">
                                    <div>
                                      <span className="text-slate-400 block mb-0.5 select-none">- Old Value:</span>
                                      <pre className="text-red-500 bg-red-50 dark:bg-red-950/20 px-2.5 py-1.5 border border-red-100 dark:border-red-900/35 rounded-lg whitespace-pre-wrap break-all leading-normal">{c.old_value ?? 'NULL'}</pre>
                                    </div>
                                    <div className="pt-2">
                                      <span className="text-slate-400 block mb-0.5 select-none">+ New Value:</span>
                                      <pre className="text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-950/20 px-2.5 py-1.5 border border-green-150 dark:border-green-900/35 rounded-lg whitespace-pre-wrap break-all leading-normal">{c.new_value ?? 'NULL'}</pre>
                                    </div>
                                  </div>
                                </div>
                                <div>
                                  <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Details Metadata</p>
                                  {c.details && Object.keys(c.details).length > 0 ? (
                                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 max-h-48 overflow-y-auto font-mono text-[11px] text-slate-700 dark:text-slate-300">
                                      {Object.entries(c.details).map(([key, val]) => (
                                        <div key={key} className="flex gap-2 py-1 border-b border-slate-50 dark:border-slate-900 last:border-0">
                                          <span className="text-slate-400 font-semibold select-none">{key}:</span>
                                          <span className="text-slate-800 dark:text-slate-200 break-all">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-slate-400 dark:text-slate-600 italic">No additional metadata</div>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <PaginationBar total={changesTotal} page={page} limit={limit} setPage={setPage} />
          </div>
        </div>
      )}

      {/* ── Activities list ──────────────────────────────────────────────── */}
      {tab === 'activity' && (
        <div className="space-y-4 animate-slide-up">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative max-w-xs flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Filter by actor..."
                value={actorFilter}
                onChange={(e) => { setActorFilter(e.target.value); setPage(0); }}
                className="premium-input pl-9"
              />
            </div>
            <select
              value={riskFilter}
              onChange={(e) => { setRiskFilter(e.target.value); setPage(0); }}
              className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-805 dark:text-slate-205 rounded-lg px-3 py-2 text-sm outline-none focus:border-brand-indigo transition-all min-w-[140px]"
            >
              <option value="">All risk levels</option>
              <option value="LOW">LOW</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="HIGH">HIGH</option>
              <option value="CRITICAL">CRITICAL</option>
            </select>
          </div>

          <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
            {loading ? (
              <div className="p-8 text-center text-slate-500 dark:text-slate-400">
                <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
                <p className="text-sm">Loading activities logs…</p>
              </div>
            ) : activities.length === 0 ? (
              <div className="p-12 text-center text-slate-400 dark:text-slate-500">
                <ShieldAlert className="h-12 w-12 mx-auto mb-3 opacity-30 animate-pulse" />
                <p className="font-semibold text-slate-850 dark:text-slate-200">No privileged activity found.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
                    <tr className="text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="px-4 py-3 text-left">Time</th>
                      <th className="px-4 py-3 text-left">Actor</th>
                      <th className="px-4 py-3 text-left">Action</th>
                      <th className="px-4 py-3 text-left">Target</th>
                      <th className="px-4 py-3 text-left">Description</th>
                      <th className="px-4 py-3 text-left">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-150 dark:divide-slate-800/50">
                    {activities.map((a) => (
                      <React.Fragment key={a.id}>
                        <tr
                          className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20 cursor-pointer transition-colors"
                          onClick={() => setExpandedActivityId(expandedActivityId === a.id ? null : a.id)}
                        >
                          <td className="px-4 py-3 text-xs text-slate-500 font-mono whitespace-nowrap">{new Date(a.occurred_at).toLocaleString()}</td>
                          <td className="px-4 py-3 text-xs font-semibold text-slate-800 dark:text-slate-200">{a.actor_email} <span className="text-slate-400 font-medium">({a.actor_role})</span></td>
                          <td className="px-4 py-3 text-xs font-mono text-brand-indigo dark:text-indigo-400 font-bold">{a.action}</td>
                          <td className="px-4 py-3 text-xs text-slate-700 dark:text-slate-300 font-mono">{a.target_type ?? '—'}{a.target_id ? `#${a.target_id}` : ''}</td>
                          <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 max-w-[280px] truncate" title={a.description ?? ''}>
                            <div className="flex items-center gap-1.5 justify-between">
                              <span className="truncate">{a.description ?? '—'}</span>
                              {expandedActivityId === a.id ? <ChevronUp className="h-3.5 w-3.5 text-slate-400 flex-shrink-0" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-405 flex-shrink-0" />}
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            <span className={cn('inline-flex px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider', RISK_COLORS[a.risk_level] ?? 'bg-slate-100 text-slate-700')}>
                              {a.risk_level}
                            </span>
                          </td>
                        </tr>
                        {expandedActivityId === a.id && (
                          <tr className="bg-slate-50/30 dark:bg-slate-900/30">
                            <td colSpan={6} className="px-5 py-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs animate-slide-up">
                                <div>
                                  <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Session Context</p>
                                  <div className="space-y-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 font-semibold text-slate-700 dark:text-slate-300">
                                    <div>IP Address: <span className="font-mono text-slate-900 dark:text-white font-bold">{a.ip_address ?? '—'}</span></div>
                                    <div>User Agent: <span className="font-mono text-slate-900 dark:text-white break-all">{a.user_agent ?? '—'}</span></div>
                                    <div>Session ID: <span className="font-mono text-slate-900 dark:text-white font-bold">{a.session_id ?? '—'}</span></div>
                                  </div>
                                </div>
                                <div>
                                  <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Activity Metadata</p>
                                  {a.details && Object.keys(a.details).length > 0 ? (
                                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 max-h-48 overflow-y-auto font-mono text-[11px] text-slate-700 dark:text-slate-305">
                                      {Object.entries(a.details).map(([key, val]) => (
                                        <div key={key} className="flex gap-2 py-1 border-b border-slate-50 dark:border-slate-900 last:border-0">
                                          <span className="text-slate-400 font-semibold select-none">{key}:</span>
                                          <span className="text-slate-850 dark:text-slate-200 break-all">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-slate-400 dark:text-slate-600 italic">No additional metadata</div>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <PaginationBar total={activitiesTotal} page={page} limit={limit} setPage={setPage} />
          </div>
        </div>
      )}

      {/* ── Session Recordings list ─────────────────────────────────────── */}
      {tab === 'sessions' && (
        <div className="space-y-4 animate-slide-up">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative max-w-xs flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Filter by user email..."
                value={actorFilter}
                onChange={(e) => { setActorFilter(e.target.value); setPage(0); }}
                className="premium-input pl-9"
              />
            </div>
          </div>

          <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
            {loading ? (
              <div className="p-8 text-center text-slate-500 dark:text-slate-400">
                <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
                <p className="text-sm">Loading session recordings…</p>
              </div>
            ) : sessions.length === 0 ? (
              <div className="p-12 text-center text-slate-400 dark:text-slate-500">
                <Video className="h-12 w-12 mx-auto mb-3 opacity-30 animate-pulse" />
                <p className="font-semibold text-slate-800 dark:text-slate-200">No session recordings found.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
                    <tr className="text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                      <th className="px-4 py-3 text-left">Started</th>
                      <th className="px-4 py-3 text-left">User</th>
                      <th className="px-4 py-3 text-left">Provider</th>
                      <th className="px-4 py-3 text-left">Status</th>
                      <th className="px-4 py-3 text-left">Replay</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-150 dark:divide-slate-800/50">
                    {sessions.map((s) => (
                      <React.Fragment key={s.id}>
                        <tr
                          className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20 cursor-pointer transition-colors"
                          onClick={() => {
                            const nextId = expandedSessionId === s.id ? null : s.id;
                            setExpandedSessionId(nextId);
                            if (nextId && s.session_id) {
                              fetchSessionScreenshots(s.session_id);
                            }
                          }}
                        >
                          <td className="px-4 py-3 text-xs text-slate-500 font-mono whitespace-nowrap">{new Date(s.started_at).toLocaleString()}</td>
                          <td className="px-4 py-3 text-xs font-semibold text-slate-800 dark:text-slate-200">{s.user_email} <span className="text-slate-400 font-medium">({s.role})</span></td>
                          <td className="px-4 py-3 text-xs text-slate-600 dark:text-slate-400 font-mono">{s.replay_provider}</td>
                          <td className="px-4 py-3">
                            <span className={cn('inline-flex px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider',
                              s.status === 'active' ? 'bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-900/30' : 'bg-slate-100 dark:bg-slate-800 text-slate-650 dark:text-slate-400 border border-slate-200 dark:border-slate-700')}>
                              {s.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs">
                            <div className="flex items-center gap-1.5 justify-between">
                              {s.recording_url ? (
                                <a href={s.recording_url} target="_blank" rel="noreferrer" className="text-brand-indigo dark:text-indigo-400 hover:underline font-bold" onClick={(e) => e.stopPropagation()}>▶ View</a>
                              ) : (
                                <span className="text-slate-400 dark:text-slate-600">No replay</span>
                              )}
                              {expandedSessionId === s.id ? <ChevronUp className="h-3.5 w-3.5 text-slate-400 flex-shrink-0" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-405 flex-shrink-0" />}
                            </div>
                          </td>
                        </tr>
                        {expandedSessionId === s.id && (
                          <tr className="bg-slate-50/30 dark:bg-slate-900/30">
                            <td colSpan={5} className="px-5 py-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs animate-slide-up">
                                <div>
                                  <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Session details</p>
                                  <div className="space-y-2 bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 font-semibold text-slate-700 dark:text-slate-300">
                                    <div>Started At: <span className="font-mono text-slate-900 dark:text-white font-bold">{new Date(s.started_at).toLocaleString()}</span></div>
                                    <div>Ended At: <span className="font-mono text-slate-900 dark:text-white font-bold">{s.ended_at ? new Date(s.ended_at).toLocaleString() : 'Active (Ongoing)'}</span></div>
                                    <div>Duration: <span className="font-mono text-slate-900 dark:text-white font-bold">
                                      {s.ended_at ? (
                                        (() => {
                                          const diffMs = new Date(s.ended_at).getTime() - new Date(s.started_at).getTime();
                                          const mins = Math.floor(diffMs / 60000);
                                          const secs = Math.floor((diffMs % 60000) / 1000);
                                          return `${mins}m ${secs}s`;
                                        })()
                                      ) : 'Ongoing'}
                                    </span></div>
                                    <div>Status: <span className="font-mono text-slate-900 dark:text-white font-bold capitalize">{s.status}</span></div>
                                  </div>
                                </div>
                                <div>
                                  <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Session Metadata</p>
                                  {s.details && Object.keys(s.details).length > 0 ? (
                                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 max-h-48 overflow-y-auto font-mono text-[11px] text-slate-700 dark:text-slate-305">
                                      {Object.entries(s.details).map(([key, val]) => (
                                        <div key={key} className="flex gap-2 py-1 border-b border-slate-50 dark:border-slate-900 last:border-0">
                                          <span className="text-slate-400 font-semibold select-none">{key}:</span>
                                          <span className="text-slate-850 dark:text-slate-200 break-all">{typeof val === 'object' ? JSON.stringify(val) : String(val)}</span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <div className="bg-white dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-slate-400 dark:text-slate-600 italic">No additional metadata</div>
                                  )}
                                </div>
                              </div>

                              <div className="mt-6 border-t border-slate-200 dark:border-slate-800 pt-6 animate-slide-up">
                                <p className="font-bold text-slate-400 dark:text-slate-550 uppercase tracking-widest mb-3.5 text-[9px]">Session Screen Recordings / Screenshots</p>
                                {s.session_id && screenshots[s.session_id] ? (
                                  screenshots[s.session_id].length > 0 ? (
                                    <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-5 gap-4">
                                      {screenshots[s.session_id].map((shot) => {
                                        const imgUrl = `${api.defaults.baseURL || 'http://localhost:8000'}/pam/sessions/${s.session_id}/screenshots/${shot.id}/image?token=${localStorage.getItem('token')}`;
                                        return (
                                          <div key={shot.id} className="relative group border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden bg-slate-100 dark:bg-slate-950 shadow-sm hover:shadow-md transition-all">
                                            <img
                                              src={imgUrl}
                                              alt={shot.active_window || 'Screenshot'}
                                              className="w-full h-32 object-cover cursor-zoom-in"
                                              onClick={() => setSelectedScreenshot({ ...shot, url: imgUrl })}
                                            />
                                            <div className="p-2.5 text-[10px] text-slate-500 space-y-1 bg-white dark:bg-slate-900 border-t border-slate-100 dark:border-slate-800/80">
                                              <div className="font-bold text-slate-700 dark:text-slate-200 truncate" title={shot.active_app || 'N/A'}>
                                                App: {shot.active_app || 'N/A'}
                                              </div>
                                              <div className="truncate text-slate-500 dark:text-slate-400" title={shot.active_window || 'N/A'}>
                                                Window: {shot.active_window || 'N/A'}
                                              </div>
                                              <div className="text-[9px] font-mono text-slate-400">
                                                {new Date(shot.captured_at).toLocaleTimeString()}
                                              </div>
                                            </div>
                                            {shot.risk_flag && (
                                              <span className="absolute top-1.5 right-1.5 bg-red-500 text-white text-[9px] px-2 py-0.5 rounded font-bold uppercase tracking-wider shadow-sm animate-pulse">
                                                Risk
                                              </span>
                                            )}
                                          </div>
                                        );
                                      })}
                                    </div>
                                  ) : (
                                    <div className="border border-slate-200 dark:border-slate-800 rounded-lg p-6 text-center text-slate-400 dark:text-slate-650 italic bg-white dark:bg-slate-900/50">
                                      No screenshots captured for this session.
                                    </div>
                                  )
                                ) : (
                                  <div className="text-slate-400 text-sm italic">Loading screenshots...</div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <PaginationBar total={sessionsTotal} page={page} limit={limit} setPage={setPage} />
          </div>
        </div>
      )}

      {/* ── Screenshot Viewer Modal ────────────────────────────────────── */}
      {selectedScreenshot && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-fade-in" onClick={() => setSelectedScreenshot(null)}>
          <div className="bg-white dark:bg-slate-900 rounded-xl shadow-2xl max-w-4xl w-full overflow-hidden flex flex-col md:flex-row max-h-[85vh] border border-slate-200 dark:border-slate-800 animate-scale-up" onClick={e => e.stopPropagation()}>
            {/* Image display */}
            <div className="bg-slate-950 flex-1 flex items-center justify-center p-2 min-h-[300px] overflow-hidden border-b md:border-b-0 md:border-r border-slate-950">
              <img
                src={selectedScreenshot.url}
                alt={selectedScreenshot.active_window || 'Screenshot'}
                className="max-w-full max-h-[75vh] object-contain rounded shadow-lg"
              />
            </div>
            {/* Details panel */}
            <div className="w-full md:w-80 border-t md:border-t-0 md:border-l border-slate-205 dark:border-slate-800 p-5 flex flex-col justify-between bg-slate-50 dark:bg-slate-900">
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                  <h3 className="font-bold text-slate-900 dark:text-white text-sm">Screenshot details</h3>
                  <button onClick={() => setSelectedScreenshot(null)} className="premium-btn-secondary px-2.5 py-1 text-xs">
                    Close
                  </button>
                </div>
                
                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block mb-0.5 font-semibold uppercase tracking-wider text-[9px]">Active Application</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200 break-words">{selectedScreenshot.active_app || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block mb-0.5 font-semibold uppercase tracking-wider text-[9px]">Active Window Title</span>
                    <span className="font-bold text-slate-800 dark:text-slate-200 break-words">{selectedScreenshot.active_window || 'N/A'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block mb-0.5 font-semibold uppercase tracking-wider text-[9px]">Captured At</span>
                    <span className="font-semibold text-slate-850 dark:text-slate-300 font-mono">{new Date(selectedScreenshot.captured_at).toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block mb-0.5 font-semibold uppercase tracking-wider text-[9px]">File Size</span>
                    <span className="font-mono text-slate-850 dark:text-slate-300">{(selectedScreenshot.file_size / 1024).toFixed(1)} KB</span>
                  </div>
                  <div>
                    <span className="text-slate-400 dark:text-slate-500 block mb-0.5 font-semibold uppercase tracking-wider text-[9px]">Checksum</span>
                    <span className="font-mono text-[10px] text-slate-800 dark:text-slate-300 select-all break-all">{selectedScreenshot.checksum || 'N/A'}</span>
                  </div>
                  {selectedScreenshot.risk_flag && (
                    <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-700 dark:text-red-400 p-2.5 rounded-lg font-bold flex items-center gap-1.5 mt-2.5 uppercase tracking-wider text-[10px]">
                      <span className="h-2.5 w-2.5 rounded-full bg-red-650 animate-ping"></span>
                      <span>Flagged: Policy Risk detected</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="pt-4 border-t border-slate-200 dark:border-slate-800 mt-4">
                <a href={selectedScreenshot.url} download={`screenshot-${selectedScreenshot.id}.png`} className="premium-btn-primary block text-center w-full text-xs font-bold">
                  Download Image
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function PaginationBar({ total, page, limit, setPage }: { total: number; page: number; limit: number; setPage: (fn: (p: number) => number) => void }) {
  if (total <= limit) return null;
  return (
    <div className="px-5 py-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-semibold bg-slate-50 dark:bg-slate-900/50 text-slate-500 dark:text-slate-400 uppercase tracking-wider">
      <span>Page {page + 1} of {Math.ceil(total / limit)}</span>
      <div className="flex gap-2">
        <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
          className="premium-btn-secondary px-3 py-1.5 text-xs">
          Previous
        </button>
        <button disabled={(page + 1) * limit >= total} onClick={() => setPage(p => p + 1)}
          className="premium-btn-secondary px-3 py-1.5 text-xs">
          Next
        </button>
      </div>
    </div>
  );
}
