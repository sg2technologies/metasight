import React, { useEffect, useState, useCallback } from 'react';
import { api, isAdmin } from '../api';
import {
  ShieldCheck, ShieldAlert, Shield, RefreshCw, ChevronDown, ChevronUp,
  CheckCircle2, XCircle, AlertTriangle, MinusCircle, Loader2, BookOpen,
  Copy, Check, Activity, Trash2, Eye, EyeOff, Radio, Bot,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { cn } from '../lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

interface CheckItem    { name: string; status: string; detail: string }
interface SourceReport { source_id: number; source_name: string; connector_type: string; reachable: boolean; score: number; grade: string; error: string | null; checks: CheckItem[] }
interface PostureResp  { overall_score: number; overall_grade: string; critical_issues: number; source_count: number; sources: SourceReport[] }
interface HardeningStep{ title: string; sql: string }
interface HardeningGuide { title: string; network: string; steps: HardeningStep[] }
interface SecurityEvt  { id: number; agent_id: number; source_id: number | null; db_type: string; session_pid: string; db_user: string; client_ip: string; app_name: string; database: string; current_sql: string; blocked: boolean; acknowledged: boolean; timestamp: string }

// ── Shared UI helpers ─────────────────────────────────────────────────────────

const GRADE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  A: { bg: '#e6fbf1', text: '#047857', border: '#10b981' },
  B: { bg: '#eff6ff', text: '#1d4ed8', border: '#3b82f6' },
  C: { bg: '#fefce8', text: '#a16207', border: '#eab308' },
  D: { bg: '#fff7ed', text: '#c2410c', border: '#f97316' },
  F: { bg: '#fef2f2', text: '#b91c1c', border: '#ef4444' },
  '?': { bg: '#f8fafc', text: '#475569', border: '#94a3b8' },
};

function GradeBadge({ grade }: { grade: string }) {
  const c = GRADE_COLORS[grade] ?? GRADE_COLORS['?'];
  return (
    <span className="inline-flex items-center justify-center w-10 h-10 rounded-xl text-lg font-black border dark:bg-slate-900/60 dark:text-slate-100"
      style={{ background: c.bg, color: c.text, borderColor: c.border }}>
      {grade}
    </span>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'pass': return <CheckCircle2 className="h-4 w-4 text-brand-green flex-shrink-0" />;
    case 'fail': return <XCircle className="h-4 w-4 text-brand-red flex-shrink-0" />;
    case 'warn': return <AlertTriangle className="h-4 w-4 text-brand-orange flex-shrink-0" />;
    default:     return <MinusCircle className="h-4 w-4 text-slate-400 flex-shrink-0" />;
  }
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 90 ? '#22c55e' : score >= 75 ? '#3b82f6' : score >= 50 ? '#eab308' : score >= 25 ? '#f97316' : '#ef4444';
  return (
    <div className="w-full bg-slate-100 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
      <div className="h-2 rounded-full transition-all duration-500" style={{ width: `${score}%`, background: color }} />
    </div>
  );
}

function CopyBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative mt-2 rounded-xl overflow-hidden bg-slate-950 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
      <button onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="absolute top-2.5 right-2.5 p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 transition text-slate-500 dark:text-slate-400 active:scale-[0.98]">
        {copied ? <Check className="h-3.5 w-3.5 text-brand-green" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
      <pre className="p-4 text-xs text-slate-700 dark:text-slate-350 overflow-x-auto leading-relaxed whitespace-pre-wrap pr-12 font-mono">{code}</pre>
    </div>
  );
}

function TabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick}
      className={cn("px-4 py-2 text-xs font-semibold rounded-lg transition border active:scale-[0.98]",
        active
          ? "text-brand-indigo bg-indigo-50/50 dark:bg-indigo-950/20 border-indigo-200/60 dark:border-indigo-900/60 font-bold"
          : "text-slate-650 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/30 border-transparent"
      )}
    >
      {children}
    </button>
  );
}

// ── Hardening Modal ───────────────────────────────────────────────────────────

function HardeningModal({ connectorType, sourceName, onClose }: { connectorType: string; sourceName: string; onClose: () => void }) {
  const [guide, setGuide] = useState<HardeningGuide | null>(null);
  useEffect(() => { api.get(`/security/hardening/${connectorType}`).then(r => setGuide(r.data)); }, [connectorType]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/40 dark:bg-slate-950/60 backdrop-blur-sm"
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="w-full max-w-2xl max-h-[85vh] flex flex-col bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-205 dark:border-slate-800 overflow-hidden animate-scale-up">
        <div className="flex items-center justify-between px-6 py-4.5 border-b border-slate-100 dark:border-slate-800/80" style={{ background: 'linear-gradient(135deg,#1e1b4b,#0f172a)' }}>
          <div className="flex items-center gap-3">
            <BookOpen className="h-5 w-5 text-sky-400" />
            <div>
              <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Hardening Guide</p>
              <h3 className="text-white font-bold text-sm mt-0.5">{sourceName}</h3>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white text-xl font-bold px-2 active:scale-95 transition-all">×</button>
        </div>
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {!guide ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3 text-slate-400">
              <Loader2 className="h-6 w-6 animate-spin text-brand-indigo" />
              <span className="text-xs font-semibold">Generating guide checklist...</span>
            </div>
          ) : (
            <div>
              <h4 className="text-sm font-semibold text-slate-850 dark:text-slate-200 mb-3">{guide.title}</h4>
              <div className="flex items-start gap-2.5 p-3.5 mb-6 rounded-xl bg-amber-50/70 dark:bg-amber-950/20 border border-amber-200/60 dark:border-amber-900/50 text-xs text-amber-800 dark:text-amber-400 leading-relaxed shadow-sm">
                <AlertTriangle className="h-4 w-4 mt-0.5 flex-shrink-0 text-brand-orange" />
                <span><strong>Network Requirement:</strong> {guide.network}</span>
              </div>
              <div className="space-y-6">
                {guide.steps.map((step, i) => (
                  <div key={i} className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="inline-flex items-center justify-center w-5 h-5 rounded-lg text-[10px] font-bold text-white bg-indigo-500">{i + 1}</span>
                      <span className="text-xs font-bold text-slate-800 dark:text-slate-250 uppercase tracking-wide">{step.title}</span>
                    </div>
                    <CopyBlock code={step.sql} />
                  </div>
                ))}
              </div>
              <div className="mt-6 p-4 rounded-xl bg-blue-50/60 dark:bg-slate-900 border border-blue-200/50 dark:border-slate-800 text-xs text-slate-700 dark:text-slate-350 leading-relaxed font-medium">
                <strong className="text-brand-indigo dark:text-indigo-400">Security Requirement:</strong> MetaSight must be the <strong className="text-slate-950 dark:text-slate-50 font-semibold">only</strong> system with direct DB administrative credentials. All human users should connect through the query gateways for session monitoring.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Tab 1: Posture ────────────────────────────────────────────────────────────

function PostureTab() {
  const [posture, setPosture] = useState<PostureResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [rechecking, setRechecking] = useState<Record<number, boolean>>({});
  const [guideFor, setGuideFor] = useState<{ type: string; name: string } | null>(null);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  const load = useCallback(() => {
    setLoading(true);
    api.get('/security/posture').then(r => setPosture(r.data)).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load]);

  const recheck = async (id: number) => {
    setRechecking(p => ({ ...p, [id]: true }));
    const r = await api.post(`/security/sources/${id}/check`);
    setPosture(p => p ? { ...p, sources: p.sources.map(s => s.source_id === id ? r.data : s) } : p);
    setRechecking(p => ({ ...p, [id]: false }));
  };

  if (loading) return (
    <div className="flex flex-col items-center justify-center h-48 gap-2 text-slate-400">
      <Loader2 className="h-7 w-7 animate-spin text-brand-indigo" />
      <span className="text-xs font-semibold">Analyzing database privilege posture...</span>
    </div>
  );
  if (!posture) return null;

  const gc = GRADE_COLORS[posture.overall_grade] ?? GRADE_COLORS['?'];
  return (
    <div className="space-y-6">
      {guideFor && <HardeningModal connectorType={guideFor.type} sourceName={guideFor.name} onClose={() => setGuideFor(null)} />}
      
      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
          <div className="w-12 h-12 rounded-xl flex items-center justify-center text-xl font-black border dark:bg-slate-950 dark:border-slate-800"
            style={{ background: gc.bg, color: gc.text, borderColor: gc.border }}>{posture.overall_grade}</div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Overall Posture</p>
            <p className="text-xl font-bold text-slate-900 dark:text-slate-50 mt-0.5">{posture.overall_score}<span className="text-xs text-slate-400 font-medium">/100</span></p>
          </div>
        </div>
        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-red-50 dark:bg-red-950/20 border border-red-100 dark:border-red-900/60"><ShieldAlert className="h-5 w-5 text-brand-red" /></div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Critical Issues</p>
            <p className="text-xl font-bold mt-0.5 text-brand-red" style={{ color: posture.critical_issues > 0 ? '#ef4444' : '#22c55e' }}>{posture.critical_issues}</p>
          </div>
        </div>
        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-indigo-50 dark:bg-indigo-950/20 border border-indigo-100 dark:border-indigo-900/60"><Shield className="h-5 w-5 text-brand-indigo" /></div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Monitored Sources</p>
            <p className="text-xl font-bold text-slate-900 dark:text-slate-50 mt-0.5">{posture.source_count}</p>
          </div>
        </div>
        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-100 dark:border-emerald-900/60"><CheckCircle2 className="h-5 w-5 text-brand-green" /></div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Passing (A/B)</p>
            <p className="text-xl font-bold text-slate-900 dark:text-slate-50 mt-0.5">{posture.sources.filter(s => ['A','B'].includes(s.grade)).length}</p>
          </div>
        </div>
      </div>

      {/* Source cards */}
      <div className="space-y-4">
        {[...posture.sources].sort((a, b) => a.score - b.score).map(rep => (
          <div key={rep.source_id} className="premium-card bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 overflow-hidden shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center gap-4 p-5">
              <GradeBadge grade={rep.reachable ? rep.grade : '?'} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-semibold text-slate-900 dark:text-slate-50 truncate">{rep.source_name}</span>
                  <span className="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200/60 dark:border-slate-700/60 font-mono">{rep.connector_type}</span>
                  {!rep.reachable && <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded bg-red-50 dark:bg-red-950/30 text-brand-red border border-red-200 dark:border-red-900/60">unreachable</span>}
                </div>
                <div className="flex items-center gap-3 mt-2.5">
                  <ScoreBar score={rep.score} />
                  <span className="text-xs text-slate-500 dark:text-slate-400 font-bold font-mono w-10 text-right">{rep.score}%</span>
                </div>
                {rep.error && <p className="text-xs text-brand-red mt-1.5 font-mono truncate">{rep.error}</p>}
              </div>
              <div className="flex items-center gap-2 flex-shrink-0 self-end md:self-auto">
                <button onClick={() => setGuideFor({ type: rep.connector_type, name: rep.source_name })}
                  className="premium-btn premium-btn-secondary gap-1.5 py-1.5 px-3 text-xs"
                >
                  <BookOpen className="h-3.5 w-3.5" /> Hardening Guide
                </button>
                <button onClick={() => recheck(rep.source_id)} disabled={rechecking[rep.source_id]}
                  className="p-2 text-slate-400 hover:text-brand-indigo hover:bg-slate-50 dark:hover:bg-slate-805/50 border border-transparent dark:border-slate-800 rounded-lg transition disabled:opacity-50 active:scale-95"
                >
                  <RefreshCw className={cn("h-3.5 w-3.5", rechecking[rep.source_id] && "animate-spin")} />
                </button>
                <button onClick={() => setExpanded(p => ({ ...p, [rep.source_id]: !p[rep.source_id] }))}
                  className="p-2 text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-805/50 border border-transparent dark:border-slate-800 rounded-lg transition active:scale-95"
                >
                  {expanded[rep.source_id] ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>
            {expanded[rep.source_id] && rep.checks.length > 0 && (
              <div className="border-t border-slate-100 dark:border-slate-800/80 bg-slate-50/60 dark:bg-slate-900/40 px-5 py-4 space-y-3">
                {rep.checks.map((c, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <StatusIcon status={c.status} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-slate-800 dark:text-slate-200">{c.name}</p>
                      {c.detail && (
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 leading-relaxed font-mono whitespace-pre-wrap">{c.detail}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Tab 2: Live Events ────────────────────────────────────────────────────────

function EventsTab() {
  const [events, setEvents] = useState<SecurityEvt[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(true);
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const admin = isAdmin();

  const load = useCallback(() => {
    api.get('/security/events').then(r => setEvents(r.data)).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 30_000); return () => clearInterval(t); }, [load]);

  const ack = async (id: number) => {
    try {
      await api.post(`/security/events/${id}/acknowledge`);
      setEvents(p => p.map(e => e.id === id ? { ...e, acknowledged: true } : e));
    } catch {}
  };

  const clearAcked = async () => {
    try {
      await api.delete('/security/events');
      setEvents(p => p.filter(e => !e.acknowledged));
    } catch {}
  };

  const visible = showNew ? events.filter(e => !e.acknowledged) : events;
  const newCount = events.filter(e => !e.acknowledged).length;

  if (loading) return (
    <div className="flex flex-col items-center justify-center py-12 gap-2 text-slate-400">
      <Loader2 className="h-7 w-7 animate-spin text-brand-indigo" />
      <span className="text-xs font-semibold">Loading security alerts...</span>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3 bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div className="flex items-center gap-2">
          <button onClick={() => setShowNew(true)}
            className={cn("px-3.5 py-2 text-xs font-bold rounded-lg transition-all border active:scale-[0.98]",
              showNew
                ? "bg-red-50 dark:bg-red-950/20 text-brand-red border-red-200 dark:border-red-900/60"
                : "text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/20 border-transparent")}
          >
            Unacknowledged {newCount > 0 && <span className="ml-1 px-1.5 py-0.5 rounded-full bg-brand-red text-white text-[10px] font-black">{newCount}</span>}
          </button>
          <button onClick={() => setShowNew(false)}
            className={cn("px-3.5 py-2 text-xs font-bold rounded-lg transition-all border active:scale-[0.98]",
              !showNew
                ? "bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border-slate-200 dark:border-slate-700"
                : "text-slate-650 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/20 border-transparent")}
          >
            All Events
          </button>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="p-2 text-slate-400 hover:text-brand-indigo hover:bg-slate-50 dark:hover:bg-slate-800 rounded-lg border border-transparent dark:border-slate-800 transition active:scale-95">
            <RefreshCw className="h-4 w-4" />
          </button>
          {admin && (
            <button onClick={clearAcked} className="premium-btn premium-btn-secondary gap-1.5 py-1.5 px-3 text-xs">
              <Trash2 className="h-3.5 w-3.5" /> Clear Acknowledged
            </button>
          )}
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="premium-card p-12 text-center text-slate-450 dark:text-slate-500 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 flex flex-col items-center justify-center gap-3">
          <div className="h-12 w-12 rounded-full bg-slate-50 dark:bg-slate-950 flex items-center justify-center">
            <ShieldCheck className="h-6 w-6 text-brand-green" />
          </div>
          <div>
            <p className="text-sm font-semibold text-slate-800 dark:text-slate-205">{showNew ? 'No unacknowledged events — all clear.' : 'No events recorded yet.'}</p>
            <p className="text-xs mt-1 text-slate-400 dark:text-slate-500">Live monitoring is active and guarding access policies.</p>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {visible.map(evt => (
            <div key={evt.id}
              className={cn("rounded-xl border overflow-hidden transition shadow-sm animate-scale-up",
                evt.acknowledged
                  ? "bg-slate-50/60 dark:bg-slate-900/40 border-slate-200 dark:border-slate-800 opacity-70"
                  : evt.blocked
                    ? "bg-orange-50/50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-900/60"
                    : "bg-red-50/50 dark:bg-red-950/20 border-red-200 dark:border-red-900/60"
              )}
            >
              <div className="flex items-start gap-4 p-4.5">
                {evt.blocked
                  ? <Shield className="h-5 w-5 text-brand-orange flex-shrink-0 mt-0.5" />
                  : <ShieldAlert className="h-5 w-5 text-brand-red flex-shrink-0 mt-0.5" />}
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={cn("text-[10px] font-black uppercase tracking-wider", evt.blocked ? "text-orange-700 dark:text-orange-400" : "text-red-700 dark:text-red-400")}>
                      {evt.blocked ? 'BLOCKED' : 'UNAUTHORIZED ACCESS'}
                    </span>
                    <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full bg-white dark:bg-slate-905 border border-slate-200 dark:border-slate-800 text-slate-605 dark:text-slate-400 font-mono">{evt.db_type}</span>
                    {evt.acknowledged && <span className="text-[9px] text-slate-500 font-semibold uppercase bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded">acknowledged</span>}
                  </div>
                  
                  <p className="text-sm text-slate-800 dark:text-slate-200 mt-2 font-medium">
                    <strong className="text-slate-900 dark:text-white font-mono">{evt.db_user || 'unknown'}</strong> from <strong className="text-slate-900 dark:text-white font-mono">{evt.client_ip || 'unknown IP'}</strong>
                    {evt.app_name && <> via <em className="text-slate-500 dark:text-slate-400 not-italic font-semibold">{evt.app_name}</em></>}
                    {evt.database && <> on <em className="text-slate-500 dark:text-slate-400 not-italic font-semibold">{evt.database}</em></>}
                  </p>
                  
                  <p className="text-xs text-slate-400 dark:text-slate-500 mt-1 font-mono">{new Date(evt.timestamp).toLocaleString()}</p>
                  
                  {expanded[evt.id] && evt.current_sql && (
                    <div className="mt-3.5">
                      <p className="text-xs font-semibold text-slate-600 dark:text-slate-400 mb-1.5">Query details:</p>
                      <CopyBlock code={evt.current_sql} />
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2 flex-shrink-0">
                  {evt.current_sql && (
                    <button onClick={() => setExpanded(p => ({ ...p, [evt.id]: !p[evt.id] }))}
                      className="p-1.5 text-slate-455 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-white dark:hover:bg-slate-900 rounded-lg border border-transparent dark:border-slate-800 transition active:scale-95" title="Show query">
                      {expanded[evt.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  )}
                  {!evt.acknowledged && (
                    <button onClick={() => ack(evt.id)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-emerald-700 dark:text-emerald-400 bg-white dark:bg-slate-900 border border-emerald-200 dark:border-emerald-900 hover:bg-emerald-50 dark:hover:bg-emerald-950/20 rounded-lg shadow-sm transition active:scale-[0.98]"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" /> Acknowledge
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

type Tab = 'posture' | 'events';

export function Security() {
  const [tab, setTab] = useState<Tab>('posture');
  const [eventCount, setEventCount] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    api.get('/security/events?unacknowledged_only=true').then(r => setEventCount(r.data.length)).catch(() => {});
    const t = setInterval(() => {
      api.get('/security/events?unacknowledged_only=true').then(r => setEventCount(r.data.length)).catch(() => {});
    }, 30_000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="space-y-6 animate-fade-in text-slate-800 dark:text-slate-100">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center shadow-lg" style={{ background: 'linear-gradient(135deg,#ef4444,#f97316)' }}>
            <ShieldCheck className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-50 font-display">Security Center</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Real-time database authorization, threat monitoring, and policy enforcement.</p>
          </div>
        </div>
        <div className="flex items-center gap-3 self-start sm:self-auto">
          {/* Agent shortcut */}
          <button
            onClick={() => navigate('/agents')}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold transition-all border border-indigo-200 dark:border-indigo-900 bg-indigo-50/50 dark:bg-indigo-950/20 text-brand-indigo dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-950/40 active:scale-[0.97]"
          >
            <Bot className="h-3.5 w-3.5" /> Manage Agents
          </button>
          {/* Live indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 text-xs text-emerald-450 border border-slate-800 font-semibold font-mono">
            <Radio className="h-3 w-3 animate-pulse text-brand-green" /> Live monitoring
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2">
        <TabButton active={tab === 'posture'} onClick={() => setTab('posture')}>
          <span className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" /> Privilege Posture</span>
        </TabButton>
        <TabButton active={tab === 'events'} onClick={() => setTab('events')}>
          <span className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5" /> Direct-Access Alerts
            {eventCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full bg-brand-red text-white text-[10px] font-black">{eventCount}</span>
            )}
          </span>
        </TabButton>
      </div>

      {/* Content */}
      {tab === 'posture' && <PostureTab />}
      {tab === 'events'  && <EventsTab />}
    </div>
  );
}
