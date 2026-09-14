import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Plus, Trash2, RefreshCw, Database, ChevronDown, ChevronUp,
  Clock, Search, X, ArrowLeft, Pencil, Check, Info, Layers,
  ArrowUpDown, Lock, KeyRound, CheckCircle2, XCircle, Loader2, Zap,
  Table as TableIcon, Hash, BarChart3, Play, Square, TrendingUp,
  CircleDot, CircleCheck,
} from 'lucide-react';
import { api, isAdmin } from '../api';
import {
  CONNECTORS, CONNECTORS_BY_CATEGORY, CATEGORY_LABELS, CATEGORY_COLORS,
  CATEGORY_ORDER, getConfigTemplate, type Connector, type ConnectorCategory,
} from '../data/connectors';
import { cn } from '../lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

type ScanStatus = 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';

type ScanProgress = {
  current_schema?: string;
  current_table?: string;
  schemas_done?: number;
  schemas_total?: number;
  tables_done?: number;
  columns_done?: number;
  phase?: string;
};

type ScanRun = {
  id: number;
  status: ScanStatus;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  progress?: ScanProgress | null;
};

type SchemaStatOut = {
  schema_name: string;
  table_count: number;
  estimated_rows: number;
};

type SortKey = 'schema_name' | 'table_count' | 'estimated_rows';

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtRows(n: number): string {
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000)     return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)         return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function fmtDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return `${m}m ${rem.toString().padStart(2, '0')}s`;
}

function parseScanCounts(msg: string) {
  const m = msg?.match(/(\d+)\s+schemas?,\s*(\d+)\s+tables?,\s*(\d+)\s+columns?/i);
  if (!m) return null;
  return { schemas: +m[1], tables: +m[2], columns: +m[3] };
}

const STATUS_CONFIG: Record<ScanStatus, { icon: React.ReactNode; cls: string; label: string }> = {
  PENDING:   { icon: <Clock className="h-3.5 w-3.5" />,   cls: 'bg-yellow-50 dark:bg-yellow-950/20 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-900/50',  label: 'Pending'   },
  RUNNING:   { icon: <Loader2 className="h-3.5 w-3.5 animate-spin" />, cls: 'bg-blue-50 dark:bg-blue-950/20 text-blue-700 dark:text-blue-400 border-blue-200 dark:border-blue-900/50', label: 'Running' },
  COMPLETED: { icon: <CheckCircle2 className="h-3.5 w-3.5" />, cls: 'bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-900/50', label: 'Completed' },
  FAILED:    { icon: <XCircle className="h-3.5 w-3.5" />,  cls: 'bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900/50',   label: 'Failed'    },
};

// ── Scan Progress Modal ───────────────────────────────────────────────────────

function ScanProgressModal({
  source,
  schemas,
  selectedSchemas,
  scanId,
  syncDone,
  onCancel,
  onClose,
}: {
  source: any;
  schemas: SchemaStatOut[];
  selectedSchemas: string[];
  scanId: number | null;
  syncDone: { ok: boolean; message: string } | null;
  onCancel: () => void;
  onClose: (result: { ok: boolean; message: string; counts?: any } | null) => void;
}) {
  const [elapsed, setElapsed] = useState(0);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus>('RUNNING');
  const [finalMessage, setFinalMessage] = useState('');
  const startRef = useRef(Date.now());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Elapsed timer
  useEffect(() => {
    const t = setInterval(() => setElapsed(Date.now() - startRef.current), 500);
    return () => clearInterval(t);
  }, []);

  // Signal from sync-scan (no Celery) when the blocking HTTP call resolves
  useEffect(() => {
    if (!scanId && syncDone) {
      setScanStatus(syncDone.ok ? 'COMPLETED' : 'FAILED');
      setFinalMessage(syncDone.message);
    }
  }, [scanId, syncDone]);

  // Poll for real progress when scan_id is known
  useEffect(() => {
    if (!scanId) return;
    pollRef.current = setInterval(async () => {
      try {
        const res = await api.get(`/scans/runs/${scanId}`);
        const run: ScanRun = res.data;
        if (run.progress) setProgress(run.progress);
        setScanStatus(run.status);
        if (run.status === 'COMPLETED' || run.status === 'FAILED') {
          clearInterval(pollRef.current!);
          setFinalMessage(run.error ?? (run.status === 'COMPLETED' ? 'Scan completed successfully' : 'Scan failed'));
        }
      } catch { /* silent */ }
    }, 2000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [scanId]);

  const selectedList = schemas.filter(s => selectedSchemas.includes(s.schema_name));
  const totalTables  = selectedList.reduce((s, x) => s + x.table_count, 0);

  // Derive simulated current-schema when no real progress yet
  const simulatedSchema = (() => {
    if (progress?.current_schema) return progress.current_schema;
    if (selectedList.length === 0) return null;
    // Walk through schemas proportional to their table counts
    const elapsedS = elapsed / 1000;
    const estTotal = Math.max(totalTables * 0.05, 10); // rough sec estimate
    let cumFrac = 0;
    for (const s of selectedList) {
      const frac = totalTables > 0 ? s.table_count / totalTables : 1 / selectedList.length;
      cumFrac += frac;
      if (cumFrac * estTotal > elapsedS) return s.schema_name;
    }
    return selectedList[selectedList.length - 1].schema_name;
  })();

  const schemasDone  = progress?.schemas_done  ?? 0;
  const tablesFound  = progress?.tables_done   ?? 0;
  const columnsFound = progress?.columns_done  ?? 0;
  const totalSchemas = progress?.schemas_total ?? selectedSchemas.length;
  const pct = totalSchemas > 0
    ? Math.min(98, Math.round((schemasDone / totalSchemas) * 100))
    : Math.min(98, Math.round((elapsed / 1000 / Math.max(totalTables * 0.05, 30)) * 100));
  const displayPct = scanStatus === 'COMPLETED' ? 100 : scanStatus === 'FAILED' ? pct : pct;

  // Estimated time remaining
  const etaMs = (() => {
    if (schemasDone === 0 || elapsed === 0) return null;
    const msPerSchema = elapsed / schemasDone;
    const remaining = (totalSchemas - schemasDone);
    return remaining > 0 ? remaining * msPerSchema : null;
  })();

  const isDone = scanStatus === 'COMPLETED' || scanStatus === 'FAILED';

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-2xl border border-slate-200 dark:border-slate-800 animate-scale-up overflow-hidden">

        {/* Header */}
        <div className={cn(
          "px-6 py-5 border-b border-slate-200 dark:border-slate-800",
          isDone
            ? (scanStatus === 'COMPLETED' ? "bg-green-50 dark:bg-green-950/20" : "bg-red-50 dark:bg-red-950/20")
            : "bg-gradient-to-r from-indigo-600 to-purple-700"
        )}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {isDone ? (
                scanStatus === 'COMPLETED'
                  ? <CheckCircle2 className="h-6 w-6 text-green-600 dark:text-green-400" />
                  : <XCircle className="h-6 w-6 text-red-600 dark:text-red-400" />
              ) : (
                <div className="relative">
                  <Database className="h-6 w-6 text-white" />
                  <span className="absolute -bottom-1 -right-1 h-3 w-3 bg-green-400 rounded-full border-2 border-white animate-pulse" />
                </div>
              )}
              <div>
                <h2 className={cn("text-lg font-bold", isDone ? "text-slate-900 dark:text-slate-100" : "text-white")}>
                  {isDone
                    ? (scanStatus === 'COMPLETED' ? 'Scan Complete' : 'Scan Failed')
                    : `Scanning ${source.name}`}
                </h2>
                <p className={cn("text-xs mt-0.5", isDone ? "text-slate-500" : "text-indigo-200")}>
                  {isDone
                    ? finalMessage
                    : `${selectedSchemas.length} schema${selectedSchemas.length !== 1 ? 's' : ''} · ${fmtRows(totalTables)} estimated tables`}
                </p>
              </div>
            </div>
            <div className={cn("text-sm font-mono font-bold", isDone ? "text-slate-500" : "text-indigo-200")}>
              {fmtDuration(elapsed)}
            </div>
          </div>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Progress bar */}
          <div>
            <div className="flex items-center justify-between text-xs font-semibold text-slate-600 dark:text-slate-400 mb-2">
              <span>
                {isDone
                  ? (scanStatus === 'COMPLETED' ? '✅ All done' : '❌ Scan stopped')
                  : progress?.current_schema
                    ? `Processing: ${progress.current_schema}`
                    : simulatedSchema
                      ? `Scanning: ${simulatedSchema}`
                      : 'Initialising…'}
              </span>
              <span className={cn("font-bold text-sm", isDone && scanStatus === 'COMPLETED' ? "text-green-600" : "text-brand-indigo")}>
                {displayPct}%
              </span>
            </div>
            <div className="h-3 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
              <div
                className={cn(
                  "h-full rounded-full transition-all duration-1000",
                  isDone
                    ? (scanStatus === 'COMPLETED' ? "bg-green-500" : "bg-red-500")
                    : "bg-gradient-to-r from-indigo-500 to-purple-600"
                )}
                style={{ width: `${displayPct}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1.5">
              <span>
                {schemasDone > 0 ? `${schemasDone} of ${totalSchemas} schemas done` : `${totalSchemas} schemas queued`}
              </span>
              {!isDone && etaMs !== null && (
                <span>ETA ~{fmtDuration(etaMs)}</span>
              )}
            </div>
          </div>

          {/* Live stats row */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { icon: <Layers className="h-4 w-4" />, label: 'Schemas done', value: schemasDone > 0 ? schemasDone.toString() : '—', color: 'text-purple-600 dark:text-purple-400' },
              { icon: <TableIcon className="h-4 w-4" />, label: 'Tables found', value: tablesFound > 0 ? tablesFound.toLocaleString() : '—', color: 'text-blue-600 dark:text-blue-400' },
              { icon: <Hash className="h-4 w-4" />, label: 'Columns found', value: columnsFound > 0 ? columnsFound.toLocaleString() : '—', color: 'text-indigo-600 dark:text-indigo-400' },
            ].map(({ icon, label, value, color }) => (
              <div key={label} className="bg-slate-50 dark:bg-slate-800/60 rounded-xl p-3 border border-slate-200 dark:border-slate-700">
                <div className={cn("flex items-center gap-1.5 text-xs font-semibold mb-1", color)}>
                  {icon} {label}
                </div>
                <div className="text-xl font-bold text-slate-900 dark:text-slate-100 font-mono">
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Schema status list */}
          <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
            <div className="bg-slate-50 dark:bg-slate-800/40 px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2">
              <BarChart3 className="h-3.5 w-3.5 text-slate-400" />
              <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Schema Queue</span>
            </div>
            <div className="max-h-48 overflow-y-auto">
              {selectedList.map((s, idx) => {
                const isDoneSchema = schemasDone > 0 && idx < schemasDone;
                const isCurrent = !isDone && (
                  (progress?.current_schema === s.schema_name) ||
                  (!progress?.current_schema && s.schema_name === simulatedSchema)
                );
                const isPending = !isDoneSchema && !isCurrent;
                return (
                  <div
                    key={s.schema_name}
                    className={cn(
                      "flex items-center justify-between px-4 py-2.5 border-b border-slate-100 dark:border-slate-800/60 last:border-0 transition-colors",
                      isCurrent && "bg-indigo-50 dark:bg-indigo-950/20",
                    )}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="flex-shrink-0">
                        {isDoneSchema ? (
                          <CircleCheck className="h-4 w-4 text-green-500" />
                        ) : isCurrent ? (
                          <Loader2 className="h-4 w-4 text-indigo-500 animate-spin" />
                        ) : (
                          <CircleDot className="h-4 w-4 text-slate-300 dark:text-slate-600" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <span className={cn(
                          "font-mono text-sm font-semibold truncate block",
                          isDoneSchema ? "text-green-700 dark:text-green-400" :
                          isCurrent   ? "text-indigo-700 dark:text-indigo-300" :
                          "text-slate-500 dark:text-slate-500"
                        )}>
                          {s.schema_name}
                        </span>
                        {isCurrent && progress?.current_table && (
                          <span className="text-[10px] text-indigo-500 dark:text-indigo-400 font-mono truncate block">
                            ↳ {progress.current_table}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0 text-right">
                      {s.table_count > 0 && (
                        <span className={cn("text-xs font-mono", isPending ? "text-slate-400" : isCurrent ? "text-indigo-600 dark:text-indigo-400" : "text-green-600 dark:text-green-400")}>
                          {s.table_count.toLocaleString()} tables
                        </span>
                      )}
                      {s.estimated_rows > 0 && (
                        <span className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded font-semibold",
                          s.estimated_rows >= 10_000_000 ? "bg-orange-100 dark:bg-orange-950/30 text-orange-700 dark:text-orange-400" :
                          s.estimated_rows >= 1_000_000  ? "bg-yellow-100 dark:bg-yellow-950/30 text-yellow-700 dark:text-yellow-400" :
                          "bg-slate-100 dark:bg-slate-800 text-slate-500"
                        )}>
                          {fmtRows(s.estimated_rows)}
                        </span>
                      )}
                      <span className={cn(
                        "text-[10px] font-bold uppercase tracking-wide w-16 text-right",
                        isDoneSchema ? "text-green-500" : isCurrent ? "text-indigo-500 animate-pulse" : "text-slate-300 dark:text-slate-600"
                      )}>
                        {isDoneSchema ? 'done' : isCurrent ? 'active' : 'queued'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Tip for large environments */}
          {!isDone && totalTables > 5000 && (
            <div className="flex items-start gap-2 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/40 rounded-lg px-3 py-2.5 text-xs text-amber-800 dark:text-amber-300">
              <Info className="h-3.5 w-3.5 flex-shrink-0 mt-0.5 text-amber-500" />
              <span>
                Large environment detected ({fmtRows(totalTables)} tables). Columns are fetched in bulk per schema — much faster than per-table mode. Progress updates every {Math.ceil(200 / Math.max(1, totalTables / selectedSchemas.length))} tables.
              </span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 flex items-center justify-between">
          <div className="text-xs text-slate-400 font-medium">
            {!isDone && <span className="flex items-center gap-1.5"><Zap className="h-3 w-3 text-yellow-500" /> Bulk schema scan active — do not close this window</span>}
            {isDone && scanStatus === 'COMPLETED' && <span className="text-green-600 dark:text-green-400 font-semibold">Catalog updated. You can now browse the Data Catalog.</span>}
          </div>
          {isDone ? (
            <button onClick={() => onClose({ ok: scanStatus === 'COMPLETED', message: finalMessage })}
              className="premium-btn-primary px-4 py-2 text-sm gap-2">
              <CheckCircle2 className="h-4 w-4" /> Close
            </button>
          ) : (
            <button onClick={onCancel}
              className="premium-btn-secondary px-4 py-2 text-sm gap-2 text-red-600 dark:text-red-400 border-red-200 dark:border-red-900/40">
              <Square className="h-3.5 w-3.5" /> Stop Scan
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Schema Browser Modal ──────────────────────────────────────────────────────

function SchemaBrowserModal({ source, onClose, onScanComplete }: {
  source: any;
  onClose: () => void;
  onScanComplete: (sourceId: number) => void;
}) {
  const [loading, setLoading] = useState(true);
  const [schemas, setSchemas] = useState<SchemaStatOut[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [fetchError, setFetchError] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('estimated_rows');
  const [sortAsc, setSortAsc] = useState(false);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [showProgress, setShowProgress] = useState(false);
  const [syncDone, setSyncDone] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setFetchError('');
      try {
        const res = await api.get(`/scans/${source.id}/schemas`);
        const data: SchemaStatOut[] = res.data;
        setSchemas(data);
        // Auto-select all by default
        setSelected(new Set(data.map((s) => s.schema_name)));
      } catch (err: any) {
        setFetchError(err.response?.data?.detail || 'Failed to connect and list schemas');
      } finally {
        setLoading(false);
      }
    })();
  }, [source.id]);

  const sorted = [...schemas].sort((a, b) => {
    const av = a[sortKey], bv = b[sortKey];
    if (typeof av === 'string') return sortAsc ? av.localeCompare(bv as string) : (bv as string).localeCompare(av);
    return sortAsc ? (av as number) - (bv as number) : (bv as number) - (av as number);
  });

  const cycleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc(p => !p);
    else { setSortKey(key); setSortAsc(key === 'schema_name'); }
  };

  const SortBtn = ({ k, label }: { k: SortKey; label: string }) => (
    <button onClick={() => cycleSort(k)} className="flex items-center gap-0.5 hover:text-slate-800 dark:hover:text-slate-200">
      {label} <ArrowUpDown className={cn('h-3 w-3 ml-0.5', sortKey === k ? 'text-indigo-500' : 'text-slate-300 dark:text-slate-600')} />
    </button>
  );

  const allSelected = selected.size === schemas.length && schemas.length > 0;
  const toggle = (name: string) => { const n = new Set(selected); n.has(name) ? n.delete(name) : n.add(name); setSelected(n); };
  const totalSelectedRows = schemas.filter(s => selected.has(s.schema_name)).reduce((sum, s) => sum + s.estimated_rows, 0);
  const totalSelectedTables = schemas.filter(s => selected.has(s.schema_name)).reduce((sum, s) => sum + s.table_count, 0);

  const startScan = async (schemasToScan?: string[]) => {
    const scanSchemas = schemasToScan ?? Array.from(selected);
    setSyncDone(null);
    try {
      // Async path: Celery worker running — get scan_id and poll
      const res = await api.post(`/scans/${source.id}/scan`, {});
      setActiveScanId(res.data.scan_id);
      setShowProgress(true);
    } catch {
      // Celery not available — fire sync scan without awaiting (don't block UI)
      setActiveScanId(null);
      setShowProgress(true);
      const body = scanSchemas.length > 0 ? { schemas: scanSchemas } : {};
      api.post(`/scans/${source.id}/scan/sync`, body)
        .then(() => setSyncDone({ ok: true, message: 'Scan completed successfully' }))
        .catch((err: any) => setSyncDone({
          ok: false,
          message: err?.response?.data?.detail || 'Scan failed',
        }));
    }
  };

  const handleCancel = async () => {
    try { await api.post(`/scans/${source.id}/cancel`); } catch { /* silent */ }
    setShowProgress(false);
  };

  const handleProgressClose = async (result: { ok: boolean; message: string } | null) => {
    setShowProgress(false);
    setActiveScanId(null);
    if (result?.ok) onScanComplete(source.id);
  };

  if (showProgress) {
    return (
      <ScanProgressModal
        source={source}
        schemas={schemas}
        selectedSchemas={Array.from(selected)}
        scanId={activeScanId}
        syncDone={syncDone}
        onCancel={handleCancel}
        onClose={handleProgressClose}
      />
    );
  }

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-4xl max-h-[90vh] flex flex-col border border-slate-200 dark:border-slate-800 animate-scale-up">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-100 dark:bg-indigo-950/40">
              <Layers className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">{source.name}</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Select schemas to scan · {schemas.length} schemas available
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-4 min-h-0">
          {loading && (
            <div className="py-16 text-center">
              <Loader2 className="h-10 w-10 mx-auto mb-3 animate-spin text-brand-indigo" />
              <p className="text-sm text-slate-500">Connecting and reading schema statistics…</p>
              <p className="text-xs text-slate-400 mt-1">This may take a few seconds for large databases</p>
            </div>
          )}

          {!loading && fetchError && (
            <div className="bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 px-4 py-3 rounded-lg text-sm flex items-center gap-2">
              <XCircle className="h-4 w-4 flex-shrink-0" /> {fetchError}
            </div>
          )}

          {!loading && !fetchError && schemas.length === 0 && (
            <div className="py-12 text-center">
              <Database className="h-10 w-10 mx-auto mb-2 text-slate-300 dark:text-slate-700 animate-pulse" />
              <p className="text-slate-500 text-sm">No schemas found in this data source.</p>
            </div>
          )}

          {!loading && schemas.length > 0 && (
            <>
              {source.type === 'oracle' && (
                <div className="mb-4 flex gap-2 bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-900/50 rounded-xl px-3 py-2.5 text-xs text-amber-800 dark:text-amber-300">
                  <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0 text-amber-500" />
                  <span>
                    <strong>Oracle ERP:</strong> Row counts from{' '}
                    <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded font-mono">ALL_TABLES.NUM_ROWS</code>.
                    Columns are fetched via <code className="bg-amber-100 dark:bg-amber-900/40 px-1 rounded font-mono">ALL_TAB_COLUMNS</code> per-schema (one query per schema instead of per table — optimised for 10K+ table environments).
                    Scan one schema at a time for schemas with 100M+ rows.
                  </span>
                </div>
              )}

              {/* Summary stats */}
              {selected.size > 0 && (
                <div className="grid grid-cols-3 gap-3 mb-4">
                  {[
                    { label: 'Selected schemas', value: selected.size, icon: <Layers className="h-3.5 w-3.5" />, color: 'text-purple-600 dark:text-purple-400' },
                    { label: 'Total tables', value: totalSelectedTables.toLocaleString(), icon: <TableIcon className="h-3.5 w-3.5" />, color: 'text-blue-600 dark:text-blue-400' },
                    { label: 'Estimated rows', value: fmtRows(totalSelectedRows), icon: <BarChart3 className="h-3.5 w-3.5" />, color: 'text-indigo-600 dark:text-indigo-400' },
                  ].map(({ label, value, icon, color }) => (
                    <div key={label} className="bg-slate-50 dark:bg-slate-800/60 rounded-xl px-4 py-3 border border-slate-200 dark:border-slate-700">
                      <div className={cn("flex items-center gap-1.5 text-xs font-semibold mb-0.5", color)}>{icon}{label}</div>
                      <div className="text-lg font-bold text-slate-900 dark:text-slate-100 font-mono">{value}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* Controls */}
              <div className="flex items-center justify-between mb-3 text-xs">
                <div className="flex items-center gap-3">
                  <button onClick={() => setSelected(allSelected ? new Set() : new Set(schemas.map(s => s.schema_name)))}
                    className="font-semibold text-brand-indigo hover:text-brand-indigo/80 transition-colors">
                    {allSelected ? 'Deselect All' : 'Select All'}
                  </button>
                  <span className="text-slate-400">{selected.size} of {schemas.length} schemas</span>
                </div>
                <span className="text-slate-400 italic">Row counts are estimates from DB statistics</span>
              </div>

              {/* Schema table */}
              <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden">
                <table className="min-w-full text-sm">
                  <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
                    <tr className="text-left text-xs text-slate-500 dark:text-slate-400 uppercase tracking-wider font-semibold">
                      <th className="px-4 py-3 w-8">
                        <input type="checkbox" checked={allSelected}
                          onChange={() => setSelected(allSelected ? new Set() : new Set(schemas.map(s => s.schema_name)))}
                          className="rounded border-slate-300 dark:border-slate-700 text-brand-indigo" />
                      </th>
                      <th className="px-4 py-3"><SortBtn k="schema_name" label="Schema" /></th>
                      <th className="px-4 py-3 text-right"><SortBtn k="table_count" label="Tables" /></th>
                      <th className="px-4 py-3 text-right"><SortBtn k="estimated_rows" label="Est. Rows" /></th>
                      <th className="px-4 py-3 text-right">Scale</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                    {sorted.map(s => {
                      const isSel = selected.has(s.schema_name);
                      const badge =
                        s.estimated_rows >= 100_000_000 ? { label: '100M+', cls: 'bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400' }
                        : s.estimated_rows >= 10_000_000  ? { label: '10M+',  cls: 'bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400' }
                        : s.estimated_rows >= 1_000_000   ? { label: '1M+',   cls: 'bg-yellow-100 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-400' }
                        : s.estimated_rows >= 1_000        ? { label: '<1M',  cls: 'bg-green-100 dark:bg-green-950/40 text-green-700 dark:text-green-400' }
                        : null;
                      return (
                        <tr key={s.schema_name}
                          onClick={() => toggle(s.schema_name)}
                          className={cn('cursor-pointer transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/30', isSel && 'bg-indigo-50/50 dark:bg-indigo-950/10')}>
                          <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                            <input type="checkbox" checked={isSel} onChange={() => toggle(s.schema_name)}
                              className="rounded border-slate-300 dark:border-slate-700 text-brand-indigo" />
                          </td>
                          <td className="px-4 py-3 font-mono text-slate-900 dark:text-slate-100 font-semibold">{s.schema_name}</td>
                          <td className="px-4 py-3 text-right text-slate-600 dark:text-slate-400 font-mono">{s.table_count.toLocaleString()}</td>
                          <td className={cn("px-4 py-3 text-right font-mono font-semibold",
                            s.estimated_rows >= 100_000_000 ? 'text-red-600' :
                            s.estimated_rows >= 10_000_000  ? 'text-orange-600' :
                            s.estimated_rows >= 1_000_000   ? 'text-yellow-600 dark:text-yellow-500' :
                            'text-slate-600 dark:text-slate-400')}>
                            {s.estimated_rows > 0 ? fmtRows(s.estimated_rows) : <span className="text-slate-300 dark:text-slate-700">—</span>}
                          </td>
                          <td className="px-4 py-3 text-right">
                            {badge && (
                              <span className={cn('inline-flex px-1.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider', badge.cls)}>
                                {badge.label}
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        {!loading && schemas.length > 0 && (
          <div className="border-t border-slate-200 dark:border-slate-800 px-6 py-4 bg-slate-50 dark:bg-slate-900/60 rounded-b-2xl">
            <div className="flex items-center justify-between">
              <p className="text-xs text-slate-500 dark:text-slate-400 font-medium">
                {selected.size > 0
                  ? `${selected.size} schema${selected.size !== 1 ? 's' : ''} · ${totalSelectedTables.toLocaleString()} tables · ~${fmtRows(totalSelectedRows)} rows`
                  : 'No schemas selected'}
              </p>
              <div className="flex items-center gap-2">
                <button onClick={onClose} className="premium-btn-secondary px-4 py-2 text-sm">Close</button>
                <button
                  onClick={() => startScan(Array.from(selected))}
                  disabled={selected.size === 0 || !isAdmin()}
                  className="premium-btn-primary px-4 py-2 text-sm gap-2"
                >
                  <Play className="h-3.5 w-3.5" />
                  Scan {selected.size} Schema{selected.size !== 1 ? 's' : ''}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Connector Picker ──────────────────────────────────────────────────────────

function ConnectorPicker({ onSelect, onCancel }: { onSelect: (c: Connector) => void; onCancel: () => void }) {
  const [search, setSearch] = useState('');
  const [activeCategory, setActiveCategory] = useState<ConnectorCategory | 'all'>('all');

  const filtered = CONNECTORS.filter(c =>
    c.display_name.toLowerCase().includes(search.toLowerCase()) &&
    (activeCategory === 'all' || c.category === activeCategory)
  );
  const grouped = CATEGORY_ORDER.reduce<Record<string, Connector[]>>((acc, cat) => {
    const items = filtered.filter(c => c.category === cat);
    if (items.length) acc[cat] = items;
    return acc;
  }, {});

  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-lg rounded-xl mb-6 overflow-hidden">
      <div className="px-4 py-4 sm:px-6 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900/50">
        <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">Select a Connector</h3>
        <button onClick={onCancel} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"><X className="h-5 w-5" /></button>
      </div>
      <div className="px-4 py-3.5 sm:px-6 border-b border-slate-100 dark:border-slate-800/80 space-y-3 bg-white dark:bg-slate-900">
        <div className="relative">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
          <input type="text" placeholder="Search connectors…" value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 border border-slate-250 dark:border-slate-800 rounded-lg outline-none focus:border-brand-indigo transition-all" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {['all', ...CATEGORY_ORDER].map(cat => (
            <button key={cat} onClick={() => setActiveCategory(cat as any)}
              className={cn('px-2.5 py-1 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors',
                activeCategory === cat ? 'bg-brand-indigo text-white shadow-sm' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700')}>
              {cat === 'all' ? `All (${CONNECTORS.length})` : `${CATEGORY_LABELS[cat as ConnectorCategory]} (${(CONNECTORS_BY_CATEGORY[cat as ConnectorCategory] ?? []).length})`}
            </button>
          ))}
        </div>
      </div>
      <div className="px-4 py-4 sm:px-6 max-h-[480px] overflow-y-auto space-y-6 bg-white dark:bg-slate-900">
        {Object.entries(grouped).map(([cat, items]) => (
          <div key={cat}>
            <h4 className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-3">{CATEGORY_LABELS[cat as ConnectorCategory]}</h4>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-2.5">
              {items.map(c => (
                <button key={c.type} onClick={() => onSelect(c)}
                  className="flex flex-col items-center justify-center p-3 rounded-lg border border-slate-200 dark:border-slate-800/80 hover:border-brand-indigo dark:hover:border-brand-indigo hover:bg-brand-indigo/5 dark:hover:bg-brand-indigo/10 transition-all text-center group active:scale-[0.98]">
                  <Database className="h-6 w-6 text-slate-400 dark:text-slate-500 group-hover:text-brand-indigo transition-colors mb-1.5" />
                  <span className="text-xs font-bold text-slate-800 dark:text-slate-200 group-hover:text-slate-900 dark:group-hover:text-white leading-tight">{c.display_name}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
        {Object.keys(grouped).length === 0 && <p className="text-center text-slate-400 py-8 text-sm">No connectors match your search.</p>}
      </div>
    </div>
  );
}

// ── Connection Form ───────────────────────────────────────────────────────────

const CONNECTOR_CONFIG_HINTS: Record<string, React.ReactNode> = {
  mongodb: (
    <div className="mt-2 flex gap-2 bg-amber-50 border border-amber-200 rounded-md px-3 py-2 text-xs text-amber-800">
      <Info className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
      <span>Set <code className="font-mono bg-amber-100 px-1 rounded">database</code> to the DB name. Without it the scanner cannot enumerate collections.</span>
    </div>
  ),
};

function ConnectionForm({ connector, onSubmit, onBack, error }: {
  connector: Connector; onSubmit: (n: string, c: string, v: string) => void; onBack: () => void; error: string;
}) {
  const [name, setName] = useState('');
  const [config, setConfig] = useState(() => getConfigTemplate(connector.type));
  const [useVault, setUseVault] = useState(false);
  const [vaultPath, setVaultPath] = useState('');
  return (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-lg rounded-xl mb-6 overflow-hidden animate-scale-up">
      <div className="px-4 py-4 sm:px-6 border-b border-slate-200 dark:border-slate-800 flex items-center gap-3 bg-slate-50 dark:bg-slate-900/50">
        <button onClick={onBack} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"><ArrowLeft className="h-5 w-5" /></button>
        <Database className="h-5 w-5 text-slate-400" />
        <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">{connector.display_name}</h3>
        <span className={cn('inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider', CATEGORY_COLORS[connector.category])}>
          {CATEGORY_LABELS[connector.category]}
        </span>
      </div>
      <div className="px-4 py-5 sm:p-6">
        {error && <div className="mb-4 bg-red-50 dark:bg-red-950/20 border border-red-250 dark:border-red-900/50 text-red-600 dark:text-red-400 px-4 py-3 rounded-lg text-sm">{error}</div>}
        <form className="space-y-4" onSubmit={e => { e.preventDefault(); onSubmit(name, config, useVault ? vaultPath : ''); }}>
          <div>
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Connection Name</label>
            <input type="text" required placeholder={`Production ${connector.display_name}`} value={name} onChange={e => setName(e.target.value)} className="premium-input" />
          </div>
          <div className="border border-purple-200 dark:border-purple-900/40 rounded-xl bg-purple-50/30 dark:bg-purple-950/10 p-4">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2"><KeyRound className="h-4 w-4 text-purple-600 dark:text-purple-400" /><span className="text-sm font-semibold text-slate-800 dark:text-slate-205">Use HashiCorp Vault</span></div>
              <button type="button" onClick={() => setUseVault(v => !v)}
                className={cn('relative inline-flex h-5 w-9 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200', useVault ? 'bg-purple-600' : 'bg-slate-300 dark:bg-slate-700')}
                role="switch" aria-checked={useVault}>
                <span className={cn('pointer-events-none block h-4 w-4 rounded-full bg-white shadow transition-transform duration-200', useVault ? 'translate-x-4' : 'translate-x-0')} />
              </button>
            </div>
            <p className="text-xs text-slate-400 dark:text-slate-500">When enabled, credentials are fetched from Vault — no secrets stored in MetaSight.</p>
            {useVault && (
              <div className="mt-3">
                <label className="block text-xs font-semibold text-purple-600 dark:text-purple-400 mb-1.5 uppercase tracking-wider">Vault Secret Path</label>
                <input type="text" required={useVault} placeholder="secret/data/datasources/prod-oracle" value={vaultPath} onChange={e => setVaultPath(e.target.value)}
                  className="block w-full border border-purple-300 dark:border-purple-800/80 rounded-lg py-1.5 px-3 text-sm bg-white dark:bg-slate-900 text-slate-950 dark:text-white focus:outline-none" />
              </div>
            )}
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Configuration (JSON)</label>
            {!useVault && <p className="text-[10px] text-slate-400 dark:text-slate-500 mb-1.5">Credentials are AES-256 encrypted at rest.</p>}
            <textarea required={!useVault} rows={10} value={config} onChange={e => setConfig(e.target.value)} className="premium-input font-mono text-xs" />
            {CONNECTOR_CONFIG_HINTS[connector.type] ?? null}
          </div>
          <div className="flex justify-end space-x-2.5 pt-2">
            <button type="button" onClick={onBack} className="premium-btn-secondary">Back</button>
            <button type="submit" className="premium-btn-primary">Save Connection</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Inline Edit Form ──────────────────────────────────────────────────────────

function EditForm({ source, onSave, onCancel }: {
  source: any; onSave: (id: number, n: string, c: string, v: string | null) => Promise<void>; onCancel: () => void;
}) {
  const [name, setName] = useState(source.name);
  const [config, setConfig] = useState(getConfigTemplate(source.type));
  const [vaultPath, setVaultPath] = useState<string>(source.vault_path ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault(); setError(''); setSaving(true);
    try { await onSave(source.id, name, config, vaultPath); }
    catch (err: any) { setError(err.message || 'Save failed'); }
    finally { setSaving(false); }
  };
  return (
    <div className="mt-4 border border-slate-200 dark:border-slate-800 rounded-xl bg-slate-50/50 dark:bg-slate-900/30 p-4 animate-scale-up">
      {error && <div className="mb-3 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 px-3 py-2 rounded-lg text-sm">{error}</div>}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Connection Name</label>
          <input type="text" required value={name} onChange={e => setName(e.target.value)} className="premium-input" />
        </div>
        <div className="border border-purple-200 dark:border-purple-905/30 rounded-xl bg-purple-50/30 dark:bg-purple-950/10 p-4">
          <div className="flex items-center gap-1.5 mb-1.5"><KeyRound className="h-4 w-4 text-purple-600 dark:text-purple-400" /><label className="block text-sm font-semibold text-slate-800 dark:text-slate-200">HashiCorp Vault Path</label></div>
          <input type="text" placeholder="secret/data/datasources/prod-oracle  (leave blank to disable)" value={vaultPath} onChange={e => setVaultPath(e.target.value)}
            className="block w-full border border-purple-300 dark:border-purple-800 rounded-lg py-1.5 px-3 text-xs bg-white dark:bg-slate-900 text-slate-950 dark:text-white focus:outline-none" />
        </div>
        <div>
          <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">New Configuration (JSON)</label>
          <p className="text-xs text-amber-600 dark:text-amber-400 mb-1.5 font-medium">Config is encrypted — enter updated credentials. Leave as template to keep existing.</p>
          <textarea rows={8} value={config} onChange={e => setConfig(e.target.value)} className="premium-input font-mono text-xs" />
        </div>
        <div className="flex items-center gap-2 pt-2">
          <button type="submit" disabled={saving} className="premium-btn-primary gap-1.5"><Check className="h-4 w-4" />{saving ? 'Saving…' : 'Save Changes'}</button>
          <button type="button" onClick={onCancel} className="premium-btn-secondary">Cancel</button>
        </div>
      </form>
    </div>
  );
}

// ── Scan History Panel ────────────────────────────────────────────────────────

function ScanHistoryPanel({ runs }: { runs: ScanRun[] }) {
  if (!runs.length) return <p className="text-xs text-slate-450 dark:text-slate-500 font-medium py-2">No scan history for this source.</p>;
  return (
    <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden mt-4">
      <table className="min-w-full text-xs">
        <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
          <tr className="text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
            <th className="text-left px-4 py-2.5">Run</th>
            <th className="text-left px-4 py-2.5">Status</th>
            <th className="text-left px-4 py-2.5">Result</th>
            <th className="text-left px-4 py-2.5">Started</th>
            <th className="text-left px-4 py-2.5">Duration</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
          {runs.map(run => {
            const started  = run.started_at  ? new Date(run.started_at)  : null;
            const finished = run.finished_at ? new Date(run.finished_at) : null;
            const durMs = started && finished ? finished.getTime() - started.getTime() : null;
            const counts = run.status === 'COMPLETED' && run.error ? parseScanCounts(run.error) : null;
            const cfg = STATUS_CONFIG[run.status];
            return (
              <tr key={run.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/10 transition-colors">
                <td className="px-4 py-2.5 text-slate-700 dark:text-slate-300 font-mono font-semibold">#{run.id}</td>
                <td className="px-4 py-2.5">
                  <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border', cfg.cls)}>
                    {cfg.icon} {cfg.label}
                  </span>
                </td>
                <td className="px-4 py-2.5 max-w-xs">
                  {counts ? (
                    <div className="flex items-center gap-3 text-[10px] font-semibold">
                      <span className="text-purple-600 dark:text-purple-400">{counts.schemas} schemas</span>
                      <span className="text-blue-600 dark:text-blue-400">{counts.tables.toLocaleString()} tables</span>
                      <span className="text-indigo-600 dark:text-indigo-400">{counts.columns.toLocaleString()} cols</span>
                    </div>
                  ) : run.error ? (
                    <span className="text-red-500 dark:text-red-400 font-medium truncate block max-w-xs" title={run.error}>{run.error}</span>
                  ) : <span className="text-slate-300 dark:text-slate-700">—</span>}
                </td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 font-mono whitespace-nowrap">
                  {started ? started.toLocaleString() : '—'}
                </td>
                <td className="px-4 py-2.5 text-slate-500 dark:text-slate-400 font-mono whitespace-nowrap">
                  {durMs !== null ? fmtDuration(durMs) : '—'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export function DataSources() {
  const admin = isAdmin();
  const [sources, setSources] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [addStep, setAddStep] = useState<'picker' | 'form' | null>(null);
  const [selectedConnector, setSelectedConnector] = useState<Connector | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [schemaBrowsingId, setSchemaBrowsingId] = useState<number | null>(null);
  const [history, setHistory] = useState<Record<number, ScanRun[]>>({});
  const [expandedHistory, setExpandedHistory] = useState<number | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [scanResult, setScanResult] = useState<Record<number, { ok: boolean; message: string }>>({});

  const fetchSources = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get('/sources');
      setSources(res.data.items || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch data sources');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSources(); }, [fetchSources]);

  const handleFormSubmit = async (name: string, configStr: string, vaultPath: string) => {
    setFormError('');
    let parsedConfig = {};
    try { parsedConfig = JSON.parse(configStr); }
    catch { setFormError('Invalid JSON configuration'); return; }
    try {
      await api.post('/sources', { name, type: selectedConnector!.type, category: selectedConnector!.category, config: parsedConfig, ...(vaultPath ? { vault_path: vaultPath } : {}) });
      setAddStep(null); setSelectedConnector(null);
      fetchSources();
    } catch (err: any) { setFormError(err.response?.data?.detail || 'Failed to add data source'); }
  };

  const handleEditSave = async (id: number, name: string, configStr: string, vaultPath: string | null) => {
    let parsedConfig: object | undefined;
    if (configStr.trim()) { try { parsedConfig = JSON.parse(configStr); } catch { throw new Error('Invalid JSON'); } }
    await api.patch(`/sources/${id}`, { name, vault_path: vaultPath ?? '', ...(parsedConfig ? { config: parsedConfig } : {}) });
    setEditingId(null); fetchSources();
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this data source and all its catalog metadata?')) return;
    try { await api.delete(`/sources/${id}`); fetchSources(); }
    catch (err: any) { setError(err.response?.data?.detail || 'Failed to delete'); }
  };

  const toggleHistory = async (id: number) => {
    if (expandedHistory === id) { setExpandedHistory(null); return; }
    try {
      const res = await api.get(`/scans/${id}/history`);
      setHistory(h => ({ ...h, [id]: res.data.items || [] }));
      setExpandedHistory(id);
    } catch (err: any) { setError(err.response?.data?.detail || 'Failed to fetch history'); }
  };

  const handleModalScanComplete = async (sourceId: number) => {
    const res = await api.get(`/scans/${sourceId}/history`).catch(() => ({ data: { items: [] } }));
    setHistory(h => ({ ...h, [sourceId]: res.data.items || [] }));
    setExpandedHistory(sourceId);
  };

  const presentCategories = Array.from(new Set(sources.map(s => s.category).filter(Boolean)));
  const visibleSources = sources.filter(s =>
    (filterCategory === 'all' || s.category === filterCategory) &&
    (s.name.toLowerCase().includes(searchQuery.toLowerCase()) || (s.type ?? '').toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Data Sources</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Manage connections, scan database schemas, and monitor discovery progress.
          </p>
        </div>
        {admin && addStep === null && (
          <button onClick={() => { setAddStep('picker'); setEditingId(null); }} className="premium-btn-primary gap-2">
            <Plus className="h-4 w-4" /> Add Source
          </button>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/20 border border-red-250 dark:border-red-900/50 text-red-600 dark:text-red-400 px-4 py-3 rounded-lg text-sm flex items-center justify-between">
          <span>{error}</span>
          <button className="underline font-semibold ml-2" onClick={() => setError('')}>Dismiss</button>
        </div>
      )}

      {/* Schema Browser modal */}
      {schemaBrowsingId !== null && (() => {
        const src = sources.find(s => s.id === schemaBrowsingId);
        return src ? (
          <SchemaBrowserModal
            source={src}
            onClose={() => setSchemaBrowsingId(null)}
            onScanComplete={handleModalScanComplete}
          />
        ) : null;
      })()}

      {addStep === 'picker' && <ConnectorPicker onSelect={c => { setSelectedConnector(c); setFormError(''); setAddStep('form'); }} onCancel={() => setAddStep(null)} />}
      {addStep === 'form' && selectedConnector && (
        <ConnectionForm connector={selectedConnector} onSubmit={handleFormSubmit} onBack={() => setAddStep('picker')} error={formError} />
      )}

      {/* Filters */}
      {addStep === null && sources.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px] max-w-xs">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
            <input type="text" placeholder="Search sources…" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="premium-input pl-9" />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {['all', ...presentCategories].map(cat => (
              <button key={cat} onClick={() => setFilterCategory(cat)}
                className={cn('px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-colors',
                  filterCategory === cat ? 'bg-brand-indigo text-white shadow-sm' : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700')}>
                {cat === 'all' ? `All (${sources.length})` : CATEGORY_LABELS[cat as ConnectorCategory] ?? cat}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Source list */}
      {addStep === null && (
        <div className="space-y-4">
          {loading ? (
            <div className="p-8 text-center text-slate-500 dark:text-slate-400">
              <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
              <p className="text-sm">Loading connections…</p>
            </div>
          ) : sources.length === 0 ? (
            <div className="p-12 text-center border border-dashed border-slate-250 dark:border-slate-800 rounded-xl bg-white dark:bg-slate-900/40">
              <Database className="h-12 w-12 mx-auto mb-3 text-slate-300 dark:text-slate-700" />
              <p className="font-semibold text-slate-800 dark:text-slate-200">No data sources yet.</p>
              {admin && <p className="text-xs mt-1 text-slate-500">Click <strong>Add Source</strong> to connect your first database.</p>}
            </div>
          ) : visibleSources.length === 0 ? (
            <div className="p-8 text-center text-slate-400 dark:text-slate-500">No sources match your filter.</div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {visibleSources.map((source: any) => {
                const lastScan = history[source.id]?.[0];
                const sr = scanResult[source.id];
                return (
                  <div key={source.id} className="premium-card p-5">
                    <div className="flex items-start justify-between flex-wrap gap-4">
                      {/* Source info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <div className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800">
                            <Database className="h-4 w-4 text-slate-500 dark:text-slate-400" />
                          </div>
                          <div>
                            <div className="flex items-center gap-2 flex-wrap">
                              <h3 className="font-bold text-slate-900 dark:text-slate-100 text-base">{source.name}</h3>
                              <span className="text-[10px] font-mono uppercase bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-1.5 py-0.5 rounded text-slate-600 dark:text-slate-300">{source.type}</span>
                              {source.category && (
                                <span className={cn('inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider', CATEGORY_COLORS[source.category as ConnectorCategory] ?? 'bg-slate-150 text-slate-700')}>
                                  {CATEGORY_LABELS[source.category as ConnectorCategory] ?? source.category}
                                </span>
                              )}
                              {source.vault_path && (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-purple-100 dark:bg-purple-950/40 text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-900/50 uppercase tracking-wider">
                                  <Lock className="h-3 w-3" /> Vault
                                </span>
                              )}
                            </div>
                            <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">
                              Added {new Date(source.created_at).toLocaleDateString()}
                              {lastScan && ` · Last scan ${new Date(lastScan.started_at ?? 0).toLocaleDateString()}`}
                            </p>
                          </div>
                        </div>

                        {/* Last scan result inline */}
                        {sr && (
                          <div className={cn(
                            'mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold border',
                            sr.ok ? 'bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-900/50'
                                  : 'bg-red-50 dark:bg-red-950/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900/50'
                          )}>
                            {sr.ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                            {sr.message}
                          </div>
                        )}
                      </div>

                      {/* Action buttons */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <button onClick={() => toggleHistory(source.id)}
                          className="premium-btn-secondary px-2.5 py-1.5 text-xs gap-1.5" title="Scan history">
                          <Clock className="h-3.5 w-3.5" /> History
                          {expandedHistory === source.id ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                        </button>
                        {admin && (
                          <>
                            <button
                              onClick={() => { setEditingId(editingId === source.id ? null : source.id); setExpandedHistory(null); }}
                              className={cn('premium-btn-secondary px-2.5 py-1.5 text-xs gap-1.5', editingId === source.id && 'border-brand-indigo text-brand-indigo')}
                              title="Edit">
                              <Pencil className="h-3.5 w-3.5" /> Edit
                            </button>
                            <button
                              onClick={() => { setSchemaBrowsingId(source.id); setEditingId(null); setExpandedHistory(null); }}
                              className="premium-btn-secondary px-2.5 py-1.5 text-xs gap-1.5 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-900/40 hover:bg-indigo-50 dark:hover:bg-indigo-950/20"
                              title="Browse schemas and scan selectively">
                              <TrendingUp className="h-3.5 w-3.5" /> Scan / Discover
                            </button>
                            <button
                              onClick={() => handleDelete(source.id)}
                              className="p-1.5 rounded-lg bg-red-50 hover:bg-red-100 dark:bg-red-950/20 dark:hover:bg-red-950/40 text-red-650 dark:text-red-400 transition-colors"
                              title="Delete">
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </>
                        )}
                      </div>
                    </div>

                    {editingId === source.id && (
                      <EditForm source={source} onSave={handleEditSave} onCancel={() => setEditingId(null)} />
                    )}

                    {expandedHistory === source.id && (
                      <div className="mt-4 border-t border-slate-200 dark:border-slate-800 pt-4 animate-slide-up">
                        <ScanHistoryPanel runs={history[source.id] ?? []} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
