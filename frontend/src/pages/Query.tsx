import React, { useState, useEffect, useRef } from 'react';
import {
  Play, ChevronDown, ChevronUp, AlertTriangle, Shield,
  Clock, Hash, Eye, EyeOff, Terminal, Database,
  Layers, Table as TableIcon, ChevronRight, Search, RefreshCw,
} from 'lucide-react';
import { api, isAdmin } from '../api';
import { cn } from '../lib/utils';
import { useLocation } from 'react-router-dom';

// ── Types ──────────────────────────────────────────────────────────────────────

type DataSource = {
  id: number; name: string; type: string; category: string; tenant_id: number; created_at: string;
};

type PolicySummary = {
  resource: string; classification: string | null; auto_policy: boolean;
  masked_columns: string[]; tokenized_columns: string[]; denied_columns: string[];
  row_filter_applied: boolean; is_admin_exempt: boolean;
};

type RiskScore = {
  score: number; level: string; factors: Record<string, unknown>; recommendations: string[];
};

type QueryResult = {
  columns: string[]; rows: unknown[][]; row_count: number;
  execution_time_ms: number; policy: PolicySummary;
  rewritten_sql: string; audit_id: number | null; warnings: string[];
  risk?: RiskScore; masking_level?: string;
};

type SchemaItem = {
  id: number; name: string; database_id: number; database_name: string;
  source_id: number; table_count: number; pii_count: number;
};

type BrowseTable = {
  id: number; name: string; schema_name: string; database_name: string; source_type: string;
};

// ── Classification badge colors ────────────────────────────────────────────────

const CLASS_COLORS: Record<string, string> = {
  PUBLIC:    'bg-green-100 dark:bg-green-950/40 text-green-800 dark:text-green-400 border border-green-200 dark:border-green-900/40',
  PII:       'bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-400 border border-red-200 dark:border-red-900/40',
  FINANCIAL: 'bg-amber-100 dark:bg-amber-950/40 text-amber-805 dark:text-amber-400 border border-amber-200 dark:border-amber-900/40',
};

// ── PolicyBar ─────────────────────────────────────────────────────────────────

function PolicyBar({ policy }: { policy: PolicySummary }) {
  const classColor = (policy.classification && CLASS_COLORS[policy.classification])
    ?? 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700';
  const masked = policy.masked_columns ?? [];
  const tokenized = policy.tokenized_columns ?? [];
  const denied = policy.denied_columns ?? [];

  return (
    <div className="flex flex-wrap items-center gap-2.5 p-3.5 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-xs font-semibold">
      <Shield className="w-4 h-4 text-slate-400 dark:text-slate-500 flex-shrink-0" />
      <span className={cn('px-2 py-0.5 rounded border uppercase tracking-wider text-[10px]', classColor)}>
        {policy.classification ?? 'AUTO'}
      </span>
      {policy.auto_policy && (
        <span className="px-2 py-0.5 rounded border text-[10px] bg-purple-100 dark:bg-purple-950/40 text-purple-800 dark:text-purple-400 border-purple-200 dark:border-purple-900/40 uppercase tracking-wider">Auto-Policy</span>
      )}
      {masked.length > 0 && <span className="text-yellow-600 dark:text-yellow-500 font-bold uppercase tracking-wider">{masked.length} masked</span>}
      {tokenized.length > 0 && <span className="text-blue-600 dark:text-blue-500 font-bold uppercase tracking-wider">{tokenized.length} tokenized</span>}
      {denied.length > 0 && <span className="text-red-600 dark:text-red-500 font-bold uppercase tracking-wider">{denied.length} denied</span>}
      {policy.row_filter_applied && <span className="text-brand-indigo font-bold uppercase tracking-wider">Row filter active</span>}
      {policy.is_admin_exempt && (
        <span className="px-2 py-0.5 rounded border text-[10px] bg-indigo-50 dark:bg-indigo-950/40 text-indigo-700 dark:text-indigo-400 border-indigo-200 dark:border-indigo-900/40 uppercase tracking-wider">Admin exempt</span>
      )}
    </div>
  );
}

// ── RewrittenSQL ───────────────────────────────────────────────────────────────

function RewrittenSQL({ original, rewritten }: { original: string; rewritten: string }) {
  const [open, setOpen] = useState(false);
  const changed = original.trim() !== rewritten.trim();
  return (
    <div className="border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
      <button onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-50 dark:bg-slate-900/80 text-xs font-bold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
        <span className="flex items-center gap-2">
          Rewritten Query
          {changed && (
            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-yellow-100 dark:bg-yellow-950/30 text-yellow-800 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-900/50 tracking-wider">modified</span>
          )}
        </span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>
      {open && (
        <pre className="p-4 text-xs font-mono bg-slate-950 text-slate-100 border-t border-slate-200 dark:border-slate-800 overflow-x-auto whitespace-pre-wrap break-all select-all">
          {rewritten}
        </pre>
      )}
    </div>
  );
}

// ── CellValue ─────────────────────────────────────────────────────────────────

function CellValue({ value, col, policy, auditId }: { value: unknown; col: string; policy: PolicySummary; auditId: number | null }) {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const masked = policy.masked_columns ?? [];
  const tokenized = policy.tokenized_columns ?? [];
  const denied = policy.denied_columns ?? [];

  const isMasked = masked.includes(col);
  const isTokenized = tokenized.includes(col);
  const isExplicitlyDenied = denied.includes(col);
  const displayValue = value === null || value === undefined ? 'NULL' : String(value);

  const handleDetokenize = async () => {
    if (!isTokenized || typeof value !== 'string') return;
    setLoading(true);
    try {
      const res = await api.post(`/query/detokenize?token=${encodeURIComponent(value)}`);
      setRevealed(res.data.value);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  };

  if (isAdmin()) {
    return <span className="text-xs text-slate-900 dark:text-slate-100 font-mono">{displayValue}</span>;
  }

  if (isExplicitlyDenied || (value === null && isExplicitlyDenied)) {
    return <span className="text-red-500 dark:text-red-400 italic line-through text-xs font-medium">{col} denied</span>;
  }
  if (value === null) {
    return <span className="text-slate-400 dark:text-slate-600 text-xs font-mono italic">NULL</span>;
  }
  if (isMasked) {
    return <span className="bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-250 dark:border-amber-900/30 px-1.5 py-0.5 rounded font-mono text-xs font-semibold">{displayValue}</span>;
  }
  if (isTokenized) {
    if (revealed) {
      return (
        <span className="flex items-center gap-1.5">
          <span className="text-xs font-mono text-green-700 dark:text-green-400 font-semibold bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-900/30 px-1.5 py-0.5 rounded">{revealed}</span>
          <button onClick={() => setRevealed(null)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300" title="Hide"><EyeOff className="w-3.5 h-3.5" /></button>
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1.5">
        <span className="bg-blue-100 dark:bg-blue-950/40 text-blue-800 dark:text-blue-450 border border-blue-250 dark:border-blue-900/30 px-1.5 py-0.5 rounded font-mono text-xs font-semibold">{displayValue}</span>
        <button onClick={handleDetokenize} disabled={loading} className="text-slate-405 hover:text-brand-indigo dark:hover:text-indigo-400 transition-colors" title="Detokenize">
          {loading ? '…' : <Eye className="w-3.5 h-3.5" />}
        </button>
      </span>
    );
  }
  return <span className="text-xs text-slate-800 dark:text-slate-205 font-mono">{displayValue}</span>;
}

// ── ResultGrid ────────────────────────────────────────────────────────────────

function ResultGrid({ result }: { result: QueryResult }) {
  const columns = result.columns ?? [];
  const rows = result.rows ?? [];
  const masked = result.policy?.masked_columns ?? [];
  const tokenized = result.policy?.tokenized_columns ?? [];
  const denied = result.policy?.denied_columns ?? [];

  if (columns.length === 0 || rows.length === 0) {
    return <div className="text-center py-12 text-slate-400 dark:text-slate-500 text-sm font-medium">Query executed successfully but returned zero rows.</div>;
  }

  return (
    <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-xl">
      <table className="min-w-full">
        <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
          <tr>
            {columns.map((col) => {
              const isMasked = !isAdmin() && masked.includes(col);
              const isTokenized = !isAdmin() && tokenized.includes(col);
              const isDenied = !isAdmin() && denied.includes(col);
              return (
                <th key={col} className={cn('px-4 py-2.5 text-left text-xs font-bold uppercase tracking-wider',
                  isAdmin() ? 'text-slate-500' : isMasked ? 'text-yellow-750 dark:text-yellow-500' : isTokenized ? 'text-blue-700 dark:text-blue-400' : isDenied ? 'text-red-400' : 'text-slate-555 dark:text-slate-400')}>
                  <span className="font-mono">{col}</span>
                  {!isAdmin() && isMasked && <span className="ml-1 text-[9px] font-normal lowercase opacity-75">(masked)</span>}
                  {!isAdmin() && isTokenized && <span className="ml-1 text-[9px] font-normal lowercase opacity-75">(token)</span>}
                  {!isAdmin() && isDenied && <span className="ml-1 text-[9px] font-normal lowercase opacity-75">(denied)</span>}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-150 dark:divide-slate-800/50">
          {rows.map((row, ri) => (
            <tr key={ri} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/10 transition-colors">
              {columns.map((col, ci) => (
                <td key={col} className="px-4 py-3 whitespace-nowrap text-sm">
                  <CellValue value={Array.isArray(row) ? row[ci] : null} col={col} policy={result.policy} auditId={result.audit_id} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── DatabaseBrowser ─────────────────────────────────────────────────���─────────

function DatabaseBrowser({
  sourceId,
  sourceType,
  onSelectTable,
}: {
  sourceId: number;
  sourceType: string;
  onSelectTable: (sql: string) => void;
}) {
  const [schemas, setSchemas] = useState<SchemaItem[]>([]);
  const [loadingSchemas, setLoadingSchemas] = useState(true);
  const [expandedSchema, setExpandedSchema] = useState<number | null>(null);
  const [tables, setTables] = useState<Record<number, BrowseTable[]>>({});
  const [loadingTables, setLoadingTables] = useState<Set<number>>(new Set());
  const [tableSearch, setTableSearch] = useState('');

  useEffect(() => {
    setSchemas([]);
    setExpandedSchema(null);
    setTables({});
    setLoadingSchemas(true);
    api.get(`/catalog/schemas?source_id=${sourceId}`)
      .then(r => setSchemas(r.data ?? []))
      .catch(() => setSchemas([]))
      .finally(() => setLoadingSchemas(false));
  }, [sourceId]);

  const toggleSchema = async (schema: SchemaItem) => {
    if (expandedSchema === schema.id) {
      setExpandedSchema(null);
      return;
    }
    setExpandedSchema(schema.id);
    if (tables[schema.id]) return;

    setLoadingTables(prev => new Set([...prev, schema.id]));
    try {
      const r = await api.get(`/catalog/tables?source_id=${sourceId}&schema_id=${schema.id}&page_size=300`);
      const items: BrowseTable[] = (r.data?.items ?? []).map((t: any) => ({
        id: t.id, name: t.name,
        schema_name: t.schema_name, database_name: t.database_name,
        source_type: t.source_type,
      }));
      setTables(prev => ({ ...prev, [schema.id]: items }));
    } catch {
      setTables(prev => ({ ...prev, [schema.id]: [] }));
    } finally {
      setLoadingTables(prev => { const n = new Set(prev); n.delete(schema.id); return n; });
    }
  };

  const handleTableClick = (tbl: BrowseTable, schema: SchemaItem) => {
    const isOracle = sourceType.toLowerCase().includes('oracle');
    // Use schema-qualified name for Oracle (avoids ORA-00942)
    const qualified = isOracle
      ? `${schema.name}.${tbl.name}`
      : `${schema.name}.${tbl.name}`;
    onSelectTable(`SELECT * FROM ${qualified}`);
  };

  const filteredSchemas = tableSearch
    ? schemas.filter(s => s.name.toLowerCase().includes(tableSearch.toLowerCase()))
    : schemas;

  // Group by database when there are multiple databases
  const dbNames = [...new Set(schemas.map(s => s.database_name))];
  const multiDb = dbNames.length > 1;

  if (loadingSchemas) {
    return (
      <div className="flex items-center gap-2 text-xs text-slate-400 py-3 px-1">
        <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Loading schema tree…
      </div>
    );
  }

  if (schemas.length === 0) {
    return <div className="text-xs text-slate-400 py-3 px-1">No schemas found. Run a scan first.</div>;
  }

  return (
    <div className="space-y-2">
      {/* Schema search */}
      <div className="relative">
        <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
        <input
          type="text"
          placeholder="Filter schemas / tables…"
          value={tableSearch}
          onChange={e => setTableSearch(e.target.value)}
          className="w-full pl-8 pr-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:border-brand-indigo"
        />
      </div>

      {/* Schema tree */}
      <div className="max-h-64 overflow-y-auto space-y-0.5 border border-slate-200 dark:border-slate-800 rounded-lg p-1.5 bg-slate-50 dark:bg-slate-900/50">
        {multiDb && dbNames.map(dbName => (
          <div key={dbName} className="mb-1">
            <div className="flex items-center gap-1.5 px-2 py-1">
              <Database className="h-3 w-3 text-slate-400" />
              <span className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{dbName}</span>
            </div>
            {filteredSchemas.filter(s => s.database_name === dbName).map(schema => (
              <SchemaRow key={schema.id} schema={schema} expanded={expandedSchema === schema.id}
                tables={tables[schema.id]} loading={loadingTables.has(schema.id)}
                onToggle={() => toggleSchema(schema)} onTableClick={t => handleTableClick(t, schema)} tableSearch={tableSearch} />
            ))}
          </div>
        ))}
        {!multiDb && filteredSchemas.map(schema => (
          <SchemaRow key={schema.id} schema={schema} expanded={expandedSchema === schema.id}
            tables={tables[schema.id]} loading={loadingTables.has(schema.id)}
            onToggle={() => toggleSchema(schema)} onTableClick={t => handleTableClick(t, schema)} tableSearch={tableSearch} />
        ))}
      </div>
    </div>
  );
}

function SchemaRow({
  schema, expanded, tables, loading, onToggle, onTableClick, tableSearch,
}: {
  schema: SchemaItem; expanded: boolean; tables?: BrowseTable[];
  loading: boolean; onToggle: () => void;
  onTableClick: (t: BrowseTable) => void; tableSearch: string;
}) {
  const filteredTables = tables
    ? (tableSearch ? tables.filter(t => t.name.toLowerCase().includes(tableSearch.toLowerCase())) : tables)
    : [];

  return (
    <div>
      <button onClick={onToggle}
        className={cn('w-full text-left flex items-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium transition-colors',
          expanded ? 'bg-brand-indigo/10 text-brand-indigo dark:text-indigo-400' : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800')}>
        {expanded ? <ChevronDown className="h-3 w-3 flex-shrink-0" /> : <ChevronRight className="h-3 w-3 flex-shrink-0 text-slate-400" />}
        <Layers className="h-3 w-3 flex-shrink-0 text-slate-400" />
        <span className="truncate flex-1 font-mono">{schema.name}</span>
        <span className="text-[10px] text-slate-400 flex-shrink-0 tabular-nums">{schema.table_count}</span>
        {schema.pii_count > 0 && <span className="text-[10px] font-bold text-red-400 flex-shrink-0">·{schema.pii_count}PII</span>}
      </button>

      {expanded && (
        <div className="ml-4 border-l border-slate-200 dark:border-slate-700 pl-2">
          {loading ? (
            <div className="flex items-center gap-1.5 py-1.5 text-xs text-slate-400">
              <RefreshCw className="h-3 w-3 animate-spin" /> Loading…
            </div>
          ) : filteredTables.length === 0 ? (
            <div className="py-1.5 text-xs text-slate-400">No tables</div>
          ) : (
            filteredTables.map(tbl => (
              <button key={tbl.id} onClick={() => onTableClick(tbl)}
                className="w-full text-left flex items-center gap-1.5 px-2 py-1 rounded text-xs text-slate-700 dark:text-slate-300 hover:bg-brand-indigo hover:text-white group transition-colors">
                <TableIcon className="h-3 w-3 flex-shrink-0 text-slate-400 group-hover:text-white/70" />
                <span className="truncate font-mono">{tbl.name}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Query page ───────────────────────────────────────────────────────────

export function Query() {
  const location = useLocation();
  const [sources, setSources] = useState<DataSource[]>([]);
  const [sourceId, setSourceId] = useState<number | ''>(location.state?.sourceId || '');
  const [sql, setSql] = useState(location.state?.sql || 'SELECT * FROM ');
  const [limit, setLimit] = useState(100);
  const [browserOpen, setBrowserOpen] = useState(false);

  const selectedDataSource = sources.find(s => s.id === sourceId);
  const isNoSql = ['mongodb', 'elasticsearch', 'opensearch', 'dynamodb', 'redis'].includes(
    selectedDataSource?.type?.toLowerCase() ?? ''
  );

  useEffect(() => {
    setSql(current => {
      if (isNoSql) {
        if (current === 'SELECT * FROM ' || current.trim() === '') return '{\n  "collection": "my_table",\n  "filter": {}\n}';
      } else {
        if (current === '{\n  "collection": "my_table",\n  "filter": {}\n}' || current.trim() === '') return 'SELECT * FROM ';
      }
      return current;
    });
  }, [isNoSql]);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    api.get('/sources?limit=200')
      .then(r => {
        const items: DataSource[] = r.data.items ?? [];
        setSources(items.filter(s => s.category === 'database' || s.category === 'storage'));
      })
      .catch(() => setSources([]));
  }, []);

  const handleExecute = async () => {
    if (!sourceId || !sql.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.post('/query/execute', { source_id: sourceId, sql: sql.trim(), limit });
      setResult(res.data as QueryResult);
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      setError(e.response?.data?.detail ?? e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleExecute();
    }
  };

  const handleBrowserTableSelect = (generatedSql: string) => {
    setSql(generatedSql);
    textareaRef.current?.focus();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Terminal className="w-6 h-6 text-brand-indigo" />
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Query Playground</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
            Execute queries safely — PII masked, policies enforced, all actions audited.
          </p>
        </div>
      </div>

      {/* Controls */}
      <div className="premium-card p-6 space-y-5 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
        <div className="flex flex-wrap gap-4">
          {/* Source selector */}
          <div className="flex-1 min-w-[200px]">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">
              Data Source
            </label>
            <select
              value={sourceId}
              onChange={e => {
                setSourceId(e.target.value ? Number(e.target.value) : '');
                setBrowserOpen(false);
              }}
              className="premium-input"
            >
              <option value="">Select a database source…</option>
              {sources.map(s => (
                <option key={s.id} value={s.id}>{s.name} ({s.type})</option>
              ))}
            </select>
          </div>

          {/* Row limit */}
          <div className="w-32">
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">
              Row limit
            </label>
            <input type="number" min={1} max={10000} value={limit}
              onChange={e => setLimit(Math.min(10000, Math.max(1, Number(e.target.value))))}
              className="premium-input" />
          </div>
        </div>

        {/* Database browser (collapsible, shown when source is selected & not NoSQL) */}
        {sourceId && !isNoSql && (
          <div>
            <button
              onClick={() => setBrowserOpen(v => !v)}
              className="flex items-center gap-2 text-xs font-semibold text-slate-600 dark:text-slate-400 hover:text-brand-indigo dark:hover:text-indigo-400 transition-colors"
            >
              <Database className="h-3.5 w-3.5" />
              Browse Tables
              {browserOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              <span className="font-normal text-slate-400">— click a table to auto-fill SELECT</span>
            </button>
            {browserOpen && (
              <div className="mt-3">
                <DatabaseBrowser
                  sourceId={sourceId as number}
                  sourceType={selectedDataSource?.type ?? ''}
                  onSelectTable={handleBrowserTableSelect}
                />
              </div>
            )}
          </div>
        )}

        {/* SQL / NoSQL editor */}
        <div>
          <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5 flex justify-between">
            <span>{isNoSql ? 'NoSQL Query (JSON format)' : 'SQL Query'}</span>
            <span className="text-slate-400 font-normal lowercase tracking-normal font-sans">(Ctrl+Enter to run)</span>
          </label>
          <textarea
            ref={textareaRef}
            value={sql}
            onChange={e => setSql(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={isNoSql ? 12 : 8}
            spellCheck={false}
            className="block w-full border border-slate-250 dark:border-slate-805 rounded-lg px-4 py-3 text-xs font-mono focus:border-brand-indigo focus:ring-2 focus:ring-brand-indigo/15 bg-slate-950 dark:bg-slate-950 text-slate-100 placeholder-slate-650 resize-y"
            placeholder={isNoSql ? '{"collection": "my_collection", "filter": {}}' : 'SELECT * FROM SCHEMA.TABLE_NAME'}
          />
        </div>

        {/* Execute */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleExecute}
            disabled={loading || !sourceId || !sql.trim()}
            className={cn('premium-btn-primary gap-2', (loading || !sourceId || !sql.trim()) && 'opacity-50 cursor-not-allowed bg-brand-indigo/70')}
          >
            <Play className="w-4 h-4" />
            {loading ? 'Executing…' : 'Execute'}
          </button>
          {!sourceId && <span className="text-xs text-slate-400 dark:text-slate-550 font-medium">Select a data source first</span>}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 p-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 rounded-lg animate-scale-up">
          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-bold text-red-800 dark:text-red-400">Query failed</p>
            <p className="text-sm text-red-700 dark:text-red-300 mt-1 whitespace-pre-wrap">{typeof error === 'string' ? error : JSON.stringify(error, null, 2)}</p>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4 animate-slide-up">
          {result.warnings && result.warnings.length > 0 && (
            <div className="flex items-start gap-3 p-3 bg-yellow-50 dark:bg-yellow-950/25 border border-yellow-200 dark:border-yellow-900/55 rounded-lg">
              <AlertTriangle className="w-4 h-4 text-yellow-600 flex-shrink-0 mt-0.5" />
              <div className="space-y-1">
                {result.warnings.map((w, i) => (
                  <p key={i} className="text-xs font-semibold text-yellow-805 dark:text-yellow-400">{w}</p>
                ))}
              </div>
            </div>
          )}

          {result.policy && <PolicyBar policy={result.policy} />}

          {result.rewritten_sql && <RewrittenSQL original={sql} rewritten={result.rewritten_sql} />}

          <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
            <ResultGrid result={result} />
            <div className="px-4 py-3 bg-slate-50 dark:bg-slate-900/50 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center gap-4 text-xs text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <Hash className="w-3.5 h-3.5 text-slate-400" />
                {result.row_count} row{result.row_count !== 1 ? 's' : ''}
              </span>
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                {result.execution_time_ms?.toFixed(1)} ms
              </span>
              {result.masking_level && (
                <span className="bg-slate-100 dark:bg-slate-850 px-2 py-0.5 rounded text-[10px]">
                  Masking: {result.masking_level}
                </span>
              )}
              {result.audit_id !== null && result.audit_id !== undefined && (
                <span className="bg-slate-100 dark:bg-slate-850 px-2 py-0.5 rounded text-[10px]">Audit ID: {result.audit_id}</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
