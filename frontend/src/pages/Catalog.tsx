import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Table as TableIcon, Search, Tag, ChevronDown, ChevronUp,
  RefreshCw, ChevronLeft, ChevronRight, Filter,
  Database, Layers, PanelLeftClose, PanelLeftOpen,
} from 'lucide-react';
import { api, isAdmin } from '../api';
import { cn } from '../lib/utils';

// ── Constants ──────────────────────────────────────────────────────────────────

const PII_TYPES = ['EMAIL', 'SSN', 'PHONE', 'CREDIT_CARD', 'NAME', 'ADDRESS', 'IP_ADDRESS'];
const CLASSIFICATIONS = ['PUBLIC', 'PII', 'FINANCIAL'];
const ACTIONS = ['allow', 'mask', 'tokenize', 'deny'];
const PAGE_SIZE = 50;

const CLASSIFICATION_COLORS: Record<string, string> = {
  PUBLIC: 'bg-green-100 dark:bg-green-950/40 text-green-800 dark:text-green-400 border border-green-200 dark:border-green-900/40',
  PII: 'bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-400 border border-red-200 dark:border-red-900/40',
  FINANCIAL: 'bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-200 dark:border-amber-900/40',
};

const ACTION_COLORS: Record<string, string> = {
  allow: 'bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-900/30',
  mask: 'bg-yellow-50 dark:bg-yellow-950/20 text-yellow-750 dark:text-yellow-400 border border-yellow-250 dark:border-yellow-900/30',
  tokenize: 'bg-blue-50 dark:bg-blue-950/20 text-blue-700 dark:text-blue-400 border border-blue-200 dark:border-blue-900/30',
  deny: 'bg-red-50 dark:bg-red-950/20 text-red-750 dark:text-red-400 border border-red-200 dark:border-red-900/30',
};

const PII_COLORS: Record<string, string> = {
  EMAIL: 'bg-purple-100 dark:bg-purple-950/40 text-purple-800 dark:text-purple-400 border border-purple-200 dark:border-purple-900/40',
  SSN: 'bg-red-100 dark:bg-red-950/40 text-red-850 dark:text-red-400 border border-red-200 dark:border-red-900/40',
  PHONE: 'bg-blue-100 dark:bg-blue-950/40 text-blue-800 dark:text-blue-400 border border-blue-200 dark:border-blue-900/40',
  CREDIT_CARD: 'bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-200 dark:border-amber-900/40',
  NAME: 'bg-yellow-100 dark:bg-yellow-950/40 text-yellow-800 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-900/40',
  ADDRESS: 'bg-teal-100 dark:bg-teal-950/40 text-teal-850 dark:text-teal-400 border border-teal-200 dark:border-teal-900/40',
  IP_ADDRESS: 'bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-slate-700',
};

// ── Types ──────────────────────────────────────────────────────────────────────

type Column = {
  id: number; name: string; type: string;
  pii_type: string | null; suggested_pii_type: string | null;
  classification: string | null; action: string | null; table_id: number;
};

type CatalogTableListItem = {
  id: number; name: string; schema_id: number;
  schema_name: string; database_name: string;
  source_name: string; source_type: string;
  tenant_id: number; department_id: number | null; department_name: string | null;
  allowed_roles: string[]; column_count: number; pii_column_count: number;
};

type CatalogPage = {
  items: CatalogTableListItem[]; total: number;
  page: number; page_size: number; pages: number;
};

type SourceItem = { id: number; name: string; type: string; category: string; };

type SchemaItem = {
  id: number; name: string;
  database_id: number; database_name: string;
  source_id: number; source_name: string; source_type: string;
  table_count: number; pii_count: number;
};

// ── Column classify form ───────────────────────────────────────────────────────

function ColumnClassifyForm({ col, onSave, onCancel }: {
  col: Column;
  onSave: (id: number, data: Record<string, unknown>) => Promise<void>;
  onCancel: () => void;
}) {
  const [piiType, setPiiType] = useState(col.pii_type ?? '');
  const [classification, setClassification] = useState(col.classification ?? 'PUBLIC');
  const [action, setAction] = useState(col.action ?? 'allow');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave(col.id, { pii_type: piiType || null, classification: classification || null, action: action || null });
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex items-center gap-2 flex-wrap bg-slate-50 dark:bg-slate-800 p-2.5 rounded-lg border border-slate-200 dark:border-slate-700 max-w-xl animate-scale-up">
      <select value={piiType} onChange={(e) => setPiiType(e.target.value)}
        className="text-xs bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-250 rounded-lg px-2.5 py-1.5 outline-none focus:border-brand-indigo transition-all">
        <option value="">No PII</option>
        {PII_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>
      <select value={classification} onChange={(e) => setClassification(e.target.value)}
        className="text-xs bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-250 rounded-lg px-2.5 py-1.5 outline-none focus:border-brand-indigo transition-all">
        {CLASSIFICATIONS.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
      <select value={action} onChange={(e) => setAction(e.target.value)}
        className="text-xs bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-250 rounded-lg px-2.5 py-1.5 outline-none focus:border-brand-indigo transition-all">
        {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
      </select>
      <button type="submit" disabled={saving} className="premium-btn-primary px-3 py-1.5 text-xs font-semibold">
        {saving ? 'Saving...' : 'Save'}
      </button>
      <button type="button" onClick={onCancel} className="premium-btn-secondary px-3 py-1.5 text-xs font-semibold">
        Cancel
      </button>
    </form>
  );
}

// ── Column panel ───────────────────────────────────────────────────────────────

function TableColumnPanel({ tableId, admin }: { tableId: number; admin: boolean }) {
  const [columns, setColumns] = useState<Column[]>([]);
  const [loading, setLoading] = useState(true);
  const [classifyingCol, setClassifyingCol] = useState<number | null>(null);

  useEffect(() => {
    api.get(`/catalog/tables/${tableId}`)
      .then(res => setColumns(res.data.columns || []))
      .catch(() => setColumns([]))
      .finally(() => setLoading(false));
  }, [tableId]);

  const handleClassify = async (colId: number, data: Record<string, unknown>) => {
    await api.patch(`/catalog/columns/${colId}`, data);
    setClassifyingCol(null);
    const res = await api.get(`/catalog/tables/${tableId}`);
    setColumns(res.data.columns || []);
  };

  if (loading) {
    return (
      <div className="mt-4 border-t border-slate-200 dark:border-slate-800 pt-4 flex items-center gap-2 text-slate-400 text-sm">
        <RefreshCw className="h-4 w-4 animate-spin" /> Loading columns…
      </div>
    );
  }

  return (
    <div className="mt-4 border-t border-slate-200 dark:border-slate-800 pt-4 overflow-x-auto animate-slide-up">
      <table className="min-w-full text-sm">
        <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
          <tr className="text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
            <th className="text-left px-4 py-2.5">Column</th>
            <th className="text-left px-4 py-2.5">Type</th>
            {admin && (
              <>
                <th className="text-left px-4 py-2.5">PII Tag</th>
                <th className="text-left px-4 py-2.5">Classification</th>
                <th className="text-left px-4 py-2.5">Action</th>
                <th className="px-4 py-2.5" />
              </>
            )}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-150 dark:divide-slate-800/50">
          {columns.map((col) => (
            <tr key={col.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/10 transition-colors">
              <td className="px-4 py-3 font-mono text-slate-800 dark:text-slate-200 text-xs font-semibold">{col.name}</td>
              <td className="px-4 py-3 text-slate-500 dark:text-slate-400 text-xs font-mono">{col.type}</td>
              {admin && (
                <>
                  <td className="px-4 py-3">
                    {col.pii_type ? (
                      <span className={cn('inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider', PII_COLORS[col.pii_type] ?? 'bg-slate-100 text-slate-700')}>{col.pii_type}</span>
                    ) : col.suggested_pii_type ? (
                      <span className="inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-dashed border-slate-300 dark:border-slate-600">{col.suggested_pii_type}?</span>
                    ) : <span className="text-slate-300 dark:text-slate-700 text-xs">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    {col.classification ? (
                      <span className={cn('inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider', CLASSIFICATION_COLORS[col.classification] ?? 'bg-slate-100 text-slate-700')}>{col.classification}</span>
                    ) : <span className="text-slate-300 dark:text-slate-700 text-xs">—</span>}
                  </td>
                  <td className="px-4 py-3">
                    {col.action ? (
                      <span className={cn('inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider', ACTION_COLORS[col.action] ?? 'bg-slate-100 text-slate-700')}>{col.action}</span>
                    ) : <span className="text-slate-300 dark:text-slate-700 text-xs">—</span>}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {classifyingCol === col.id ? (
                      <ColumnClassifyForm col={col} onSave={handleClassify} onCancel={() => setClassifyingCol(null)} />
                    ) : (
                      <button onClick={() => setClassifyingCol(col.id)} className="text-xs font-bold text-brand-indigo hover:text-brand-indigo/80">
                        Classify
                      </button>
                    )}
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Source / Schema tree panel ─────────────────────────────────────────────────

function SourceTreePanel({
  selectedSourceId,
  selectedSchemaId,
  onSelect,
  onClear,
}: {
  selectedSourceId: number | null;
  selectedSchemaId: number | null;
  onSelect: (sourceId: number, schemaId: number | null, schemaName?: string) => void;
  onClear: () => void;
}) {
  const [sources, setSources] = useState<SourceItem[]>([]);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [schemasMap, setSchemasMap] = useState<Record<number, SchemaItem[]>>({});
  const [loadingSet, setLoadingSet] = useState<Set<number>>(new Set());
  const [treeSearch, setTreeSearch] = useState('');

  useEffect(() => {
    api.get('/sources?limit=200')
      .then(r => {
        const items: SourceItem[] = (r.data.items ?? []).filter(
          (s: SourceItem) => s.category === 'database'
        );
        setSources(items);
      })
      .catch(() => {});
  }, []);

  const loadSchemas = async (sourceId: number) => {
    if (schemasMap[sourceId]) return;
    setLoadingSet(prev => new Set([...prev, sourceId]));
    try {
      const r = await api.get(`/catalog/schemas?source_id=${sourceId}`);
      setSchemasMap(prev => ({ ...prev, [sourceId]: r.data }));
    } catch {
      setSchemasMap(prev => ({ ...prev, [sourceId]: [] }));
    } finally {
      setLoadingSet(prev => { const n = new Set(prev); n.delete(sourceId); return n; });
    }
  };

  const toggleSource = (sourceId: number) => {
    if (expanded.has(sourceId)) {
      setExpanded(prev => { const n = new Set(prev); n.delete(sourceId); return n; });
    } else {
      setExpanded(prev => new Set([...prev, sourceId]));
      loadSchemas(sourceId);
    }
  };

  // Group schemas by database name
  const groupByDb = (schemas: SchemaItem[]): Record<string, SchemaItem[]> => {
    const map: Record<string, SchemaItem[]> = {};
    for (const s of schemas) {
      const key = s.database_name || '(default)';
      if (!map[key]) map[key] = [];
      map[key].push(s);
    }
    return map;
  };

  const filterSchemas = (schemas: SchemaItem[]) => {
    if (!treeSearch) return schemas;
    return schemas.filter(s => s.name.toLowerCase().includes(treeSearch.toLowerCase()));
  };

  return (
    <div className="flex flex-col h-full">
      {/* Tree search */}
      <div className="px-3 pb-2 pt-1 border-b border-slate-200 dark:border-slate-800">
        <div className="relative">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text"
            placeholder="Filter schemas…"
            value={treeSearch}
            onChange={e => setTreeSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:border-brand-indigo"
          />
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
        {/* All Tables */}
        <button
          onClick={onClear}
          className={cn(
            'w-full text-left flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors',
            !selectedSourceId
              ? 'bg-brand-indigo text-white'
              : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800',
          )}
        >
          <TableIcon className="h-3.5 w-3.5 flex-shrink-0" />
          All Tables
        </button>

        {sources.map(source => {
          const isExp = expanded.has(source.id);
          const schemas = schemasMap[source.id] ?? [];
          const filtered = filterSchemas(schemas);
          const dbGroups = groupByDb(filtered);
          const multiDb = Object.keys(groupByDb(schemas)).length > 1;
          const isSourceSelected = selectedSourceId === source.id;

          return (
            <div key={source.id}>
              {/* Source row */}
              <button
                onClick={() => toggleSource(source.id)}
                className={cn(
                  'w-full text-left flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors',
                  isSourceSelected && !selectedSchemaId
                    ? 'bg-brand-indigo/10 text-brand-indigo dark:text-indigo-400'
                    : 'text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800',
                )}
              >
                {isExp
                  ? <ChevronDown className="h-3.5 w-3.5 flex-shrink-0 text-slate-400" />
                  : <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-slate-400" />}
                <Database className="h-3.5 w-3.5 flex-shrink-0 text-slate-400" />
                <span className="truncate flex-1">{source.name}</span>
                <span className="text-[10px] font-normal text-slate-400 uppercase tracking-wider flex-shrink-0">{source.type}</span>
              </button>

              {/* Expanded schemas */}
              {isExp && (
                <div className="ml-4 border-l border-slate-200 dark:border-slate-700 pl-2 mt-0.5 pb-1">
                  {loadingSet.has(source.id) ? (
                    <div className="py-2 text-xs text-slate-400 flex items-center gap-1.5 px-2">
                      <RefreshCw className="h-3 w-3 animate-spin" /> Loading schemas…
                    </div>
                  ) : filtered.length === 0 ? (
                    <div className="py-2 text-xs text-slate-400 px-2">No schemas found</div>
                  ) : (
                    Object.entries(dbGroups).map(([dbName, dbSchemas]) => (
                      <div key={dbName}>
                        {/* Database sub-group header (only if multiple DBs) */}
                        {multiDb && (
                          <div className="flex items-center gap-1.5 px-2 py-1.5 mt-1">
                            <Database className="h-3 w-3 text-slate-400 flex-shrink-0" />
                            <span className="text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider truncate">{dbName}</span>
                          </div>
                        )}
                        {dbSchemas.map(schema => (
                          <button
                            key={schema.id}
                            onClick={() => onSelect(source.id, schema.id, schema.name)}
                            className={cn(
                              'w-full text-left flex items-center gap-2 px-2 py-1.5 rounded text-xs font-medium transition-colors group',
                              selectedSchemaId === schema.id
                                ? 'bg-brand-indigo text-white'
                                : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800',
                            )}
                          >
                            <Layers className={cn('h-3 w-3 flex-shrink-0', selectedSchemaId === schema.id ? 'text-white/70' : 'text-slate-400')} />
                            <span className="truncate flex-1 font-mono">{schema.name}</span>
                            <span className={cn('text-[10px] font-semibold flex-shrink-0 tabular-nums', selectedSchemaId === schema.id ? 'text-white/70' : 'text-slate-400')}>
                              {schema.table_count}
                            </span>
                            {schema.pii_count > 0 && (
                              <span className={cn('text-[10px] font-bold flex-shrink-0', selectedSchemaId === schema.id ? 'text-red-300' : 'text-red-500 dark:text-red-400')}>
                                ·{schema.pii_count}PII
                              </span>
                            )}
                          </button>
                        ))}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main Catalog page ──────────────────────────────────────────────────────────

export function Catalog() {
  const admin = isAdmin();
  const [page, setPage] = useState(1);
  const [catalogPage, setCatalogPage] = useState<CatalogPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expandedTable, setExpandedTable] = useState<number | null>(null);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [piiOnly, setPiiOnly] = useState(false);
  const [treeOpen, setTreeOpen] = useState(true);

  // Tree selection state
  const [selectedSourceId, setSelectedSourceId] = useState<number | null>(null);
  const [selectedSchemaId, setSelectedSchemaId] = useState<number | null>(null);
  const [selectedSchemaName, setSelectedSchemaName] = useState<string | null>(null);

  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleSearchChange = (value: string) => {
    setSearch(value);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setDebouncedSearch(value);
      setPage(1);
    }, 350);
  };

  const handleTreeSelect = (sourceId: number, schemaId: number | null, schemaName?: string) => {
    setSelectedSourceId(sourceId);
    setSelectedSchemaId(schemaId);
    setSelectedSchemaName(schemaName ?? null);
    setPage(1);
    setExpandedTable(null);
  };

  const handleTreeClear = () => {
    setSelectedSourceId(null);
    setSelectedSchemaId(null);
    setSelectedSchemaName(null);
    setPage(1);
    setExpandedTable(null);
  };

  const fetchPage = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams({ page: String(page), page_size: String(PAGE_SIZE) });
      if (debouncedSearch) params.set('search', debouncedSearch);
      if (piiOnly) params.set('pii_only', 'true');
      if (selectedSourceId) params.set('source_id', String(selectedSourceId));
      if (selectedSchemaId) params.set('schema_id', String(selectedSchemaId));
      const res = await api.get(`/catalog/tables?${params}`);
      setCatalogPage(res.data);
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } } };
      setError(e.response?.data?.detail || 'Failed to load catalog');
    } finally {
      setLoading(false);
    }
  }, [page, debouncedSearch, piiOnly, selectedSourceId, selectedSchemaId]);

  useEffect(() => { fetchPage(); }, [fetchPage]);
  useEffect(() => { setExpandedTable(null); }, [page]);

  const tables = catalogPage?.items ?? [];
  const total = catalogPage?.total ?? 0;
  const pages = catalogPage?.pages ?? 1;

  // Breadcrumb label for active filter
  const breadcrumb = selectedSchemaId
    ? `${tables[0]?.source_name ?? ''} / ${tables[0]?.database_name ?? ''} / ${selectedSchemaName}`
    : selectedSourceId
    ? (tables[0]?.source_name ?? 'Selected Source')
    : null;

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Data Catalog</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Browse your data sources, classify PII, and manage security policies.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="text-xs font-semibold px-2.5 py-1.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 uppercase tracking-wider">
            {total.toLocaleString()} tables
          </div>
          <button
            onClick={() => setTreeOpen(v => !v)}
            className="premium-btn-secondary px-2.5 py-1.5 text-xs gap-1.5"
            title={treeOpen ? 'Hide tree' : 'Show tree'}
          >
            {treeOpen ? <PanelLeftClose className="h-3.5 w-3.5" /> : <PanelLeftOpen className="h-3.5 w-3.5" />}
          </button>
          <button onClick={() => fetchPage()} disabled={loading} className="premium-btn-secondary px-2.5 py-1.5 text-xs gap-1.5" title="Refresh">
            <RefreshCw className={cn('h-3.5 w-3.5', loading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-650 dark:text-red-400 px-4 py-3 rounded-lg text-sm">{error}</div>
      )}

      {/* ── Main layout: tree + table list ───────────────────────────────── */}
      <div className="flex gap-4 min-h-0">

        {/* Left: Source / Schema tree */}
        {treeOpen && (
          <div className="w-64 flex-shrink-0 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden flex flex-col" style={{ maxHeight: 'calc(100vh - 200px)' }}>
            <div className="px-3 py-2.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wider">Browse</span>
              {(selectedSourceId || selectedSchemaId) && (
                <button onClick={handleTreeClear} className="text-[10px] text-brand-indigo hover:underline font-semibold">
                  Clear
                </button>
              )}
            </div>
            <SourceTreePanel
              selectedSourceId={selectedSourceId}
              selectedSchemaId={selectedSchemaId}
              onSelect={handleTreeSelect}
              onClear={handleTreeClear}
            />
          </div>
        )}

        {/* Right: table list */}
        <div className="flex-1 min-w-0 space-y-4">
          {/* Active filter breadcrumb */}
          {breadcrumb && (
            <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-medium">
              <Layers className="h-3.5 w-3.5 text-brand-indigo" />
              <span className="font-mono">{breadcrumb}</span>
              <button onClick={handleTreeClear} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
                ✕
              </button>
            </div>
          )}

          {/* Search & filter bar */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative max-w-xs flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
              <input
                type="text"
                placeholder="Search tables…"
                value={search}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="premium-input pl-9"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={piiOnly}
                onChange={(e) => { setPiiOnly(e.target.checked); setPage(1); }}
                className="rounded border-slate-300 dark:border-slate-600 text-brand-indigo"
              />
              <Filter className="h-3.5 w-3.5" />
              PII only
            </label>
          </div>

          {/* Table list */}
          {loading ? (
            <div className="p-8 text-center text-slate-500 dark:text-slate-400">
              <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
              <p className="text-sm">Loading catalog…</p>
            </div>
          ) : tables.length === 0 ? (
            <div className="p-12 text-center text-slate-405 dark:text-slate-500 border border-dashed border-slate-250 dark:border-slate-800 rounded-xl bg-white dark:bg-slate-900/40">
              <TableIcon className="h-12 w-12 mx-auto mb-3 opacity-30 animate-pulse" />
              <p className="font-semibold text-slate-800 dark:text-slate-200">No tables found.</p>
              <p className="text-xs mt-1 text-slate-550 dark:text-slate-400">
                {selectedSchemaId ? 'This schema has no tables, or try a different filter.' : 'Select a schema from the tree, or adjust your search.'}
              </p>
            </div>
          ) : (
            <div className="space-y-3.5">
              {tables.map((table) => (
                <div key={table.id} className="premium-card p-4">
                  <div className="flex items-center justify-between flex-wrap gap-4">
                    <div className="flex items-center gap-3">
                      <TableIcon className="h-5 w-5 text-slate-400 dark:text-slate-500 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className="font-bold text-slate-900 dark:text-slate-100 font-mono text-sm">{table.name}</span>
                          <span className="inline-flex px-2 py-0.5 rounded border border-slate-200 dark:border-slate-805 bg-slate-50 dark:bg-slate-800/60 text-[10px] font-bold text-slate-500 dark:text-slate-450 uppercase tracking-wider">
                            {table.source_name} / {table.database_name} / {table.schema_name}
                          </span>
                          {admin && table.pii_column_count > 0 && (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-400 border border-red-200 dark:border-red-900/40 uppercase tracking-wider">
                              <Tag className="h-3 w-3" /> {table.pii_column_count} PII
                            </span>
                          )}
                          <span className="text-xs text-slate-400 dark:text-slate-500 font-medium">{table.column_count} cols</span>
                          {table.department_name && (
                            <span className="text-xs text-slate-400 dark:text-slate-500">{table.department_name}</span>
                          )}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => setExpandedTable(expandedTable === table.id ? null : table.id)}
                      className="premium-btn-secondary px-3 py-1.5 text-xs gap-1.5"
                    >
                      {expandedTable === table.id
                        ? <><ChevronUp className="h-3.5 w-3.5" /> Hide Columns</>
                        : <><ChevronDown className="h-3.5 w-3.5" /> Show Columns</>}
                    </button>
                  </div>

                  {expandedTable === table.id && (
                    <TableColumnPanel tableId={table.id} admin={admin} />
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Pagination */}
          {!loading && total > PAGE_SIZE && (
            <div className="flex items-center justify-between pt-2">
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, total)} of {total.toLocaleString()} tables
              </p>
              <div className="flex items-center gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  className="premium-btn-secondary px-2 py-1.5 text-xs disabled:opacity-40">
                  <ChevronLeft className="h-4 w-4" />
                </button>
                {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
                  const p = pages <= 7 ? i + 1 : page <= 4 ? i + 1 : page >= pages - 3 ? pages - 6 + i : page - 3 + i;
                  return (
                    <button key={p} onClick={() => setPage(p)}
                      className={cn('px-2.5 py-1 text-xs rounded-lg font-medium transition-colors',
                        p === page ? 'bg-brand-indigo text-white' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800')}>
                      {p}
                    </button>
                  );
                })}
                <button onClick={() => setPage(p => Math.min(pages, p + 1))} disabled={page === pages}
                  className="premium-btn-secondary px-2 py-1.5 text-xs disabled:opacity-40">
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
