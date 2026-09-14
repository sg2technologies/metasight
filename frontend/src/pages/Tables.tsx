import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Database, Layers, Table as TableIcon, Search, RefreshCw,
  ChevronRight, ChevronDown, Shield, ChevronLeft,
  AlertTriangle, ArrowUp, ArrowDown, ArrowUpDown,
  Columns, Hash, Clock, Eye, EyeOff, PanelLeftClose, PanelLeftOpen,
  Info,
} from 'lucide-react';
import { api, isAdmin } from '../api';
import { cn } from '../lib/utils';

// ── Types ─────────────────────────────────────────────────────────────────────

type Source = { id: number; name: string; type: string };
type SchemaItem = {
  id: number; name: string; table_count: number; pii_count: number;
  database_id: number; database_name: string; source_id: number;
};
type TableItem = {
  id: number; name: string; schema_name: string; database_name: string;
  source_id: number; source_name: string; source_type: string;
  column_count: number; pii_column_count: number; row_count: number | null;
  schema_id: number;
};
type ColumnInfo = {
  id: number; name: string; type: string;
  pii_type: string | null; suggested_pii_type: string | null; classification: string | null;
};
type PolicySummary = {
  masked_columns: string[]; tokenized_columns: string[];
  denied_columns: string[]; row_filter_applied: boolean;
  classification: string | null; is_admin_exempt: boolean;
};
type QueryResult = {
  columns: string[]; rows: unknown[][]; row_count: number;
  execution_time_ms: number; policy: PolicySummary; warnings: string[];
};

// ── Helpers ───────────────────────────────────────────────────────────────────

const PAGE_SIZES = [50, 100, 200, 500];

function buildSQL(
  table: TableItem,
  page: number,
  pageSize: number,
  sortCol?: string,
  sortDir?: 'asc' | 'desc',
): string {
  const isOracle = table.source_type.toLowerCase().includes('oracle');
  const isMSSQL = /mssql|sqlserver|azuresql/.test(table.source_type.toLowerCase());
  const fq = table.schema_name ? `${table.schema_name}.${table.name}` : table.name;
  const offset = (page - 1) * pageSize;
  const dir = sortDir === 'desc' ? 'DESC' : 'ASC';
  const order = sortCol ? ` ORDER BY ${sortCol} ${dir}` : '';

  if (isOracle) {
    if (offset === 0) return `SELECT * FROM ${fq}${order} FETCH FIRST ${pageSize} ROWS ONLY`;
    return `SELECT * FROM ${fq}${order} OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`;
  }
  if (isMSSQL) {
    const safeOrder = order || ' ORDER BY (SELECT NULL)';
    return `SELECT * FROM ${fq}${safeOrder} OFFSET ${offset} ROWS FETCH NEXT ${pageSize} ROWS ONLY`;
  }
  return `SELECT * FROM ${fq}${order} LIMIT ${pageSize} OFFSET ${offset}`;
}

function useDebounce<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

// ── PII badge ─────────────────────────────────────────────────────────────────

const PII_COLORS: Record<string, string> = {
  PII:  'bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 border-red-200 dark:border-red-900/40',
  PHI:  'bg-orange-100 dark:bg-orange-950/40 text-orange-700 dark:text-orange-400 border-orange-200 dark:border-orange-900/40',
  PSI:  'bg-yellow-100 dark:bg-yellow-950/40 text-yellow-700 dark:text-yellow-400 border-yellow-200 dark:border-yellow-900/40',
};

function PiiBadge({ type }: { type: string }) {
  return (
    <span className={cn('px-1 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wider', PII_COLORS[type] ?? 'bg-slate-100 text-slate-600 border-slate-200')}>
      {type}
    </span>
  );
}

// ── Source/Schema/Table tree ──────────────────────────────────────────────────

function TreePanel({
  selectedTable,
  onSelectTable,
}: {
  selectedTable: TableItem | null;
  onSelectTable: (t: TableItem) => void;
}) {
  const [sources, setSources] = useState<Source[]>([]);
  const [openSources, setOpenSources] = useState<Set<number>>(new Set());
  const [schemas, setSchemas] = useState<Record<number, SchemaItem[]>>({});
  const [openSchemas, setOpenSchemas] = useState<Set<number>>(new Set());
  const [tables, setTables] = useState<Record<number, { items: TableItem[]; total: number; page: number }>>({});
  const [schemaSearch, setSchemaSearch] = useState<Record<number, string>>({});
  const [globalSearch, setGlobalSearch] = useState('');
  const [loadingSource, setLoadingSource] = useState<Set<number>>(new Set());
  const [loadingSchema, setLoadingSchema] = useState<Set<number>>(new Set());

  const debouncedGlobal = useDebounce(globalSearch, 300);
  const debouncedSchemaSearch = Object.fromEntries(
    Object.entries(schemaSearch).map(([k, v]) => [k, v])
  );

  useEffect(() => {
    api.get('/sources?limit=200').then(r => {
      const all: Source[] = r.data?.items ?? [];
      setSources(all.filter(s => !['s3_storage', 's3_datalake', 'mongodb', 'elasticsearch', 'opensearch', 'dynamodb', 'redis'].includes(s.type)));
    }).catch(() => setSources([]));
  }, []);

  const toggleSource = async (src: Source) => {
    const next = new Set(openSources);
    if (next.has(src.id)) { next.delete(src.id); setOpenSources(next); return; }
    next.add(src.id); setOpenSources(next);
    if (schemas[src.id]) return;
    setLoadingSource(prev => new Set([...prev, src.id]));
    try {
      const r = await api.get(`/catalog/schemas?source_id=${src.id}`);
      setSchemas(prev => ({ ...prev, [src.id]: r.data ?? [] }));
    } finally {
      setLoadingSource(prev => { const n = new Set(prev); n.delete(src.id); return n; });
    }
  };

  const loadTables = async (schema: SchemaItem, page = 1, search = '') => {
    setLoadingSchema(prev => new Set([...prev, schema.id]));
    try {
      const params = new URLSearchParams({
        source_id: String(schema.source_id),
        schema_id: String(schema.id),
        page: String(page),
        page_size: '100',
      });
      if (search) params.set('search', search);
      const r = await api.get(`/catalog/tables?${params}`);
      const data = r.data as { items: TableItem[]; total: number };
      setTables(prev => ({
        ...prev,
        [schema.id]: page === 1
          ? { items: data.items, total: data.total, page: 1 }
          : { items: [...(prev[schema.id]?.items ?? []), ...data.items], total: data.total, page },
      }));
    } finally {
      setLoadingSchema(prev => { const n = new Set(prev); n.delete(schema.id); return n; });
    }
  };

  const toggleSchema = (schema: SchemaItem) => {
    const next = new Set(openSchemas);
    if (next.has(schema.id)) { next.delete(schema.id); setOpenSchemas(next); return; }
    next.add(schema.id); setOpenSchemas(next);
    if (!tables[schema.id]) loadTables(schema);
  };

  // Reload tables when schema search changes
  const handleSchemaSearch = (schemaId: number, schema: SchemaItem, value: string) => {
    setSchemaSearch(prev => ({ ...prev, [schemaId]: value }));
  };

  // Debounced schema search effect
  useEffect(() => {
    openSchemas.forEach(schemaId => {
      const search = schemaSearch[schemaId] ?? '';
      // Only reload when we have a search term (empty = initial load)
      if (search !== undefined) {
        const schema = Object.values(schemas).flat().find(s => s.id === schemaId);
        if (schema) loadTables(schema, 1, search);
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(schemaSearch)]);

  const filteredSources = debouncedGlobal
    ? sources.filter(s => s.name.toLowerCase().includes(debouncedGlobal.toLowerCase()))
    : sources;

  return (
    <div className="flex flex-col h-full">
      {/* Global search */}
      <div className="p-3 border-b border-slate-200 dark:border-slate-800">
        <div className="relative">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
          <input
            type="text" placeholder="Search sources…"
            value={globalSearch} onChange={e => setGlobalSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg outline-none focus:border-brand-indigo"
          />
        </div>
      </div>

      {/* Tree */}
      <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
        {filteredSources.length === 0 && (
          <div className="text-xs text-slate-400 text-center py-6">No sources yet. Add a connector.</div>
        )}
        {filteredSources.map(src => (
          <div key={src.id}>
            {/* Source row */}
            <button onClick={() => toggleSource(src)}
              className="w-full text-left flex items-center gap-2 px-2 py-2 rounded-lg text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
              {openSources.has(src.id)
                ? <ChevronDown className="h-3.5 w-3.5 flex-shrink-0 text-brand-indigo" />
                : <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-slate-400" />}
              <Database className="h-3.5 w-3.5 flex-shrink-0 text-brand-indigo" />
              <span className="truncate flex-1">{src.name}</span>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400 uppercase font-bold tracking-wider flex-shrink-0">
                {src.type.replace('oracledb', 'oracle')}
              </span>
            </button>

            {openSources.has(src.id) && (
              <div className="ml-4 border-l border-slate-200 dark:border-slate-700 pl-1.5 mt-0.5">
                {loadingSource.has(src.id) ? (
                  <div className="flex items-center gap-2 py-2 text-xs text-slate-400">
                    <RefreshCw className="h-3 w-3 animate-spin" /> Loading…
                  </div>
                ) : (schemas[src.id] ?? []).length === 0 ? (
                  <div className="text-xs text-slate-400 py-2 px-2">No schemas. Run a scan first.</div>
                ) : (
                  (schemas[src.id] ?? []).map(schema => (
                    <SchemaNode
                      key={schema.id}
                      schema={schema}
                      open={openSchemas.has(schema.id)}
                      tables={tables[schema.id]}
                      loading={loadingSchema.has(schema.id)}
                      search={schemaSearch[schema.id] ?? ''}
                      selectedTable={selectedTable}
                      onToggle={() => toggleSchema(schema)}
                      onSearchChange={v => handleSchemaSearch(schema.id, schema, v)}
                      onLoadMore={() => {
                        const cur = tables[schema.id];
                        if (cur) loadTables(schema, cur.page + 1, schemaSearch[schema.id] ?? '');
                      }}
                      onSelectTable={onSelectTable}
                    />
                  ))
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function SchemaNode({
  schema, open, tables, loading, search, selectedTable,
  onToggle, onSearchChange, onLoadMore, onSelectTable,
}: {
  schema: SchemaItem; open: boolean;
  tables?: { items: TableItem[]; total: number; page: number };
  loading: boolean; search: string; selectedTable: TableItem | null;
  onToggle: () => void; onSearchChange: (v: string) => void;
  onLoadMore: () => void; onSelectTable: (t: TableItem) => void;
}) {
  const debouncedSearch = useDebounce(search, 300);
  const searchRef = useRef<HTMLInputElement>(null);

  // Propagate debounced search up
  const prevSearch = useRef(debouncedSearch);
  useEffect(() => {
    if (prevSearch.current !== debouncedSearch) {
      prevSearch.current = debouncedSearch;
      onSearchChange(debouncedSearch);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch]);

  const items = tables?.items ?? [];
  const total = tables?.total ?? 0;
  const hasMore = items.length < total;

  return (
    <div className="mb-0.5">
      <button onClick={onToggle}
        className={cn('w-full text-left flex items-center gap-1.5 px-2 py-1.5 rounded text-xs font-medium transition-colors',
          open ? 'text-brand-indigo dark:text-indigo-400' : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800')}>
        {open ? <ChevronDown className="h-3 w-3 flex-shrink-0" /> : <ChevronRight className="h-3 w-3 flex-shrink-0 text-slate-400" />}
        <Layers className="h-3 w-3 flex-shrink-0 text-slate-400" />
        <span className="truncate flex-1 font-mono text-[11px]">{schema.name}</span>
        <span className="text-[10px] text-slate-400 tabular-nums flex-shrink-0">{schema.table_count}</span>
        {schema.pii_count > 0 && (
          <span className="text-[9px] font-bold text-red-400 flex-shrink-0">·PII</span>
        )}
      </button>

      {open && (
        <div className="ml-3 border-l border-slate-200 dark:border-slate-700 pl-2 pb-1">
          {/* Schema-level table search */}
          {(total > 20 || search) && (
            <div className="relative my-1">
              <Search className="absolute left-2 top-1.5 h-3 w-3 text-slate-400" />
              <input
                ref={searchRef}
                type="text"
                placeholder="Find table…"
                defaultValue={search}
                onChange={e => onSearchChange(e.target.value)}
                className="w-full pl-6 pr-2 py-1 text-[11px] bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded outline-none focus:border-brand-indigo"
              />
            </div>
          )}

          {loading && items.length === 0 ? (
            <div className="flex items-center gap-1.5 py-1.5 text-xs text-slate-400">
              <RefreshCw className="h-3 w-3 animate-spin" /> Loading…
            </div>
          ) : items.length === 0 ? (
            <div className="text-xs text-slate-400 py-1.5">No tables found.</div>
          ) : (
            <>
              {items.map(tbl => (
                <button key={tbl.id} onClick={() => onSelectTable(tbl)}
                  className={cn(
                    'w-full text-left flex items-center gap-1.5 px-2 py-1 rounded text-[11px] transition-colors group',
                    selectedTable?.id === tbl.id
                      ? 'bg-brand-indigo text-white'
                      : 'text-slate-700 dark:text-slate-300 hover:bg-brand-indigo/10 dark:hover:bg-brand-indigo/20',
                  )}>
                  <TableIcon className={cn('h-3 w-3 flex-shrink-0', selectedTable?.id === tbl.id ? 'text-white/70' : 'text-slate-400')} />
                  <span className="truncate flex-1 font-mono">{tbl.name}</span>
                  {tbl.pii_column_count > 0 && (
                    <span className={cn('text-[9px] font-bold flex-shrink-0', selectedTable?.id === tbl.id ? 'text-red-300' : 'text-red-400')}>PII</span>
                  )}
                </button>
              ))}
              {hasMore && (
                <button onClick={onLoadMore} disabled={loading}
                  className="w-full text-center text-[10px] text-brand-indigo dark:text-indigo-400 py-1 hover:underline disabled:opacity-50">
                  {loading ? <RefreshCw className="h-3 w-3 animate-spin inline" /> : `+ ${total - items.length} more`}
                </button>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Data grid ─────────────────────────────────────────────────────────────────

function DataGrid({
  table,
  result,
  loading,
  error,
  page,
  pageSize,
  sortCol,
  sortDir,
  onSort,
  onPageChange,
  onPageSizeChange,
}: {
  table: TableItem;
  result: QueryResult | null;
  loading: boolean;
  error: string | null;
  page: number;
  pageSize: number;
  sortCol: string | undefined;
  sortDir: 'asc' | 'desc';
  onSort: (col: string) => void;
  onPageChange: (p: number) => void;
  onPageSizeChange: (ps: number) => void;
}) {
  const columns = result?.columns ?? [];
  const rows = result?.rows ?? [];
  const policy = result?.policy;
  const masked = policy?.masked_columns ?? [];
  const tokenized = policy?.tokenized_columns ?? [];
  const denied = policy?.denied_columns ?? [];

  const hasNext = rows.length >= pageSize;
  const hasPrev = page > 1;
  const approxTotal = table.row_count;

  if (error) {
    return (
      <div className="flex items-start gap-3 p-4 m-4 bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 rounded-xl">
        <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-bold text-red-800 dark:text-red-400">Query failed</p>
          <p className="text-xs text-red-700 dark:text-red-300 mt-1 whitespace-pre-wrap font-mono">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Policy bar */}
      {policy && (masked.length > 0 || tokenized.length > 0 || denied.length > 0 || policy.row_filter_applied) && (
        <div className="flex flex-wrap items-center gap-2 px-4 py-2 bg-slate-50 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800 text-xs font-semibold flex-shrink-0">
          <Shield className="h-3.5 w-3.5 text-slate-400" />
          <span className="text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[10px]">{policy.classification ?? 'Auto-Policy'}</span>
          {masked.length > 0 && <span className="text-yellow-600 dark:text-yellow-500">{masked.length} masked</span>}
          {tokenized.length > 0 && <span className="text-blue-600 dark:text-blue-500">{tokenized.length} tokenized</span>}
          {denied.length > 0 && <span className="text-red-500">{denied.length} denied</span>}
          {policy.row_filter_applied && <span className="text-brand-indigo">Row filter active</span>}
        </div>
      )}

      {/* Scrollable data table */}
      <div className="flex-1 overflow-auto min-h-0 relative">
        {loading && (
          <div className="absolute inset-0 bg-white/60 dark:bg-slate-950/60 z-10 flex items-center justify-center">
            <div className="flex items-center gap-2 text-sm text-slate-500">
              <RefreshCw className="h-4 w-4 animate-spin text-brand-indigo" />
              Loading rows…
            </div>
          </div>
        )}

        {!loading && !result && (
          <div className="flex items-center justify-center h-full text-slate-400 text-sm">
            Select a table to browse its data.
          </div>
        )}

        {result && columns.length > 0 && (
          <table className="min-w-full border-collapse text-xs">
            <thead className="sticky top-0 z-10 bg-slate-100 dark:bg-slate-800 shadow-sm">
              <tr>
                <th className="w-10 px-3 py-2.5 text-right text-[10px] font-bold text-slate-400 uppercase tracking-wider border-r border-slate-200 dark:border-slate-700 select-none">
                  #
                </th>
                {columns.map(col => {
                  const isMasked = !isAdmin() && masked.includes(col);
                  const isTokenized = !isAdmin() && tokenized.includes(col);
                  const isDenied = !isAdmin() && denied.includes(col);
                  const isSorted = sortCol === col;
                  return (
                    <th key={col}
                      onClick={() => onSort(col)}
                      className={cn(
                        'px-3 py-2.5 text-left whitespace-nowrap cursor-pointer select-none border-r border-slate-200 dark:border-slate-700',
                        'hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors',
                        isSorted && 'bg-brand-indigo/10 dark:bg-indigo-900/30',
                      )}>
                      <div className="flex items-center gap-1.5">
                        <span className={cn('font-mono font-bold text-[11px]',
                          isDenied ? 'text-red-500' : isMasked ? 'text-yellow-700 dark:text-yellow-500' : isTokenized ? 'text-blue-700 dark:text-blue-400' : 'text-slate-700 dark:text-slate-300')}>
                          {col}
                        </span>
                        {isMasked && <span className="text-[8px] text-yellow-600 uppercase font-bold">mask</span>}
                        {isTokenized && <span className="text-[8px] text-blue-500 uppercase font-bold">token</span>}
                        {isDenied && <span className="text-[8px] text-red-400 uppercase font-bold">denied</span>}
                        {isSorted
                          ? sortDir === 'asc'
                            ? <ArrowUp className="h-3 w-3 text-brand-indigo flex-shrink-0" />
                            : <ArrowDown className="h-3 w-3 text-brand-indigo flex-shrink-0" />
                          : <ArrowUpDown className="h-3 w-3 text-slate-300 dark:text-slate-600 flex-shrink-0" />}
                      </div>
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length + 1} className="px-4 py-8 text-center text-slate-400">
                    No rows on this page.
                  </td>
                </tr>
              ) : rows.map((row, ri) => (
                <tr key={ri} className="hover:bg-slate-50/70 dark:hover:bg-slate-800/20 transition-colors">
                  <td className="px-3 py-2 text-right text-[10px] text-slate-400 tabular-nums border-r border-slate-100 dark:border-slate-800 select-none">
                    {(page - 1) * pageSize + ri + 1}
                  </td>
                  {columns.map((col, ci) => {
                    const val = Array.isArray(row) ? row[ci] : null;
                    const isDenied = !isAdmin() && denied.includes(col);
                    const isMasked = !isAdmin() && masked.includes(col);
                    const isTokenized = !isAdmin() && tokenized.includes(col);
                    return (
                      <td key={col} className="px-3 py-2 border-r border-slate-100 dark:border-slate-800 max-w-[240px]">
                        <CellValue value={val} isDenied={isDenied} isMasked={isMasked} isTokenized={isTokenized} />
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination footer */}
      <div className="flex items-center justify-between px-4 py-2.5 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 flex-shrink-0 gap-3 flex-wrap">
        <div className="flex items-center gap-3 text-xs text-slate-500 dark:text-slate-400">
          {result && (
            <>
              <span className="flex items-center gap-1">
                <Hash className="h-3 w-3" />
                <span>{(page - 1) * pageSize + 1}–{(page - 1) * pageSize + rows.length}</span>
                {approxTotal != null && <span className="text-slate-400"> of ~{approxTotal.toLocaleString()}</span>}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                {result.execution_time_ms.toFixed(0)} ms
              </span>
            </>
          )}
        </div>

        <div className="flex items-center gap-2">
          <select
            value={pageSize}
            onChange={e => onPageSizeChange(Number(e.target.value))}
            className="text-xs border border-slate-200 dark:border-slate-700 rounded px-2 py-1 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 outline-none focus:border-brand-indigo"
          >
            {PAGE_SIZES.map(s => <option key={s} value={s}>{s} rows</option>)}
          </select>

          <div className="flex items-center gap-1">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={!hasPrev || loading}
              className="p-1.5 rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="h-3.5 w-3.5 text-slate-600 dark:text-slate-400" />
            </button>
            <span className="px-2 py-1 text-xs font-semibold text-slate-600 dark:text-slate-300 min-w-[40px] text-center">
              {page}
            </span>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={!hasNext || loading}
              className="p-1.5 rounded border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight className="h-3.5 w-3.5 text-slate-600 dark:text-slate-400" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Cell value ────────────────────────────────────────────────────────────────

function CellValue({
  value, isDenied, isMasked, isTokenized,
}: {
  value: unknown; isDenied: boolean; isMasked: boolean; isTokenized: boolean;
}) {
  const [showFull, setShowFull] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [detoking, setDetoking] = useState(false);

  if (isDenied) return <span className="text-red-400 italic text-[10px]">denied</span>;
  if (value === null || value === undefined) return <span className="text-slate-300 dark:text-slate-600 italic text-[10px]">NULL</span>;

  const str = String(value);

  if (isMasked) return (
    <span className="font-mono text-[11px] bg-yellow-50 dark:bg-yellow-950/30 text-yellow-800 dark:text-yellow-400 px-1 rounded border border-yellow-200 dark:border-yellow-900/30">
      {str}
    </span>
  );

  if (isTokenized) {
    if (revealed) return (
      <span className="flex items-center gap-1">
        <span className="font-mono text-[11px] text-green-700 dark:text-green-400">{revealed}</span>
        <button onClick={() => setRevealed(null)}><EyeOff className="h-3 w-3 text-slate-400" /></button>
      </span>
    );
    return (
      <span className="flex items-center gap-1">
        <span className="font-mono text-[11px] bg-blue-50 dark:bg-blue-950/30 text-blue-700 dark:text-blue-400 px-1 rounded border border-blue-200 dark:border-blue-900/30">{str}</span>
        <button onClick={async () => {
          setDetoking(true);
          try {
            const r = await api.post(`/query/detokenize?token=${encodeURIComponent(str)}`);
            setRevealed(r.data.value);
          } finally { setDetoking(false); }
        }}>
          {detoking ? <RefreshCw className="h-3 w-3 animate-spin text-slate-400" /> : <Eye className="h-3 w-3 text-slate-400 hover:text-brand-indigo" />}
        </button>
      </span>
    );
  }

  const LIMIT = 80;
  if (str.length > LIMIT && !showFull) {
    return (
      <span>
        <span className="font-mono text-[11px] text-slate-800 dark:text-slate-200">{str.slice(0, LIMIT)}</span>
        <button onClick={() => setShowFull(true)} className="text-[10px] text-brand-indigo ml-1 hover:underline">…more</button>
      </span>
    );
  }
  return (
    <span>
      <span className="font-mono text-[11px] text-slate-800 dark:text-slate-200 break-all">{str}</span>
      {str.length > LIMIT && (
        <button onClick={() => setShowFull(false)} className="text-[10px] text-slate-400 ml-1 hover:underline">less</button>
      )}
    </span>
  );
}

// ── Schema / column view ──────────────────────────────────────────────────────

function SchemaView({ tableId }: { tableId: number }) {
  const [columns, setColumns] = useState<ColumnInfo[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api.get(`/catalog/tables/${tableId}`)
      .then(r => setColumns(r.data?.columns ?? []))
      .catch(() => setColumns([]))
      .finally(() => setLoading(false));
  }, [tableId]);

  if (loading) return (
    <div className="flex items-center justify-center py-12 text-slate-400 text-sm gap-2">
      <RefreshCw className="h-4 w-4 animate-spin text-brand-indigo" /> Loading columns…
    </div>
  );

  return (
    <div className="overflow-auto">
      <table className="min-w-full text-xs">
        <thead className="sticky top-0 bg-slate-50 dark:bg-slate-800/60 border-b border-slate-200 dark:border-slate-800">
          <tr>
            {['Column', 'Type', 'Sensitivity', 'Suggested'].map(h => (
              <th key={h} className="px-4 py-2.5 text-left text-[10px] font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/50">
          {columns.map(col => (
            <tr key={col.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20">
              <td className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <Columns className="h-3 w-3 text-slate-400 flex-shrink-0" />
                  <span className="font-mono font-semibold text-slate-800 dark:text-slate-200">{col.name}</span>
                </div>
              </td>
              <td className="px-4 py-2.5 font-mono text-slate-500 dark:text-slate-400">{col.type || '—'}</td>
              <td className="px-4 py-2.5">
                {col.pii_type ? <PiiBadge type={col.pii_type} /> : <span className="text-slate-300 dark:text-slate-600 text-[11px]">—</span>}
              </td>
              <td className="px-4 py-2.5">
                {col.suggested_pii_type && !col.pii_type
                  ? <span className="flex items-center gap-1 text-[10px] text-indigo-600 dark:text-indigo-400 font-semibold">✨ {col.suggested_pii_type}</span>
                  : <span className="text-slate-300 dark:text-slate-600 text-[11px]">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Main Tables page ──────────────────────────────────────────────────────────

export function Tables() {
  const [selectedTable, setSelectedTable] = useState<TableItem | null>(null);
  const [activeTab, setActiveTab] = useState<'data' | 'schema'>('data');
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Data grid state
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [sortCol, setSortCol] = useState<string | undefined>();
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [result, setResult] = useState<QueryResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async (
    tbl: TableItem, pg: number, ps: number, sc?: string, sd?: 'asc' | 'desc',
  ) => {
    if (!tbl.source_id) {
      setError('This table has no associated data source. Re-scan may be needed.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const sql = buildSQL(tbl, pg, ps, sc, sd);
      const res = await api.post('/query/execute', {
        source_id: tbl.source_id,
        sql,
        limit: ps + 1, // fetch one extra to detect if there's a next page
      });
      const data = res.data as QueryResult;
      // If we got ps+1 rows, there IS a next page — trim the extra row
      if (data.rows?.length > ps) {
        data.rows = data.rows.slice(0, ps);
        data.row_count = ps;
      }
      setResult(data);
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      const msg = e.response?.data?.detail;
      setError(typeof msg === 'string' ? msg : JSON.stringify(msg ?? e.message ?? 'Unknown error'));
    } finally {
      setLoading(false);
    }
  }, []);

  const handleSelectTable = (tbl: TableItem) => {
    setSelectedTable(tbl);
    setPage(1);
    setSortCol(undefined);
    setSortDir('asc');
    setResult(null);
    setError(null);
    setActiveTab('data');
    fetchData(tbl, 1, pageSize);
  };

  const handleSort = (col: string) => {
    const newDir = sortCol === col && sortDir === 'asc' ? 'desc' : 'asc';
    setSortCol(col);
    setSortDir(newDir);
    setPage(1);
    if (selectedTable) fetchData(selectedTable, 1, pageSize, col, newDir);
  };

  const handlePageChange = (p: number) => {
    setPage(p);
    if (selectedTable) fetchData(selectedTable, p, pageSize, sortCol, sortDir);
  };

  const handlePageSizeChange = (ps: number) => {
    setPageSize(ps);
    setPage(1);
    if (selectedTable) fetchData(selectedTable, 1, ps, sortCol, sortDir);
  };

  return (
    <div className="flex flex-col h-[calc(100vh-80px)]">
      {/* Header */}
      <div className="flex-shrink-0 flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-3">
          <TableIcon className="w-5 h-5 text-brand-indigo" />
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Table Browser</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Browse table data with policy enforcement — PII masked, all access audited.
            </p>
          </div>
        </div>
        <button
          onClick={() => setSidebarOpen(v => !v)}
          className="p-2 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
        >
          {sidebarOpen
            ? <PanelLeftClose className="h-4 w-4 text-slate-500" />
            : <PanelLeftOpen className="h-4 w-4 text-slate-500" />}
        </button>
      </div>

      {/* Body: sidebar + content */}
      <div className="flex flex-1 min-h-0 overflow-hidden">
        {/* Sidebar */}
        {sidebarOpen && (
          <div className="w-72 flex-shrink-0 border-r border-slate-200 dark:border-slate-800 flex flex-col min-h-0 bg-white dark:bg-slate-950">
            <TreePanel selectedTable={selectedTable} onSelectTable={handleSelectTable} />
          </div>
        )}

        {/* Main content */}
        <div className="flex-1 flex flex-col min-w-0 min-h-0">
          {!selectedTable ? (
            <div className="flex-1 flex flex-col items-center justify-center gap-4 text-slate-400 dark:text-slate-500">
              <TableIcon className="h-12 w-12 opacity-20" />
              <div className="text-center">
                <p className="font-semibold text-slate-500 dark:text-slate-400">No table selected</p>
                <p className="text-sm mt-1">Pick a source → schema → table from the left panel</p>
              </div>
            </div>
          ) : (
            <>
              {/* Table header */}
              <div className="flex-shrink-0 flex items-center gap-3 px-5 py-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50">
                <TableIcon className="h-4 w-4 text-brand-indigo flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono font-bold text-sm text-slate-900 dark:text-slate-100">{selectedTable.name}</span>
                    <span className="text-slate-400">·</span>
                    <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">{selectedTable.schema_name}</span>
                    <span className="text-slate-400">·</span>
                    <span className="text-xs text-slate-500 dark:text-slate-400">{selectedTable.source_name}</span>
                    <span className={cn(
                      'text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider',
                      'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300',
                    )}>{selectedTable.source_type}</span>
                    {selectedTable.pii_column_count > 0 && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider bg-red-100 dark:bg-red-950/40 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-900/40">
                        {selectedTable.pii_column_count} PII cols
                      </span>
                    )}
                    {selectedTable.row_count != null && (
                      <span className="text-[10px] text-slate-400">~{selectedTable.row_count.toLocaleString()} rows</span>
                    )}
                  </div>
                </div>

                {/* Re-run button */}
                <button
                  onClick={() => selectedTable && fetchData(selectedTable, page, pageSize, sortCol, sortDir)}
                  disabled={loading}
                  className="p-1.5 rounded border border-slate-200 dark:border-slate-700 hover:bg-white dark:hover:bg-slate-800 transition-colors disabled:opacity-50"
                  title="Refresh"
                >
                  <RefreshCw className={cn('h-3.5 w-3.5 text-slate-500', loading && 'animate-spin')} />
                </button>
              </div>

              {/* Tabs */}
              <div className="flex-shrink-0 flex border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950">
                {([['data', TableIcon, 'Data'], ['schema', Columns, 'Schema']] as const).map(([tab, Icon, label]) => (
                  <button key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={cn(
                      'flex items-center gap-1.5 px-5 py-2.5 text-xs font-semibold border-b-2 transition-colors',
                      activeTab === tab
                        ? 'border-brand-indigo text-brand-indigo dark:text-indigo-400'
                        : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300',
                    )}>
                    <Icon className="h-3.5 w-3.5" />
                    {label}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              <div className="flex-1 min-h-0 overflow-hidden">
                {activeTab === 'data' ? (
                  <DataGrid
                    table={selectedTable}
                    result={result}
                    loading={loading}
                    error={error}
                    page={page}
                    pageSize={pageSize}
                    sortCol={sortCol}
                    sortDir={sortDir}
                    onSort={handleSort}
                    onPageChange={handlePageChange}
                    onPageSizeChange={handlePageSizeChange}
                  />
                ) : (
                  <SchemaView tableId={selectedTable.id} />
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
