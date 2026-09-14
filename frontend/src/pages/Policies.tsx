import React, { useState, useEffect } from 'react';
import { Plus, Trash2, ChevronDown, ChevronUp, Shield, Pencil, X, Lock, RefreshCw } from 'lucide-react';
import { api, isAdmin, fetchSettings, updateSettings, fetchTables } from '../api';
import { cn } from '../lib/utils';
import { Navigate } from 'react-router-dom';
import { CONNECTORS } from '../data/connectors';

const CLASSIFICATIONS = ['PUBLIC', 'PII', 'PHI', 'PSI'];
// Default source types, will be augmented by actual connected sources
const DEFAULT_SOURCE_TYPES = ['postgres', 'mysql', 'mongodb', 'snowflake', 'bigquery', 'redshift', 's3_storage', 'gcs_storage', 'azure_blob'];
const ACTIONS = ['allow', 'mask', 'tokenize', 'deny'];

const CLASSIFICATION_COLORS: Record<string, string> = {
  PUBLIC: 'bg-green-150 dark:bg-green-950/40 text-green-800 dark:text-green-400 border border-green-200 dark:border-green-900/40',
  PII: 'bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-400 border border-red-200 dark:border-red-900/40',
  PHI: 'bg-blue-100 dark:bg-blue-950/40 text-blue-800 dark:text-blue-400 border border-blue-200 dark:border-blue-900/40',
  PSI: 'bg-purple-105 dark:bg-purple-950/40 text-purple-800 dark:text-purple-400 border border-purple-200 dark:border-purple-900/40',
};

const ACTION_COLORS: Record<string, string> = {
  allow: 'bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-900/30',
  mask: 'bg-yellow-50 dark:bg-yellow-950/20 text-yellow-750 dark:text-yellow-400 border border-yellow-250 dark:border-yellow-900/30',
  tokenize: 'bg-blue-50 dark:bg-blue-950/20 text-blue-700 dark:text-blue-400 border border-blue-200 dark:border-blue-900/30',
  deny: 'bg-red-50 dark:bg-red-950/20 text-red-750 dark:text-red-400 border border-red-250 dark:border-red-900/30',
};

const MASKING_TYPES = [
  { value: '', label: 'Auto-detect' },
  { value: 'EMAIL', label: 'Email' },
  { value: 'NAME', label: 'Name' },
  { value: 'SSN', label: 'SSN' },
  { value: 'PHONE', label: 'Phone' },
  { value: 'SENSITIVE', label: 'Full Redact' },
];

type ColumnPolicy = { action: string; roles_exempt: string[]; masking_type?: string };
type RowFilter = { column: string; value: string };
type Policy = {
  id: number;
  resource: string;
  classification: string;
  source_type: string;
  column_policies: Record<string, ColumnPolicy>;
  row_filters: RowFilter[];
  tenant_id: number;
  created_at: string;
  updated_at: string;
  database_name?: string;
};

// ── Role Masking Map ──────────────────────────────────────────────────────────
function RoleMaskingEditor() {
  const [roleLevels, setRoleLevels] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSettings().then((res) => {
      setRoleLevels(res.masking?.role_levels || {});
      setLoading(false);
    });
  }, []);

  const updateRoleLevel = async (role: string, level: string) => {
    const next = { ...roleLevels, [role]: level };
    setRoleLevels(next);
    const settings = await fetchSettings();
    settings.masking = { ...settings.masking, role_levels: next };
    await updateSettings(settings);
  };

  if (loading) return null;

  return (
    <div className="bg-indigo-50/20 dark:bg-slate-800/40 p-4 rounded-xl border border-slate-200 dark:border-slate-800">
      <label className="block text-xs font-bold text-slate-900 dark:text-slate-100 uppercase tracking-wider mb-2.5 flex items-center gap-2">
        <Shield className="h-4 w-4 text-brand-indigo" /> Policy Role Access
      </label>
      <p className="text-xs text-slate-400 dark:text-slate-500 mb-3.5">Control global visibility levels for primary roles.</p>
      <div className="grid grid-cols-2 gap-4">
        <div className="flex flex-col gap-1">
          <span className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Admin (Tenant)</span>
          <select
            value={roleLevels['admin'] || 'raw'}
            onChange={(e) => updateRoleLevel('admin', e.target.value)}
            className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-200 rounded-lg px-2.5 py-1.5 text-xs outline-none focus:border-brand-indigo font-bold transition-all"
          >
            <option value="raw">Raw (Full Access)</option>
            <option value="partial">Partial Mask</option>
            <option value="full">Full Mask</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <span className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Analyst</span>
          <select
            value={roleLevels['analyst'] || 'full'}
            onChange={(e) => updateRoleLevel('analyst', e.target.value)}
            className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-200 rounded-lg px-2.5 py-1.5 text-xs outline-none focus:border-brand-indigo font-bold transition-all"
          >
            <option value="partial">Partial Mask</option>
            <option value="full">Full Mask (Strict)</option>
          </select>
        </div>
      </div>
      <p className="mt-2.5 text-[10px] text-brand-indigo dark:text-indigo-400 italic font-semibold">Note: Analysts are restricted from viewing raw sensitive data.</p>
    </div>
  );
}

// ── Policy form (create / edit) ───────────────────────────────────────────────
function PolicyForm({
  initial,
  onSave,
  onCancel,
}: {
  initial?: Partial<Policy>;
  onSave: (data: any) => Promise<void>;
  onCancel: () => void;
}) {
  const [resource, setResource] = useState(initial?.resource ?? '');
  const [databaseName, setDatabaseName] = useState(initial?.database_name ?? '');
  const [classification, setClassification] = useState(initial?.classification ?? 'PII');
  const [sourceType, setSourceType] = useState(initial?.source_type ?? 'postgres');
  const [columnPolicies, setColumnPolicies] = useState<Record<string, ColumnPolicy>>(initial?.column_policies ?? {});
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  
  const [availableSources, setAvailableSources] = useState<any[]>([]);
  const [availableTables, setAvailableTables] = useState<any[]>([]);
  const [loadingMetadata, setLoadingMetadata] = useState(false);

  useEffect(() => {
    setLoadingMetadata(true);
    Promise.all([
        api.get('/sources'),
        fetchTables()
    ]).then(([sourcesRes, tablesRes]) => {
        setAvailableSources(sourcesRes.data.items || []);
        setAvailableTables(tablesRes.items || []);
    }).finally(() => setLoadingMetadata(false));
  }, []);

  // Compute dynamic source types based on CONNECTORS + actual sources
  const dynamicSourceTypes = Array.from(new Set([
    ...DEFAULT_SOURCE_TYPES,
    ...availableSources.map(s => s.type),
    ...CONNECTORS.filter(c => c.category === 'database' || c.category === 'storage').map(c => c.type)
  ])).sort();

  const [editCols, setEditCols] = useState<{name: string, policy: ColumnPolicy}[]>(() => {
    return Object.entries(initial?.column_policies ?? {})
      .filter(([k]) => k !== '__tags__' && k !== '__schedule__')
      .map(([name, policy]) => ({ name, policy }));
  });

  useEffect(() => {
    if (editCols.length === 0 && !resource.startsWith('FIELD:')) {
      setEditCols([{ name: '', policy: { action: 'mask', roles_exempt: [], masking_type: '' } }]);
    }
  }, []);

  const updateCol = (i: number, name: string, policy: ColumnPolicy) => {
    const next = [...editCols];
    next[i] = { name, policy };
    setEditCols(next);
    
    // Sync to main state
    const nextPolicies: Record<string, ColumnPolicy> = {};
    next.forEach(c => { if (c.name) nextPolicies[c.name] = c.policy; });
    setColumnPolicies(nextPolicies);

    if (resource.startsWith('FIELD:')) {
        setResource(`FIELD:${name}`);
    }
  };

  const addCol = () => setEditCols([...editCols, { name: '', policy: { action: 'mask', roles_exempt: [], masking_type: '' } }]);
  const removeCol = (i: number) => {
    const next = editCols.filter((_, idx) => idx !== i);
    setEditCols(next);
    const nextPolicies: Record<string, ColumnPolicy> = {};
    next.forEach(c => { if (c.name) nextPolicies[c.name] = c.policy; });
    setColumnPolicies(nextPolicies);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSaving(true);
    try {
      await onSave({ 
        resource, 
        database_name: databaseName, 
        classification, 
        source_type: sourceType, 
        column_policies: columnPolicies, 
        row_filters: [] 
      });
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6 p-5 bg-white dark:bg-slate-900 text-slate-800 dark:text-slate-100">
      {error && <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-650 dark:text-red-400 px-3 py-2 rounded-lg text-sm">{error}</div>}
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Resource Scope</label>
            <div className="flex gap-2.5">
              <select
                value={resource === '*' ? '*' : resource.startsWith('FIELD:') ? 'field' : 'table'}
                onChange={(e) => {
                  if (e.target.value === '*') setResource('*');
                  else if (e.target.value === 'field') setResource('FIELD:');
                  else setResource('');
                }}
                disabled={!!initial?.id}
                className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-200 rounded-lg px-2.5 py-1.5 text-xs outline-none focus:border-brand-indigo font-bold transition-all w-1/3 disabled:opacity-50"
              >
                <option value="table">Specific Table</option>
                <option value="field">Specific Field (Global)</option>
                <option value="*">Full Database (*)</option>
              </select>
              
              {resource !== '*' && !resource.startsWith('FIELD:') && (
                <div className="flex-1 relative">
                  <input
                    required type="text" 
                    value={resource} 
                    onChange={(e) => setResource(e.target.value)}
                    disabled={!!initial?.id}
                    placeholder="Table Name (e.g. users)"
                    className="premium-input font-mono text-xs disabled:opacity-50"
                    list="resource-suggestions"
                  />
                  <datalist id="resource-suggestions">
                    {availableTables
                        .filter(t => !sourceType || (t.source_type || 'postgres').toLowerCase() === sourceType.toLowerCase())
                        .map(t => <option key={t.id} value={t.name}>{t.database_name ? `${t.database_name}.${t.name}` : t.name}</option>)
                    }
                  </datalist>
                  <p className="mt-1.5 text-[10px] text-slate-400 dark:text-slate-550 font-medium">
                    {loadingMetadata ? 'Loading suggestions...' : 'Suggestions shown from scanned resources'}
                  </p>
                </div>
              )}
            </div>

            {resource !== '*' && (
              <div className="mt-4 space-y-3.5">
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Column Name Field(s)</label>
                
                <div className="space-y-2">
                  {editCols.map((c, i) => (
                    <div key={i} className="flex items-center gap-2 animate-scale-up">
                      <input
                        type="text"
                        value={c.name}
                        onChange={(e) => updateCol(i, e.target.value, c.policy)}
                        placeholder="column name..."
                        className="flex-1 premium-input font-mono text-xs"
                      />
                      <select
                        value={c.policy.action}
                        onChange={(e) => updateCol(i, c.name, { ...c.policy, action: e.target.value })}
                        className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-200 rounded-lg px-2 py-1.5 text-xs outline-none focus:border-brand-indigo font-semibold transition-all"
                      >
                        {ACTIONS.map(a => <option key={a} value={a}>{a}</option>)}
                      </select>
                      {c.policy.action === 'mask' && (
                        <select
                          value={c.policy.masking_type || ''}
                          onChange={(e) => updateCol(i, c.name, { ...c.policy, masking_type: e.target.value })}
                          className="text-xs border border-indigo-200 dark:border-indigo-900/60 rounded-lg px-2.5 py-1.5 font-bold focus:outline-none bg-indigo-50 dark:bg-indigo-950/40 text-brand-indigo dark:text-indigo-400 transition-colors"
                        >
                          {MASKING_TYPES.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
                        </select>
                      )}
                      <button
                        type="button"
                        onClick={() => removeCol(i)}
                        className="p-2.5 rounded-lg text-slate-350 hover:text-red-500 hover:bg-slate-100 dark:hover:bg-slate-800 transition-all"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={addCol}
                  className="mt-2.5 text-xs text-brand-indigo dark:text-indigo-400 font-bold hover:underline flex items-center gap-1"
                >
                  <Plus className="h-3 w-3" /> Add one more column
                </button>
              </div>
            )}
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Database Name</label>
              <input type="text" value={databaseName} onChange={(e) => setDatabaseName(e.target.value)}
                placeholder="e.g. metadata_db (optional)"
                list="db-suggestions"
                className="premium-input font-mono" />
              <datalist id="db-suggestions">
                {Array.from(new Set(availableTables.map(t => t.database_name))).filter(Boolean).map(db => (
                    <option key={db} value={db} />
                ))}
              </datalist>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Classification</label>
              <select value={classification} onChange={(e) => setClassification(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-205 rounded-lg px-2.5 py-1.5 text-xs outline-none focus:border-brand-indigo font-bold transition-all w-full"
              >
                {CLASSIFICATIONS.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-widest mb-1.5">Source Type</label>
              <select value={sourceType} onChange={(e) => setSourceType(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-205 rounded-lg px-2.5 py-1.5 text-xs outline-none focus:border-brand-indigo font-medium transition-all w-full">
                {dynamicSourceTypes.map((s) => (
                    <option key={s} value={s}>
                        {s} {availableSources.some(src => src.type === s) ? '(Connected)' : ''}
                    </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          {!resource.startsWith('FIELD:') && <RoleMaskingEditor />}
        </div>
      </div>

      <div className="flex justify-end gap-2.5 pt-4 border-t border-slate-200 dark:border-slate-800">
        <button type="button" onClick={onCancel}
          className="premium-btn-secondary">
          Cancel
        </button>
        <button type="submit" disabled={saving}
          className="premium-btn-primary font-bold">
          {saving ? 'Saving...' : (initial?.id ? 'Save Changes' : 'Create Policy')}
        </button>
      </div>
    </form>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export function Policies() {
  if (!isAdmin()) return <Navigate to="/" replace />;

  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const res = await api.get('/policies');
      setPolicies(res.data.items || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load policies');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchPolicies(); }, []);

  const handleCreate = async (data: any) => {
    await api.post('/policies', data);
    setCreating(false);
    fetchPolicies();
  };

  const handleUpdate = async (id: number, data: any) => {
    await api.patch(`/policies/${id}`, data);
    setEditingId(null);
    fetchPolicies();
  };

  const handleDelete = async (id: number, resource: string) => {
    if (!confirm(`Delete policy for "${resource}"?`)) return;
    await api.delete(`/policies/${id}`);
    fetchPolicies();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Policy Engine</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1 flex items-center gap-1.5 flex-wrap">
            <Shield className="h-4 w-4 text-brand-indigo" />
            Define masking rules and compliance standards. 
            <a href="/query" className="text-brand-indigo dark:text-indigo-400 hover:underline font-bold ml-1">Verify results in Query Playground →</a>
          </p>
        </div>
        {!creating && (
          <button onClick={() => { setCreating(true); setEditingId(null); }}
            className="premium-btn-primary gap-2"
          >
            <Plus className="h-4 w-4" /> New Policy
          </button>
        )}
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 px-4 py-3 rounded-lg text-sm flex justify-between">
          <span>{error}</span>
          <button onClick={() => setError('')} className="underline font-bold">dismiss</button>
        </div>
      )}

      {creating && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-lg rounded-xl overflow-hidden animate-scale-up">
          <div className="px-5 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 flex justify-between items-center">
            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">New Policy Rule</h3>
            <button onClick={() => setCreating(false)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"><X className="h-5 w-5" /></button>
          </div>
          <PolicyForm onSave={handleCreate} onCancel={() => setCreating(false)} />
        </div>
      )}

      <div className="space-y-4">
        {loading ? (
          <div className="p-8 text-center text-slate-500 dark:text-slate-400">
            <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
            <p className="text-sm">Loading security policies…</p>
          </div>
        ) : policies.length === 0 ? (
          <div className="p-12 text-center text-slate-400 dark:text-slate-500 border border-dashed border-slate-250 dark:border-slate-800 rounded-xl bg-white dark:bg-slate-900/40">
            <Shield className="h-12 w-12 mx-auto mb-3 opacity-30 animate-pulse" />
            <p className="font-semibold text-slate-800 dark:text-slate-200">No security policies found.</p>
            <p className="text-xs mt-1">Create a policy to control access to sensitive database columns.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {policies.map((p) => (
              <div key={p.id} className="premium-card p-5">
                <div className="flex items-center justify-between flex-wrap gap-4">
                  <div className="flex items-center gap-3">
                    <Shield className="h-5 w-5 text-slate-400 dark:text-slate-500 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2.5 flex-wrap">
                        <span className="font-bold text-slate-900 dark:text-slate-100 font-mono text-sm">{p.resource}</span>
                        {p.database_name && (
                          <span className="text-[10px] text-slate-500 dark:text-slate-450 font-mono border border-slate-200 dark:border-slate-700 rounded px-1.5 bg-slate-50 dark:bg-slate-800/40 font-bold uppercase tracking-wider">
                            DB: {p.database_name}
                          </span>
                        )}
                        <span className={cn('inline-flex px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider', CLASSIFICATION_COLORS[p.classification] ?? 'bg-slate-100 text-slate-750')}>
                          {p.classification}
                        </span>
                        <span className="text-xs text-slate-400 dark:text-slate-500 font-semibold">
                          {p.source_type === 'postgres' ? 'PostgreSQL' : 
                           p.source_type === 'mongodb' ? 'MongoDB' : 
                           p.source_type === 's3_storage' ? 'S3 Storage' : 
                           p.source_type === 'gcs_storage' ? 'GCS' : 
                           p.source_type === 'azure_blob' ? 'Azure Blob' : 
                           p.source_type.charAt(0).toUpperCase() + p.source_type.slice(1)}
                        </span>
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold border border-green-200 dark:border-green-900/40 bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 uppercase tracking-wider">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span> Active
                        </span>
                        <span className="text-xs text-slate-400 dark:text-slate-550 font-medium">
                          {Object.keys(p.column_policies).length} column rule(s)
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] text-slate-400 dark:text-slate-500">
                        Updated {new Date(p.updated_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <button onClick={() => setExpandedId(expandedId === p.id ? null : p.id)}
                      className="premium-btn-secondary px-3 py-1.5 text-xs gap-1.5"
                    >
                      {expandedId === p.id ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                      {expandedId === p.id ? 'Hide Details' : 'View Rules'}
                    </button>
                    <button onClick={() => { setEditingId(p.id); setExpandedId(null); setCreating(false); }}
                      className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 transition-colors"
                      title="Edit"
                    >
                      <Pencil className="h-4 w-4" />
                    </button>
                    <button onClick={() => handleDelete(p.id, p.resource)}
                      className="p-1.5 rounded-lg bg-red-50 hover:bg-red-100 dark:bg-red-950/20 dark:hover:bg-red-950/40 text-red-650 dark:text-red-400 transition-colors"
                      title="Delete"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                {/* Read-only view */}
                {expandedId === p.id && editingId !== p.id && (
                  <div className="mt-4 border-t border-slate-205 dark:border-slate-800 pt-4 space-y-3.5 animate-slide-up">
                    {Object.entries(p.column_policies).length > 0 && (
                      <div className="space-y-4">
                        {Object.entries(p.column_policies).filter(([col]) => col !== '__tags__' && col !== '__schedule__').length > 0 && (
                          <div>
                            <p className="text-[10px] font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-2.5">Column Rules</p>
                            <div className="flex flex-wrap gap-2">
                              {Object.entries(p.column_policies).filter(([col]) => col !== '__tags__' && col !== '__schedule__').map(([col, pol]) => {
                                  const colPol = pol as ColumnPolicy;
                                  return (
                                    <span key={col} className="inline-flex items-center gap-2 px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-800 text-xs bg-slate-50 dark:bg-slate-900/50 shadow-sm">
                                      <span className="font-mono font-bold text-slate-700 dark:text-slate-300">{col}</span>
                                      <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider', ACTION_COLORS[colPol.action])}>{colPol.action}</span>
                                    </span>
                                  );
                              })}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Edit form */}
                {editingId === p.id && (
                  <div className="mt-4 border-t border-slate-200 dark:border-slate-805 pt-4 animate-scale-up">
                    <PolicyForm
                      initial={p}
                      onSave={(data) => handleUpdate(p.id, data)}
                      onCancel={() => setEditingId(null)}
                    />
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
