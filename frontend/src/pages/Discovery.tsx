import React, { useState, useEffect } from 'react';
import { Search, Shield, Eye, ShieldAlert, Table as TableIcon, Filter, AlertCircle, CheckCircle2, X, Play } from 'lucide-react';
import { fetchTables, fetchColumns, fetchPolicies, fetchTableDetail, executeQuery } from '../api';
import { cn } from '../lib/utils';
import { useNavigate } from 'react-router-dom';

interface Table {
  id: number;
  name: string;
  tenant_id: number;
  schema_id: number;
  source_id?: number;
  source_type?: string;
  database_name?: string;
  schema_name?: string;
}

interface Column {
  id: number;
  name: string;
  type: string;
  pii_type?: string;
  classification?: string;
}

interface Policy {
  id: number;
  resource: string;
  column_policies: Record<string, any>;
  classification: string;
  database_name?: string;
  source_type?: string;
}

interface PreviewData {
  columns: string[];
  originalRows: any[][];
  maskedRows: any[][];
  targetName: string;
}

export function Discovery() {
  const [tables, setTables] = useState<Table[]>([]);
  const [selectedTable, setSelectedTable] = useState<number | null>(null);
  const [activeTableDetail, setActiveTableDetail] = useState<Table | null>(null);
  const [columns, setColumns] = useState<Column[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [preview, setPreview] = useState<PreviewData | null>(null);
  const [previewMode, setPreviewMode] = useState<'original' | 'masked'>('original');
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [selectedSource, setSelectedSource] = useState<string>('');
  const [selectedDb, setSelectedDb] = useState<string>('');
  const navigate = useNavigate();

  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      const [tableData, policyData] = await Promise.all([
        fetchTables(),
        fetchPolicies()
      ]);
      setTables(tableData.items || []);
      setPolicies(policyData.items || []);
    } catch (e) {
      console.error('Error loading data:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleTableChange = async (tableId: number) => {
    setSelectedTable(tableId);
    setLoadingDetails(true);
    setPreview(null);
    try {
      const [detail, columnData] = await Promise.all([
        fetchTableDetail(tableId),
        fetchColumns(tableId)
      ]);
      setActiveTableDetail(detail);
      setColumns(columnData || []);

      // Auto-trigger preview
      if (detail && detail.source_id) {
        setLoadingPreview(true);
        setPreviewMode('masked');
        try {
          let sql = "";
          const isOracle = detail.source_type === "oracle" || detail.source_type === "oracledb";
          const colSelector = "*";
          
          if (detail.source_type === "mongodb") {
              sql = JSON.stringify({ collection: detail.name, filter: {}, projection: {}, limit: 100 }, null, 2);
          } else {
              const schemaName = detail.schema_name;
              const tableName = isOracle ? detail.name.toUpperCase() : detail.name;
              const fullTableName = schemaName 
                ? `"${isOracle ? schemaName.toUpperCase() : schemaName}"."${tableName}"` 
                : `"${tableName}"`;
              sql = `SELECT ${colSelector} FROM ${fullTableName} LIMIT 100`;
          }
          
          const [originalResult, maskedResult] = await Promise.all([
            executeQuery(detail.source_id, sql, 100, true), // bypass masking
            executeQuery(detail.source_id, sql, 100, false) // normal masking
          ]);
          
          setPreview({
            columns: originalResult.columns,
            originalRows: originalResult.rows,
            maskedRows: maskedResult.rows,
            targetName: detail.name
          });
        } catch (previewErr) {
          console.error('Auto-preview failed:', previewErr);
        } finally {
          setLoadingPreview(false);
        }
      }
    } catch (e) {
      console.error('Error loading table details:', e);
    } finally {
      setLoadingDetails(false);
    }
  };

  const handlePreview = async (columnName?: string) => {
    if (!activeTableDetail?.source_id) return;
    
    setLoadingPreview(true);
    setPreviewMode('masked');
    try {
      let sql = "";
      const isOracle = activeTableDetail.source_type === "oracle" || activeTableDetail.source_type === "oracledb";
      const colSelector = columnName ? (isOracle ? `"${columnName.toUpperCase()}"` : `"${columnName}"`) : "*";
      
      if (activeTableDetail.source_type === "mongodb") {
          const projection = columnName ? { [columnName]: 1 } : {};
          sql = JSON.stringify({ collection: activeTableDetail.name, filter: {}, projection, limit: 100 }, null, 2);
      } else {
          const schemaName = activeTableDetail.schema_name;
          const tableName = isOracle ? activeTableDetail.name.toUpperCase() : activeTableDetail.name;
          const fullTableName = schemaName 
            ? `"${isOracle ? schemaName.toUpperCase() : schemaName}"."${tableName}"` 
            : `"${tableName}"`;
          sql = `SELECT ${colSelector} FROM ${fullTableName} LIMIT 100`;
      }
      
      const [originalResult, maskedResult] = await Promise.all([
        executeQuery(activeTableDetail.source_id, sql, 100, true), // bypass masking
        executeQuery(activeTableDetail.source_id, sql, 100, false) // normal masking
      ]);
      
      setPreview({
        columns: originalResult.columns,
        originalRows: originalResult.rows,
        maskedRows: maskedResult.rows,
        targetName: columnName ? `${activeTableDetail.name}.${columnName}` : activeTableDetail.name
      });
    } catch (e) {
      console.error('Preview failed:', e);
      alert('Preview failed. Ensure the data source is reachable.');
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleTestInQuery = () => {
    if (!activeTableDetail) return;
    let sql = "";
    if (activeTableDetail.source_type === "mongodb") {
      sql = JSON.stringify({ collection: activeTableDetail.name, filter: {} }, null, 2);
    } else {
      const isOracle = activeTableDetail.source_type === "oracle" || activeTableDetail.source_type === "oracledb";
      const tableName = isOracle ? activeTableDetail.name.toUpperCase() : activeTableDetail.name;
      sql = `SELECT * FROM "${tableName}" LIMIT 100`;
    }
    navigate('/query', { state: { sourceId: activeTableDetail.source_id, sql } });
  };

  const activePolicy = policies.find(p => {
    if (!activeTableDetail) return false;
    
    const pResource = p.resource || '';
    const pDb = (p.database_name || 'default').toLowerCase();
    const pSource = (p.source_type || 'postgres').toLowerCase().replace('postgresql', 'postgres');
    
    const tName = activeTableDetail.name;
    const tDb = (activeTableDetail.database_name || 'default').toLowerCase();
    const tSource = (activeTableDetail.source_type || 'postgres').toLowerCase().replace('postgresql', 'postgres');

    let resourceName = pResource;
    if (pResource.startsWith('FIELD:')) {
       resourceName = pResource.split(':')[1].split('.')[0];
    }

    const nameMatch = 
        resourceName === tName || 
        pResource === '*' ||
        (pResource.includes('*') && new RegExp('^' + pResource.replace(/\*/g, '.*') + '$', 'i').test(tName));
    const sourceMatch = pSource === tSource;
    
    // Flexible Database Match: Perfect match OR one is a substring of the other
    const dbMatch = pDb === tDb || 
                    (pDb && tDb && (pDb.includes(tDb) || tDb.includes(pDb))) ||
                    !pDb || pDb === 'default';

    return nameMatch && dbMatch && sourceMatch;
  });

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-8 animate-fade-in text-slate-800 dark:text-slate-100">
      {/* Header Section */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-6 border-b border-slate-150 dark:border-slate-800 pb-6">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100 font-display flex items-center gap-3">
            <Search className="w-8 h-8 text-brand-indigo" />
            Data Discovery
          </h1>
          <p className="mt-1.5 text-slate-500 dark:text-slate-400 text-sm">
            Identify sensitive data patterns, PII fields, and examine active masking policies.
          </p>
        </div>
        
        <div className="flex flex-wrap items-center gap-3.5">
          {/* 1. Source Type Selector */}
          <div className="relative min-w-[180px] w-full sm:w-auto">
            <Shield className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-450 dark:text-slate-500 pointer-events-none" />
            <select
              className="premium-input pl-9 pr-8 font-semibold cursor-pointer appearance-none bg-white dark:bg-slate-900"
              value={selectedSource}
              onChange={(e) => {
                setSelectedSource(e.target.value);
                setSelectedDb('');
                setSelectedTable(null);
                setActiveTableDetail(null);
              }}
            >
              <option value="">All Data Sources</option>
              {Array.from(new Set([
                ...policies.map(p => (p.source_type || 'postgres').toLowerCase()),
                ...tables.map(t => (t.source_type || 'postgres').toLowerCase())
              ])).sort().map(st => (
                <option key={st} value={st} className="capitalize">
                   {st === 'postgres' ? 'PostgreSQL' : 
                    st === 'mongodb' ? 'MongoDB' : 
                    st === 's3_storage' ? 'S3 Storage' : 
                    st === 'gcs_storage' ? 'GCS' : 
                    st === 'azure_blob' ? 'Azure Blob' : 
                    st.charAt(0).toUpperCase() + st.slice(1)}
                </option>
              ))}
            </select>
          </div>

          {/* 2. Database Name Selector */}
          <div className="relative min-w-[180px] w-full sm:w-auto">
            <Shield className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-450 dark:text-slate-500 pointer-events-none" />
            <select
              className="premium-input pl-9 pr-8 font-semibold cursor-pointer appearance-none bg-white dark:bg-slate-900 disabled:opacity-50"
              value={selectedDb}
              onChange={(e) => {
                setSelectedDb(e.target.value);
                setSelectedTable(null);
                setActiveTableDetail(null);
              }}
            >
              <option value="">Select Database...</option>
              {Array.from(new Set([
                ...policies
                  .filter(p => !selectedSource || (p.source_type || 'postgres').toLowerCase() === selectedSource.toLowerCase())
                  .map(p => (p.database_name || 'default').toLowerCase()),
                ...tables
                  .filter(t => !selectedSource || (t.source_type || 'postgres').toLowerCase() === selectedSource.toLowerCase())
                  .map(t => (t.database_name || 'default').toLowerCase())
              ])).sort().map(db => (
                <option key={db} value={db}>DB: {db}</option>
              ))}
            </select>
          </div>

          {/* 3. Table Selector */}
          <div className="relative min-w-[200px] w-full sm:w-auto">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-450 dark:text-slate-500 pointer-events-none" />
            <select
              className="premium-input pl-9 pr-8 font-semibold cursor-pointer appearance-none bg-white dark:bg-slate-900 disabled:opacity-50"
              value={selectedTable === null ? '' : selectedTable.toString()}
              onChange={(e) => {
                const val = e.target.value;
                if (val) handleTableChange(Number(val));
              }}
              disabled={!selectedDb}
            >
              <option value="">Select Table...</option>
              {tables
                .filter(t => {
                    const tSource = (t.source_type || 'postgres').toLowerCase().replace('postgresql', 'postgres');
                    const sSource = selectedSource.toLowerCase().replace('postgresql', 'postgres');
                    const tDb = (t.database_name || 'default').toLowerCase();
                    const sDb = selectedDb.toLowerCase();
                    
                    if (sSource && tSource !== sSource) return false;
                    if (sDb && sDb !== 'default' && tDb && tDb !== sDb && tDb !== 'default') return false;
                    
                    return true;
                })
                .sort((a, b) => a.name.localeCompare(b.name))
                .map(t => {
                    const hasPolicy = policies.some(p => {
                        const pSource = (p.source_type || 'postgres').toLowerCase().replace('postgresql', 'postgres');
                        const pDb = (p.database_name || 'default').toLowerCase();
                        const pResource = p.resource;
                        
                        const sourceMatch = pSource === (t.source_type || 'postgres').toLowerCase().replace('postgresql', 'postgres');
                        const dbMatch = pDb === (t.database_name || 'default').toLowerCase() || pDb === 'default';
                        const resourceMatch = pResource === '*' || pResource === t.name || (pResource.startsWith('FIELD:') && pResource.includes(t.name));
                        
                        return sourceMatch && dbMatch && resourceMatch;
                    });

                    return (
                        <option key={t.id} value={t.id.toString()}>
                            {t.name} {hasPolicy ? '🛡️' : ''}
                        </option>
                    );
                })
              }
            </select>
          </div>
          
          <div className="flex gap-2 w-full sm:w-auto">
            <button 
              onClick={handleTestInQuery}
              disabled={!selectedTable}
              className="premium-btn premium-btn-secondary gap-1.5 py-2 text-xs flex-1 sm:flex-initial"
            >
              <Play className="w-3.5 h-3.5 text-brand-indigo" />
              Query
            </button>
            <button 
              onClick={() => handlePreview()}
              disabled={!selectedTable || loadingPreview}
              className="premium-btn premium-btn-primary gap-1.5 py-2 text-xs flex-1 sm:flex-initial"
            >
              {loadingPreview ? 'Loading...' : 'Apply & Preview'}
            </button>
          </div>
        </div>
      </div>

      {selectedTable ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          {/* Policy Overview Card */}
          <div className="lg:col-span-1 space-y-6">
            <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 shadow-sm">
              <div className="bg-slate-900 dark:bg-slate-950 px-5 py-4 border-b border-slate-800">
                <h3 className="text-white font-semibold flex items-center gap-2 text-sm font-display">
                  <Shield className="w-4 h-4 text-brand-indigo" />
                  Protection Status
                </h3>
              </div>
              <div className="p-5 space-y-4 text-xs font-semibold">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Table Name</span>
                  <span className="text-slate-800 dark:text-slate-205 font-mono">{activeTableDetail?.name}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Database</span>
                  <span className="text-slate-800 dark:text-slate-205 truncate max-w-[150px]" title={(activeTableDetail as any)?.database_name || 'default'}>
                    {(activeTableDetail as any)?.database_name || 'default'}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Policy Level</span>
                  <span className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider",
                    activePolicy?.classification === 'PII' ? "bg-rose-50 dark:bg-rose-950/20 text-rose-600 dark:text-rose-400 border border-rose-100 dark:border-rose-900/60" :
                    activePolicy?.classification === 'FINANCIAL' ? "bg-amber-50 dark:bg-amber-950/20 text-amber-600 dark:text-amber-400 border border-amber-100 dark:border-amber-900/60" :
                    "bg-emerald-50 dark:bg-emerald-950/20 text-emerald-600 dark:text-emerald-400 border border-emerald-100 dark:border-emerald-900/60"
                  )}>
                    {activePolicy?.classification || 'PUBLIC'}
                  </span>
                </div>
                <hr className="border-slate-100 dark:border-slate-800/80" />
                <div className="flex items-center gap-2 text-brand-green">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{Object.keys(activePolicy?.column_policies || {}).length} Columns Masked</span>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-indigo-600 to-purple-700 rounded-xl p-5 text-white shadow-md space-y-2 animate-scale-up">
              <h4 className="font-bold text-sm flex items-center gap-1.5 font-display">
                <AlertCircle className="w-4 h-4" />
                Discovery Hint
              </h4>
              <p className="text-indigo-100 text-xs leading-relaxed font-medium">
                MetaSight scans schema attributes. Columns flagged with sensitive flags like email, phone, or SSN apply masking automatically unless overridden in system policy.
              </p>
            </div>
          </div>

          {/* Fields Table */}
          <div className="lg:col-span-2 space-y-6">
            {/* Preview Section */}
            {preview && (
              <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-indigo-500/30 border-t-2 shadow-md animate-scale-up">
                <div className="bg-slate-50 dark:bg-slate-900/60 px-5 py-3.5 flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
                      <Filter className="w-3.5 h-3.5" />
                      Preview: {preview.targetName}
                    </span>
                    <div className="flex bg-slate-100 dark:bg-slate-800 p-0.5 rounded-lg border border-slate-200/60 dark:border-slate-700/60">
                      <button 
                        onClick={() => setPreviewMode('original')}
                        className={cn(
                          "px-3 py-1 text-xs font-bold rounded-md transition-all",
                          previewMode === 'original'
                            ? "bg-white dark:bg-slate-700 text-slate-800 dark:text-slate-100 shadow-sm"
                            : "text-slate-400 hover:text-slate-650"
                        )}
                      >
                        Original
                      </button>
                      <button 
                        onClick={() => setPreviewMode('masked')}
                        className={cn(
                          "px-3 py-1 text-xs font-bold rounded-md transition-all flex items-center gap-1.5",
                          previewMode === 'masked'
                            ? "bg-brand-indigo text-white shadow-sm"
                            : "text-slate-400 hover:text-slate-650"
                        )}
                      >
                        <Shield className="w-3 h-3" />
                        Masked
                      </button>
                    </div>
                  </div>
                  <button onClick={() => setPreview(null)} className="text-slate-400 hover:text-rose-500 transition-colors">
                    <X className="w-4 h-4" />
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="bg-slate-50/50 dark:bg-slate-800/10">
                        {preview.columns.map(c => (
                          <th key={c} className="px-5 py-3 font-bold text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-mono">{c}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                      {(previewMode === 'original' ? preview.originalRows : preview.maskedRows).map((row, i) => (
                        <tr key={i} className="hover:bg-slate-50/30 dark:hover:bg-slate-800/10 transition-colors">
                          {row.map((val, j) => (
                            <td key={j} className="px-5 py-3 text-slate-600 dark:text-slate-350 font-mono">
                              {val === null ? <span className="text-slate-300 dark:text-slate-700 italic">null</span> : String(val)}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 shadow-sm animate-scale-up">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50/50 dark:bg-slate-800/20">
                      <th className="px-5 py-3.5 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">Field Name</th>
                      <th className="px-5 py-3.5 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">Type</th>
                      <th className="px-5 py-3.5 text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">Policies</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                    {loadingDetails ? (
                      [...Array(4)].map((_, i) => (
                        <tr key={i} className="animate-pulse">
                          <td colSpan={3} className="px-5 py-6">
                            <div className="h-4 bg-slate-100 dark:bg-slate-800 rounded w-full"></div>
                          </td>
                        </tr>
                      ))
                    ) : columns.map((col) => {
                      const colPolicy = activePolicy?.column_policies?.[col.name];
                      const isSensitive = !!colPolicy || col.classification === 'PII';
                      
                      return (
                        <tr key={col.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/10 transition-colors">
                          <td className="px-5 py-4">
                            <div className="flex items-center gap-2.5">
                              <div className={cn(
                                "w-1.5 h-1.5 rounded-full flex-shrink-0",
                                isSensitive ? "bg-rose-500 animate-pulse" : "bg-slate-250 dark:bg-slate-700"
                              )} />
                              <span className="font-semibold text-slate-900 dark:text-slate-100 font-mono text-xs">{col.name}</span>
                            </div>
                          </td>
                          <td className="px-5 py-4">
                            <code className="text-xs font-mono bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-350 px-2 py-0.5 rounded border border-slate-200/50 dark:border-slate-700/60">
                              {col.type}
                            </code>
                          </td>
                          <td className="px-5 py-4">
                            {isSensitive ? (
                              <div className="flex flex-wrap gap-1.5">
                                <span className="bg-rose-50 dark:bg-rose-950/20 text-rose-600 dark:text-rose-450 text-[9px] font-black uppercase px-2 py-0.5 rounded border border-rose-100 dark:border-rose-900/60 font-mono">
                                  {colPolicy?.action || 'MASKED'}
                                </span>
                                {col.pii_type && (
                                  <span className="bg-indigo-55 dark:bg-indigo-950/20 text-indigo-650 dark:text-indigo-400 text-[9px] font-black uppercase px-2 py-0.5 rounded border border-indigo-100 dark:border-indigo-900/60 font-mono">
                                    {col.pii_type}
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span className="text-slate-400 dark:text-slate-600 text-xs italic">No matching policy</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="premium-card p-16 flex flex-col items-center text-center space-y-5 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
          <div className="bg-slate-50 dark:bg-slate-950 p-6 rounded-2xl border border-slate-100 dark:border-slate-800/80">
            <TableIcon className="w-12 h-12 text-slate-300 dark:text-slate-700" />
          </div>
          <div className="space-y-1.5">
            <h2 className="text-xl font-bold text-slate-900 dark:text-slate-50 font-display">Begin Schema Discovery</h2>
            <p className="text-slate-450 dark:text-slate-400 text-xs max-w-sm mx-auto">
              Please select a database and table from the header filters to inspect specific column properties, sensitive values, and active policy definitions.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
