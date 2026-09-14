import React, { useState, useEffect } from 'react';
import { Search, Activity, ChevronDown, ChevronUp } from 'lucide-react';
import { api, isAdmin } from '../api';
import { cn } from '../lib/utils';
import { Navigate } from 'react-router-dom';

const ACTION_COLORS: Record<string, string> = {
  query: 'bg-blue-100 dark:bg-blue-950/40 text-blue-800 dark:text-blue-400 border border-blue-200 dark:border-blue-900/40',
  policy_change: 'bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-400 border border-amber-200 dark:border-amber-900/40',
  detokenize: 'bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-400 border border-red-200 dark:border-red-900/40',
  classify: 'bg-purple-100 dark:bg-purple-950/40 text-purple-800 dark:text-purple-400 border border-purple-200 dark:border-purple-900/40',
};

export function AuditLog() {
  if (!isAdmin()) return <Navigate to="/" replace />;

  const [logs, setLogs] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filterResource, setFilterResource] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [page, setPage] = useState(0);
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);
  const limit = 50;

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const params: any = { skip: page * limit, limit };
      if (filterResource) params.resource = filterResource;
      if (filterAction) params.action = filterAction;
      const res = await api.get('/audit', { params });
      setLogs(res.data.items || []);
      setTotal(res.data.total || 0);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    setExpandedLogId(null);
  }, [filterResource, filterAction, page]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">Audit Log</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">Monitor real-time access requests, modified query logs, and detokenize events.</p>
        </div>
        <div className="text-xs font-semibold px-2.5 py-1.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 uppercase tracking-wider">{total} total events</div>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 px-4 py-3 rounded-lg text-sm">{error}</div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative max-w-xs flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400 dark:text-slate-500" />
          <input
            type="text" placeholder="Filter by resource..."
            value={filterResource} onChange={(e) => { setFilterResource(e.target.value); setPage(0); }}
            className="premium-input pl-9"
          />
        </div>
        <select value={filterAction} onChange={(e) => { setFilterAction(e.target.value); setPage(0); }}
          className="bg-white dark:bg-slate-900 border border-slate-250 dark:border-slate-700 text-slate-800 dark:text-slate-205 rounded-lg px-3 py-2 text-sm outline-none focus:border-brand-indigo transition-all min-w-[160px]"
        >
          <option value="">All actions</option>
          <option value="query">query</option>
          <option value="policy_change">policy_change</option>
          <option value="detokenize">detokenize</option>
          <option value="classify">classify</option>
        </select>
      </div>

      <div className="premium-card overflow-hidden flex flex-col bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
        {loading ? (
          <div className="p-8 text-center text-slate-500 dark:text-slate-400">
            <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-brand-indigo" />
            <p className="text-sm">Loading audit events list…</p>
          </div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center text-slate-400 dark:text-slate-500">
            <Activity className="h-12 w-12 mx-auto mb-3 opacity-30 animate-pulse" />
            <p className="font-semibold text-slate-800 dark:text-slate-200">No audit events found.</p>
            <p className="text-xs mt-1">Audit events will be logged once database queries are processed.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/40 border-b border-slate-200 dark:border-slate-800">
                <tr className="text-slate-500 dark:text-slate-400 uppercase text-[10px] font-bold tracking-wider">
                  <th className="px-4 py-3 text-left">Time</th>
                  <th className="px-4 py-3 text-left">User</th>
                  <th className="px-4 py-3 text-left">Role</th>
                  <th className="px-4 py-3 text-left">Action</th>
                  <th className="px-4 py-3 text-left">Resource</th>
                  <th className="px-4 py-3 text-left">Policy</th>
                  <th className="px-4 py-3 text-left">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-150 dark:divide-slate-800/50">
                {logs.map((log) => (
                  <React.Fragment key={log.id}>
                    <tr
                      className="hover:bg-slate-50/50 dark:hover:bg-slate-800/20 cursor-pointer transition-colors"
                      onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
                    >
                      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-450 font-mono whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 text-xs font-semibold text-slate-805 dark:text-slate-200 truncate max-w-[160px]">
                        {log.user_email}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-bold uppercase tracking-wider bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 px-2 py-0.5 rounded text-slate-600 dark:text-slate-350">{log.role}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={cn('inline-flex px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider', ACTION_COLORS[log.action] ?? 'bg-slate-100 text-slate-750')}>
                          {log.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-brand-indigo dark:text-indigo-400 font-bold">{log.resource}</td>
                      <td className="px-4 py-3 text-xs text-slate-500 dark:text-slate-400 font-medium">{log.policy_applied ?? '—'}</td>
                      <td className="px-4 py-3 text-xs text-slate-400 dark:text-slate-500 max-w-[200px] truncate" title={log.original_query ?? ''}>
                        <div className="flex items-center gap-1.5 justify-between">
                          <span className="truncate max-w-[150px] font-mono text-xs">{log.original_query ?? '—'}</span>
                          {log.original_query && (expandedLogId === log.id ? <ChevronUp className="h-3.5 w-3.5 text-slate-405 flex-shrink-0" /> : <ChevronDown className="h-3.5 w-3.5 text-slate-405 flex-shrink-0" />)}
                        </div>
                      </td>
                    </tr>
                    {expandedLogId === log.id && (
                      <tr className="bg-slate-50/30 dark:bg-slate-900/30">
                        <td colSpan={7} className="px-5 py-4">
                          <div className="space-y-4 text-xs animate-slide-up">
                            {log.original_query && (
                              <div>
                                <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Original Query</p>
                                <pre className="bg-slate-950 text-slate-100 border border-slate-800 rounded-lg p-3 whitespace-pre-wrap break-all font-mono leading-relaxed select-all">{log.original_query}</pre>
                              </div>
                            )}
                            {log.rewritten_query && log.rewritten_query !== log.original_query && (
                              <div>
                                <p className="font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-1.5 text-[9px]">Rewritten Query</p>
                                <pre className="bg-slate-950 text-indigo-300 border border-indigo-950/60 rounded-lg p-3 whitespace-pre-wrap break-all font-mono leading-relaxed select-all">{log.rewritten_query}</pre>
                              </div>
                            )}
                            <div className="flex flex-wrap gap-4 pt-1 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                              <span>Row Count: <strong className="text-slate-800 dark:text-slate-200">{log.row_count !== null ? log.row_count : '—'}</strong></span>
                              <span>Action type: <strong className="text-slate-800 dark:text-slate-205">{log.action}</strong></span>
                              <span>Policy Applied: <strong className="text-slate-800 dark:text-slate-205">{log.policy_applied ?? '—'}</strong></span>
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

        {/* Pagination */}
        {total > limit && (
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
        )}
      </div>
    </div>
  );
}

// Simple loader helper import workaround inside AuditLog file
import { RefreshCw } from 'lucide-react';
