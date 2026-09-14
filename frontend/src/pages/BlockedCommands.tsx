import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import {
  ShieldAlert, Terminal, Camera, RefreshCw, Play, Pause, Search,
  Database, User, Globe, Calendar, AlertTriangle, Loader2, Eye,
  EyeOff, Download, ExternalLink, ShieldCheck, HelpCircle
} from 'lucide-react';
import { cn } from '../lib/utils';

interface ScreenshotInfo {
  id: string;
  session_id: string;
  captured_at: string;
  active_window: string | null;
  active_app: string | null;
  file_size: number;
  checksum: string;
  risk_flag: boolean;
}

interface BlockedCommand {
  id: number;
  agent_id: number;
  source_id: number | null;
  db_type: string;
  session_pid: string | null;
  db_user: string;
  client_ip: string;
  app_name: string | null;
  database: string | null;
  current_sql: string;
  state: string | null;
  blocked: boolean;
  acknowledged: boolean;
  timestamp: string;
  screenshot: ScreenshotInfo | null;
}

export function BlockedCommands() {
  const [commands, setCommands] = useState<BlockedCommand[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Real-time auto-refresh settings
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshIntervalSec, setRefreshIntervalSec] = useState(5);
  const [countdown, setCountdown] = useState(5);
  
  // Search and filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [filterUser, setFilterUser] = useState('');
  const [filterDb, setFilterDb] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'captured' | 'pending'>('all');
  
  // UI states
  const [expandedSql, setExpandedSql] = useState<Record<number, boolean>>({});
  const [selectedScreenshot, setSelectedScreenshot] = useState<ScreenshotInfo | null>(null);

  const fetchCommands = useCallback(async (showLoading = false) => {
    try {
      if (showLoading) setLoading(true);
      const res = await api.get('/agents/blocked-commands', { params: { limit: 150 } });
      setCommands(res.data);
      setError('');
    } catch (e: any) {
      console.error(e);
      setError(e.response?.data?.detail || 'Failed to fetch blocked commands');
    } finally {
      if (showLoading) setLoading(false);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchCommands(true);
  }, [fetchCommands]);

  // Handle auto-refresh interval
  useEffect(() => {
    if (!autoRefresh) return;
    setCountdown(refreshIntervalSec);
    
    const interval = setInterval(() => {
      setCountdown(prev => {
        if (prev <= 1) {
          fetchCommands(false);
          return refreshIntervalSec;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [autoRefresh, refreshIntervalSec, fetchCommands]);

  // Filter commands
  const filteredCommands = commands.filter(cmd => {
    const matchesSearch = 
      (cmd.current_sql || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (cmd.db_user || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (cmd.client_ip || '').toLowerCase().includes(searchTerm.toLowerCase());
      
    const matchesUser = !filterUser || (cmd.db_user || '').toLowerCase().includes(filterUser.toLowerCase());
    const matchesDb = !filterDb || (cmd.database || '').toLowerCase().includes(filterDb.toLowerCase());
    
    const matchesStatus = 
      filterStatus === 'all' ||
      (filterStatus === 'captured' && cmd.screenshot !== null) ||
      (filterStatus === 'pending' && cmd.screenshot === null);
      
    return matchesSearch && matchesUser && matchesDb && matchesStatus;
  });

  // Calculate statistics
  const totalBlocked = commands.length;
  const capturedCount = commands.filter(c => c.screenshot !== null).length;
  const pendingCount = totalBlocked - capturedCount;

  // Generate screenshot image URL
  const getScreenshotUrl = (shot: ScreenshotInfo) => {
    const baseUrl = api.defaults.baseURL || 'http://localhost:8000';
    const sessId = shot.session_id || 'unlinked';
    return `${baseUrl}/pam/sessions/${sessId}/screenshots/${shot.id}/image?token=${localStorage.getItem('token')}`;
  };

  return (
    <div className="space-y-6 animate-fade-in text-slate-800 dark:text-slate-100">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-100 dark:border-slate-800 pb-5">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl flex items-center justify-center shadow-lg" style={{ background: 'linear-gradient(135deg,#ef4444,#dc2626)' }}>
            <ShieldAlert className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-50 font-display">Blocked Commands Monitor</h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              Real-time feed of blocked database statements and associated client workstation screen captures.
            </p>
          </div>
        </div>
        
        {/* Controls */}
        <div className="flex items-center gap-3 self-start sm:self-auto">
          {/* Auto Refresh Status Ticker */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs font-mono">
            {autoRefresh ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span className="text-emerald-400 font-semibold">Live Feed ({countdown}s)</span>
              </>
            ) : (
              <>
                <span className="h-2 w-2 rounded-full bg-slate-600"></span>
                <span className="text-slate-400 font-semibold">Paused</span>
              </>
            )}
          </div>

          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={cn(
              "p-2 rounded-lg border transition-all active:scale-95",
              autoRefresh 
                ? "border-amber-200/60 dark:border-amber-900/50 bg-amber-500/10 text-amber-500 hover:bg-amber-500/20"
                : "border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-900"
            )}
            title={autoRefresh ? "Pause Auto Refresh" : "Resume Auto Refresh"}
          >
            {autoRefresh ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          </button>

          <button
            onClick={() => fetchCommands(true)}
            className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-900 text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition-all active:scale-95"
            title="Force Reload Now"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {error && (
        <div className="px-4 py-3 bg-rose-50 dark:bg-rose-950/20 text-rose-600 dark:text-rose-455 text-sm font-medium rounded-lg border border-rose-100 dark:border-rose-900/20 animate-scale-up">
          {error}
        </div>
      )}

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 shadow-sm">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-red-50 dark:bg-red-950/20 border border-red-100 dark:border-red-900/60">
            <ShieldAlert className="h-5 w-5 text-brand-red" />
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Total Blocked</p>
            <p className="text-xl font-bold text-slate-900 dark:text-slate-50 mt-0.5">{totalBlocked}</p>
          </div>
        </div>

        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 shadow-sm">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-purple-50 dark:bg-purple-950/20 border border-purple-100 dark:border-purple-900/60">
            <Camera className="h-5 w-5 text-brand-purple" />
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Screenshots Captured</p>
            <p className="text-xl font-bold text-slate-900 dark:text-slate-50 mt-0.5">{capturedCount}</p>
          </div>
        </div>

        <div className="premium-card p-4 flex items-center gap-4 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 shadow-sm">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-amber-50 dark:bg-amber-950/20 border border-amber-100 dark:border-amber-900/60">
            {pendingCount > 0 ? (
              <Loader2 className="h-5 w-5 text-brand-orange animate-spin" />
            ) : (
              <ShieldCheck className="h-5 w-5 text-brand-green" />
            )}
          </div>
          <div>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-semibold font-display">Capture Pending</p>
            <p className="text-xl font-bold text-slate-900 dark:text-slate-50 mt-0.5">{pendingCount}</p>
          </div>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="flex items-center justify-between flex-wrap gap-4 bg-white dark:bg-slate-900 p-4 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div className="flex items-center gap-2 flex-grow max-w-md">
          <div className="relative w-full">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by SQL, user or IP..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="premium-input pl-9"
            />
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-400 font-medium">User:</span>
            <input
              type="text"
              placeholder="All users"
              value={filterUser}
              onChange={e => setFilterUser(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800/80 focus:border-brand-indigo outline-none"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-400 font-medium">Database:</span>
            <input
              type="text"
              placeholder="All DBs"
              value={filterDb}
              onChange={e => setFilterDb(e.target.value)}
              className="bg-slate-50 dark:bg-slate-950 text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800/80 focus:border-brand-indigo outline-none"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-xs text-slate-400 font-medium">Capture:</span>
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value as any)}
              className="bg-slate-50 dark:bg-slate-950 text-xs px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800/80 focus:border-brand-indigo outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="captured">Captured Only</option>
              <option value="pending">Pending Only</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Feed List */}
      <div className="space-y-4">
        {loading && commands.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-3 text-slate-400">
            <Loader2 className="h-8 w-8 animate-spin text-brand-indigo" />
            <span className="text-xs font-semibold">Scanning direct DB connections and query gateway events...</span>
          </div>
        ) : filteredCommands.length === 0 ? (
          <div className="premium-card p-16 text-center text-slate-450 dark:text-slate-500 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 flex flex-col items-center justify-center gap-3">
            <div className="h-12 w-12 rounded-full bg-slate-50 dark:bg-slate-950 flex items-center justify-center">
              <ShieldCheck className="h-6 w-6 text-brand-green" />
            </div>
            <div>
              <p className="text-sm font-semibold text-slate-850 dark:text-slate-200">No Blocked SQL Events</p>
              <p className="text-xs mt-1 text-slate-400 dark:text-slate-500">
                All database activity conforms to policies. No blocked operations detected.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-4 animate-scale-up">
            {filteredCommands.map(cmd => {
              const isExpanded = !!expandedSql[cmd.id];
              const isCaptured = cmd.screenshot !== null;
              
              return (
                <div 
                  key={cmd.id} 
                  className={cn(
                    "rounded-xl border overflow-hidden transition-all shadow-sm border-l-4",
                    isCaptured
                      ? "bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 border-l-brand-purple"
                      : "bg-amber-50/15 dark:bg-amber-950/5 border-amber-200/50 dark:border-amber-900/40 border-l-brand-orange"
                  )}
                >
                  <div className="p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                    <div className="flex-1 space-y-2">
                      {/* Meta Tags */}
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-black uppercase tracking-wider text-red-500 flex items-center gap-1 bg-red-500/10 px-2 py-0.5 rounded-lg border border-red-500/20">
                          <Terminal className="h-3 w-3" /> Blocked
                        </span>
                        
                        <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-805 border border-slate-200 dark:border-slate-700 text-slate-550 dark:text-slate-400 font-mono">
                          {cmd.db_type}
                        </span>
                        
                        {cmd.app_name && (
                          <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full bg-indigo-50/50 dark:bg-indigo-950/20 border border-indigo-200/30 dark:border-indigo-900/40 text-brand-indigo dark:text-indigo-400">
                            {cmd.app_name}
                          </span>
                        )}
                        
                        {isCaptured ? (
                          <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full bg-purple-50 dark:bg-purple-950/30 border border-purple-200/30 dark:border-purple-900/40 text-brand-purple dark:text-purple-400 flex items-center gap-1">
                            <Camera className="h-3 w-3" /> Workstation Screen Captured
                          </span>
                        ) : (
                          <span className="text-[9px] font-bold uppercase px-2 py-0.5 rounded-full bg-amber-50 dark:bg-amber-950/30 border border-amber-200/30 dark:border-amber-900/40 text-brand-orange dark:text-amber-400 flex items-center gap-1.5 animate-pulse">
                            <Loader2 className="h-3 w-3 animate-spin" /> Screen Capture Pending
                          </span>
                        )}
                      </div>

                      {/* Header details */}
                      <div className="text-sm font-medium text-slate-800 dark:text-slate-200 leading-relaxed">
                        User <span className="font-mono font-bold text-slate-900 dark:text-white bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded text-xs">{cmd.db_user}</span> from <span className="font-mono font-bold text-slate-900 dark:text-white bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded text-xs">{cmd.client_ip}</span>
                        {cmd.database && <> on database <span className="text-slate-950 dark:text-slate-100 font-semibold">{cmd.database}</span></>}
                      </div>

                      <div className="flex items-center gap-4 text-xs text-slate-450 dark:text-slate-500 font-mono">
                        <span className="flex items-center gap-1"><Calendar className="h-3.5 w-3.5" /> {new Date(cmd.timestamp).toLocaleString()}</span>
                        {cmd.session_pid && <span>PID: {cmd.session_pid}</span>}
                      </div>

                      {/* SQL Code Block */}
                      <div className="mt-2.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Statement:</span>
                          <button 
                            onClick={() => setExpandedSql(prev => ({ ...prev, [cmd.id]: !prev[cmd.id] }))}
                            className="text-xs text-brand-indigo dark:text-indigo-400 font-bold flex items-center gap-1 active:scale-95 transition-all"
                          >
                            {isExpanded ? (
                              <>Collapse <EyeOff className="h-3 w-3" /></>
                            ) : (
                              <>View SQL <Eye className="h-3 w-3" /></>
                            )}
                          </button>
                        </div>
                        {isExpanded && (
                          <div className="mt-1.5 rounded-xl overflow-hidden bg-slate-950 dark:bg-slate-950 border border-slate-200 dark:border-slate-800/80">
                            <pre className="p-4 text-xs text-slate-300 overflow-x-auto leading-relaxed whitespace-pre-wrap font-mono select-all">
                              {cmd.current_sql}
                            </pre>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Screenshot Viewer Trigger Button */}
                    <div className="flex items-center justify-end flex-shrink-0 lg:border-l lg:border-slate-200/60 dark:border-slate-800/60 lg:pl-6">
                      {isCaptured ? (
                        <button
                          onClick={() => setSelectedScreenshot(cmd.screenshot)}
                          className="premium-btn-primary bg-gradient-to-r from-purple-600 to-indigo-600 border-none hover:shadow-lg hover:shadow-indigo-500/10 gap-2 text-xs py-2 px-4 shadow-sm"
                        >
                          <Camera className="h-4 w-4" />
                          View Screen Capture
                        </button>
                      ) : (
                        <div className="flex flex-col items-center justify-center p-3 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 max-w-[200px] text-center">
                          <HelpCircle className="h-4.5 w-4.5 text-slate-400 dark:text-slate-500 mb-1" />
                          <p className="text-[10px] text-slate-450 dark:text-slate-500 leading-normal">
                            Workstation agent is polling. Capture will appear automatically.
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Screenshot Modal Viewer ────────────────────────────────────── */}
      {selectedScreenshot && (
        <div 
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in"
          onClick={() => setSelectedScreenshot(null)}
        >
          <div 
            className="w-full max-w-5xl bg-white dark:bg-slate-900 rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col max-h-[90vh] animate-scale-up"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-100 dark:border-slate-805 bg-slate-50/50 dark:bg-slate-900/60">
              <div className="flex items-center gap-3">
                <Camera className="h-5 w-5 text-brand-purple" />
                <div>
                  <h3 className="font-bold text-slate-900 dark:text-white text-sm">Workstation Desktop Screenshot</h3>
                  <p className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
                    Captured from user's machine on violation trigger.
                  </p>
                </div>
              </div>
              <button 
                onClick={() => setSelectedScreenshot(null)} 
                className="text-slate-400 hover:text-slate-700 dark:hover:text-white text-xl font-bold transition-all px-2 active:scale-95"
              >
                ×
              </button>
            </div>

            {/* Content / Image Display */}
            <div className="flex-1 overflow-auto bg-slate-950 flex items-center justify-center p-4 min-h-[40vh] relative group">
              <img 
                src={getScreenshotUrl(selectedScreenshot)}
                alt={selectedScreenshot.active_window || 'User Workstation Screen'}
                className="max-h-[60vh] object-contain rounded-lg border border-slate-800 shadow-xl"
              />
            </div>

            {/* Footer / Metadata details */}
            <div className="border-t border-slate-100 dark:border-slate-805 bg-slate-50/50 dark:bg-slate-900/50 px-6 py-4.5 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider">Active App</span>
                <p className="font-bold text-slate-800 dark:text-slate-200 truncate">{selectedScreenshot.active_app || 'N/A'}</p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider">Active Window</span>
                <p className="font-bold text-slate-800 dark:text-slate-200 truncate" title={selectedScreenshot.active_window || ''}>{selectedScreenshot.active_window || 'N/A'}</p>
              </div>
              <div className="space-y-1">
                <span className="text-[10px] text-slate-400 dark:text-slate-500 font-bold uppercase tracking-wider">Captured Time</span>
                <p className="font-bold text-slate-800 dark:text-slate-200 font-mono">{new Date(selectedScreenshot.captured_at).toLocaleString()}</p>
              </div>
              <div className="flex items-center justify-end gap-2.5">
                <a 
                  href={getScreenshotUrl(selectedScreenshot)} 
                  download={`screenshot-${selectedScreenshot.id}.png`}
                  className="premium-btn-primary bg-gradient-to-r from-indigo-500 to-indigo-600 border-none hover:shadow-indigo-550/10 flex items-center gap-1.5 text-xs py-2 px-3 shadow-sm"
                >
                  <Download className="h-3.5 w-3.5" /> Download
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
