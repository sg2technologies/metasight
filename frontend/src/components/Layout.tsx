import React, { useState, useEffect } from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { Database, Users, Table, LogOut, Shield, BookOpen, Activity, Terminal, Settings2, ShieldCheck, FileSearch, Bot, Network, Sun, Moon, UserCog } from 'lucide-react';
import { cn } from '../lib/utils';
import { getTokenPayload } from '../api';
import { pamPlugin } from '../plugins/pam';

export function Layout() {
  const navigate = useNavigate();
  const location = useLocation();
  const payload = getTokenPayload();
  const role = payload?.role ?? '';
  const email = payload?.sub ?? '';

  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try {
      const saved = localStorage.getItem('theme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch (_) {}
    return 'dark'; // Default to dark mode for modern enterprise feel
  });

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    try {
      localStorage.setItem('theme', theme);
    } catch (_) {}
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'light' ? 'dark' : 'light');
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    navigate('/login');
  };

  const navItems = [
    { name: 'Data Sources', path: '/', icon: Database },
    { name: 'Catalog', path: '/catalog', icon: BookOpen },
    { name: 'Tables', path: '/tables', icon: Table },
    { name: 'Query', path: '/query', icon: Terminal },
    ...(role === 'admin' ? [
      { name: 'Policies', path: '/policies', icon: Shield },
      { name: 'Data Discovery', path: '/discovery', icon: BookOpen },
      { name: 'Department Management', path: '/table-management', icon: ShieldCheck },
      { name: 'Audit Log', path: '/audit', icon: Activity },
      { name: 'Governance Audit', path: '/governance-audit', icon: FileSearch },
      { name: 'Security', path: '/security', icon: ShieldCheck },
      { name: 'Agents', path: '/agents', icon: Bot },
      { name: 'Gateway Credentials', path: '/gateway-credentials', icon: Network },
      { name: 'Blocked Commands', path: '/blocked-commands', icon: Terminal },
      { name: 'Users', path: '/users', icon: Users },
      { name: 'Settings', path: '/settings', icon: Settings2 },
    ] : []),
  ];

  // PAM nav items come from a plugin registry (frontend/src/plugins/pam) —
  // empty in Community, populated by Enterprise's frontend overlay. See
  // plugins/types.ts.
  const pamItems = pamPlugin.navItems.filter(
    item => !item.requiresAdmin || role === 'admin' || role === 'superadmin'
  );

  const activeItemName = [...navItems, ...pamItems].find(n => n.path === location.pathname)?.name ?? 'Dashboard';

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 transition-colors duration-200">
      {/* ── Sidebar ───────────────────────────────────────────────────────── */}
      <aside className="w-64 flex flex-col bg-slate-950 dark:bg-slate-950 border-r border-slate-900 flex-shrink-0 z-20">

        {/* Logo / Brand */}
        <div className="flex flex-col items-center pt-6 pb-5 px-4 border-b border-slate-900">
          <img
            src="/metasight-logo.svg"
            alt="MetaSight Logo"
            className="w-10 h-auto mb-2 opacity-90 filter drop-shadow-[0_0_12px_rgba(99,102,241,0.2)]"
          />
          {/* Brand name */}
          <div className="text-center leading-tight">
            <span
              className="text-lg font-bold tracking-tight bg-gradient-to-r from-sky-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent"
            >
              MetaSight
            </span>
            <p className="text-[9px] font-bold tracking-[0.2em] text-slate-500 uppercase mt-0.5">
              DATABASE GOVERNANCE PLATFORM
            </p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.name}
                to={item.path}
                className={cn(
                  'flex items-center px-3 py-2.5 text-xs font-semibold rounded-lg transition-all duration-150 border-l-2',
                  isActive
                    ? 'text-white bg-slate-900 border-indigo-500 shadow-sm shadow-indigo-500/5'
                    : 'text-slate-400 hover:text-white hover:bg-slate-900/60 border-transparent'
                )}
              >
                <Icon
                  className={cn(
                    'mr-3 flex-shrink-0 h-4 w-4 transition-colors',
                    isActive ? 'text-indigo-400' : 'text-slate-500 hover:text-slate-300'
                  )}
                />
                {item.name}
              </Link>
            );
          })}

          {/* PAM Section — omitted entirely when the plugin has no nav items
              (Community edition) rather than showing an empty heading. */}
          {pamItems.length > 0 && (
            <>
              <div className="pt-4 pb-1">
                <p className="px-3 text-[9px] font-bold tracking-[0.18em] text-slate-500 uppercase">
                  {pamPlugin.sectionLabel}
                </p>
              </div>
              {pamItems.map((item) => {
                const Icon = item.icon;
                const isActive = location.pathname === item.path;
                return (
                  <Link
                    key={item.name}
                    to={item.path}
                    className={cn(
                      'flex items-center px-3 py-2.5 text-xs font-semibold rounded-lg transition-all duration-150 border-l-2',
                      isActive
                        ? 'text-white bg-slate-900 border-red-500 shadow-sm shadow-red-500/5'
                        : 'text-slate-400 hover:text-white hover:bg-slate-900/60 border-transparent'
                    )}
                  >
                    <Icon
                      className={cn(
                        'mr-3 flex-shrink-0 h-4 w-4 transition-colors',
                        isActive ? 'text-red-400' : 'text-slate-500 hover:text-slate-300'
                      )}
                    />
                    {item.name}
                  </Link>
                );
              })}
            </>
          )}
        </nav>

        {/* User info + Theme Toggle + Logout */}
        <div className="p-4 border-t border-slate-900 space-y-3">
          {email && (
            <div className="px-3 py-2.5 rounded-lg bg-slate-900/80 border border-slate-900">
              <p className="text-[10px] text-slate-400 truncate font-mono">{email}</p>
              <div className="flex items-center gap-2 mt-1.5">
                <span
                  className={cn(
                    "inline-block text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded",
                    role === 'admin' || role === 'superadmin'
                      ? 'bg-gradient-to-r from-indigo-500 to-purple-500 text-white'
                      : 'bg-gradient-to-r from-sky-500 to-indigo-500 text-white'
                  )}
                >
                  {role}
                </span>
                {role !== 'admin' && payload?.department_id && (
                  <span className="text-[9px] font-bold text-slate-400 uppercase tracking-widest border border-slate-800 px-1.5 py-0.5 rounded">
                    Dept: {payload.department_id}
                  </span>
                )}
              </div>
            </div>
          )}

          <div className="flex gap-2">
            <button
              onClick={toggleTheme}
              className="flex-1 flex items-center justify-center p-2 rounded-lg bg-slate-900 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-900 transition-colors"
              title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
            >
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>

            <Link
              to="/my-account"
              className="flex-1 flex items-center justify-center p-2 rounded-lg bg-slate-900 text-slate-400 hover:text-white hover:bg-slate-800 border border-slate-900 transition-colors"
              title="My Account"
            >
              <UserCog className="h-4 w-4" />
            </Link>

            <button
              onClick={handleLogout}
              className="flex-1 flex items-center justify-center p-2 rounded-lg bg-slate-900 text-slate-400 hover:text-red-400 hover:bg-red-500/10 border border-slate-900 transition-colors"
              title="Logout"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main Content ──────────────────────────────────────────────────── */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="h-14 flex items-center justify-between px-8 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 transition-colors duration-200">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-slate-500 dark:text-slate-400">MetaSight</span>
            <span className="text-slate-300 dark:text-slate-700">/</span>
            <span className="text-sm text-slate-800 dark:text-slate-200 font-bold">
              {activeItemName}
            </span>
          </div>
          <div className="flex items-center gap-3">
            {role && (
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                {role.toUpperCase()} Workspace
              </span>
            )}
          </div>
        </header>

        <div className="flex-1 overflow-auto py-6 px-8 bg-slate-50 dark:bg-slate-950 transition-colors duration-200">
          <div className="max-w-7xl mx-auto animate-fade-in">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}

