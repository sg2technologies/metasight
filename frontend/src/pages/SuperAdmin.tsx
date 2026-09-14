import React, { useState, useEffect } from 'react';
import { api, isSuperAdmin } from '../api';
import { Navigate, useNavigate } from 'react-router-dom';
import { LogOut, Plus, Search, Building2, User } from 'lucide-react';
import { cn } from '../lib/utils';

export function SuperAdmin() {
  const navigate = useNavigate();
  if (!isSuperAdmin()) return <Navigate to="/" replace />;

  const [tenants, setTenants] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);
  const [expandedTenantId, setExpandedTenantId] = useState<number | null>(null);
  
  // Form State
  const [tenantName, setTenantName] = useState('');
  const [adminEmail, setAdminEmail] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [error, setError] = useState('');
  const [formLoading, setFormLoading] = useState(false);

  const fetchTenants = async () => {
    try {
      setLoading(true);
      const res = await api.get('/superadmin/tenants');
      setTenants(res.data.items);
    } catch (err: any) {
      setError('Failed to fetch tenants');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTenants();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    window.location.href = '/login';
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormLoading(true);
    setError('');
    try {
      await api.post('/superadmin/tenants', {
        tenant_name: tenantName,
        admin_email: adminEmail,
        admin_password: adminPassword
      });
      setCreating(false);
      setTenantName('');
      setAdminEmail('');
      setAdminPassword('');
      fetchTenants();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create tenant');
    } finally {
      setFormLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-100 transition-colors duration-200">
      {/* Super Admin Topbar navigation */}
      <nav className="sticky top-0 z-20 backdrop-blur-md bg-indigo-950/95 dark:bg-slate-900 border-b border-indigo-900 dark:border-slate-800 flex-shrink-0 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2.5">
              <Building2 className="h-6 w-6 text-indigo-400" />
              <span className="text-white font-bold text-lg tracking-tight font-display flex items-center gap-2">
                MetaSight <span className="text-xs bg-indigo-500/20 dark:bg-indigo-500/10 text-indigo-300 px-2 py-0.5 rounded border border-indigo-500/30">SuperAdmin Dashboard</span>
              </span>
            </div>
            <div>
              <button
                onClick={handleLogout}
                className="text-indigo-200 hover:text-white dark:text-slate-400 dark:hover:text-white transition-colors flex items-center gap-2 text-sm font-semibold hover:scale-102 active:scale-98"
              >
                <LogOut className="h-4 w-4" />
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content Portal */}
      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 animate-fade-in">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2">
          <div>
            <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-3">
              <span>Organizations Control</span>
            </h1>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              Manage multi-tenant organizations, billing boundaries, and system administrators.
            </p>
          </div>
          
          {!creating && (
            <button
              onClick={() => setCreating(true)}
              className="premium-btn-primary gap-1.5 self-start sm:self-auto"
            >
              <Plus className="h-4 w-4" /> 
              New Tenant Organization
            </button>
          )}
        </div>

        {error && (
          <div className="px-4 py-3 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-455 text-sm font-medium rounded-lg border border-rose-100 dark:border-rose-900/20 animate-scale-up">
            {error}
          </div>
        )}

        {/* Tenant Creation Form Modal/Card */}
        {creating && (
          <div className="premium-card overflow-hidden animate-slide-up">
            <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-800 flex justify-between items-center">
              <h3 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <Plus className="w-5 h-5 text-brand-indigo" />
                <span>Create New Tenant Workspace</span>
              </h3>
              <button 
                type="button" 
                onClick={() => setCreating(false)} 
                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-205 text-xs font-semibold"
              >
                ✕ Close Panel
              </button>
            </div>
            
            <form onSubmit={handleCreate} className="p-6 space-y-5">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="block text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Organization / Tenant Name</label>
                  <input
                    required
                    type="text"
                    value={tenantName}
                    onChange={(e) => setTenantName(e.target.value)}
                    placeholder="e.g. Acme Corporation"
                    className="premium-input font-medium"
                  />
                </div>
              </div>
              
              <div className="bg-slate-50 dark:bg-slate-900/50 p-5 rounded-xl border border-slate-200 dark:border-slate-800 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="col-span-1 md:col-span-2">
                  <h4 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <User className="h-4 w-4 text-brand-indigo" /> 
                    <span>Initial Organization Administrator</span>
                  </h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">This credentials set will be instantiated as the tenant root administrator.</p>
                </div>
                
                <div className="space-y-1.5">
                  <label className="block text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Admin Account Email</label>
                  <input
                    required
                    type="email"
                    value={adminEmail}
                    onChange={(e) => setAdminEmail(e.target.value)}
                    placeholder="admin@acme.com"
                    className="premium-input font-medium"
                  />
                </div>
                
                <div className="space-y-1.5">
                  <label className="block text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider">Admin Secure Password</label>
                  <input
                    required
                    type="password"
                    value={adminPassword}
                    onChange={(e) => setAdminPassword(e.target.value)}
                    placeholder="Choose secure password..."
                    className="premium-input font-medium"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-slate-150 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => setCreating(false)}
                  className="premium-btn-secondary"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={formLoading}
                  className="premium-btn-primary disabled:opacity-50"
                >
                  {formLoading ? 'Provisioning Tenant Workspace...' : 'Create Tenant Workspace'}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Datagrid Table */}
        <div className="premium-card overflow-hidden">
          <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Registered Organizations & Tenants
            </h2>
            <span className="premium-badge bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-350 border border-slate-200 dark:border-slate-700">
              {tenants.length} tenants
            </span>
          </div>

          {loading ? (
            <div className="p-12 text-center text-slate-450 dark:text-slate-500 animate-pulse">
              Querying register organizations...
            </div>
          ) : tenants.length === 0 ? (
            <div className="p-16 text-center text-slate-400 dark:text-slate-500">
              <Building2 className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p className="font-semibold text-slate-700 dark:text-slate-300">No tenants created yet.</p>
              <p className="text-xs text-slate-400 dark:text-slate-500 mt-1">Create your first organization above to start platform services.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse border-spacing-0 text-sm">
                <thead>
                  <tr className="bg-slate-50 dark:bg-slate-900/50 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase border-b border-slate-200 dark:border-slate-800 tracking-wider">
                    <th className="px-6 py-3.5">Tenant Organization</th>
                    <th className="px-6 py-3.5">Date Created</th>
                    <th className="px-6 py-3.5 text-center">Root Admins</th>
                    <th className="px-6 py-3.5">Registered Users</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-850/80">
                  {tenants.map((t) => (
                    <React.Fragment key={t.id}>
                      <tr 
                        onClick={() => setExpandedTenantId(expandedTenantId === t.id ? null : t.id)} 
                        className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 cursor-pointer transition-colors"
                      >
                        <td className="px-6 py-4.5 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-9 w-9 rounded-xl bg-indigo-50 dark:bg-indigo-950/40 text-brand-indigo border border-indigo-150/40 dark:border-indigo-900/10 flex items-center justify-center font-bold">
                              {t.name.substring(0, 2).toUpperCase()}
                            </div>
                            <div className="ml-3.5">
                              <div className="font-bold text-slate-900 dark:text-white">{t.name}</div>
                              <div className="text-[10px] text-slate-400 dark:text-slate-500 font-mono mt-0.5">UUID: {t.id}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4.5 whitespace-nowrap text-slate-500 dark:text-slate-400">
                          {new Date(t.created_at).toLocaleDateString()}
                        </td>
                        <td className="px-6 py-4.5 whitespace-nowrap text-center">
                          <span className="premium-badge bg-purple-50 dark:bg-purple-950/20 text-brand-purple dark:text-purple-400 border border-purple-100 dark:border-purple-900/10 font-bold">
                            {t.admin_count} admins
                          </span>
                        </td>
                        <td className="px-6 py-4.5 whitespace-nowrap text-slate-500 dark:text-slate-400">
                          <div className="flex items-center justify-between gap-4">
                            <span className="font-semibold text-slate-700 dark:text-slate-300">{t.user_count} total</span>
                            <span className="text-xs text-brand-indigo hover:text-brand-indigo/80 font-bold">
                              {expandedTenantId === t.id ? 'Hide Details' : 'Expand Users'}
                            </span>
                          </div>
                        </td>
                      </tr>
                      
                      {expandedTenantId === t.id && (
                        <tr className="bg-slate-50/50 dark:bg-slate-900/20">
                          <td colSpan={4} className="px-8 py-5">
                            <div className="space-y-3 max-w-3xl">
                              <h4 className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider flex items-center gap-2">
                                <User className="h-4 w-4 text-brand-indigo" /> 
                                <span>Authorized Users Checklist</span>
                              </h4>
                              
                              <div className="premium-card overflow-hidden bg-white dark:bg-slate-900">
                                <table className="w-full text-left border-collapse border-spacing-0">
                                  <thead>
                                    <tr className="bg-slate-50/50 dark:bg-slate-900/20 text-xs font-semibold text-slate-550 dark:text-slate-455 border-b border-slate-200 dark:border-slate-800">
                                      <th className="px-4 py-2">User Email Address</th>
                                      <th className="px-4 py-2">Assigned System Role</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-slate-150 dark:divide-slate-850/80 text-xs font-semibold text-slate-700 dark:text-slate-300">
                                    {t.users?.map((u: any) => (
                                      <tr key={u.id}>
                                        <td className="px-4 py-2.5 font-mono">{u.email}</td>
                                        <td className="px-4 py-2.5 whitespace-nowrap">
                                          <span className={cn(
                                            'premium-badge text-[9px]', 
                                            u.role === 'admin' 
                                              ? 'bg-purple-50 dark:bg-purple-950/20 text-brand-purple dark:text-purple-400 border border-purple-100 dark:border-purple-900/10' 
                                              : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700'
                                          )}>
                                            {u.role}
                                          </span>
                                        </td>
                                      </tr>
                                    ))}
                                    {(!t.users || t.users.length === 0) && (
                                      <tr>
                                        <td colSpan={2} className="px-4 py-4 text-center text-slate-400 italic font-medium">No users mapped inside this organization.</td>
                                      </tr>
                                    )}
                                  </tbody>
                                </table>
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
        </div>
      </main>
    </div>
  );
}
