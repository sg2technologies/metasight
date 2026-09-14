import React, { useState, useEffect } from 'react';
import { Plus, Trash2, User, Mail, Shield, ShieldCheck, HelpCircle } from 'lucide-react';
import { api, getTokenPayload } from '../api';
import { Navigate } from 'react-router-dom';

export function Users() {
  const payload = getTokenPayload();
  if (payload?.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  const [users, setUsers] = useState<any[]>([]);
  const [departments, setDepartments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [newUser, setNewUser] = useState({ email: '', password: '', role: 'analyst', department_id: '' });

  const fetchData = async () => {
    try {
      setLoading(true);
      const [userRes, deptRes] = await Promise.all([
        api.get('/users'),
        api.get('/catalog/departments')
      ]);
      setUsers(userRes.data || []);
      setDepartments(deptRes.data || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    try {
      const payload = {
        ...newUser,
        department_id: newUser.department_id ? parseInt(newUser.department_id) : null
      };
      await api.post('/users', payload);
      setIsAdding(false);
      setNewUser({ email: '', password: '', role: 'analyst', department_id: '' });
      fetchData();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to add user');
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this user?')) return;
    try {
      await api.delete(`/users/${id}`);
      fetchData();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to delete user');
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-slate-100 font-display">Users</h1>
          <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
            Manage user accounts, assign roles, and map departmental affiliations.
          </p>
        </div>
        <button
          onClick={() => setIsAdding(true)}
          className="premium-btn premium-btn-primary self-start sm:self-auto gap-2"
        >
          <Plus className="h-4 w-4" />
          Add User
        </button>
      </div>

      {error && (
        <div className="bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900 text-red-600 dark:text-red-400 px-4 py-3 rounded-xl text-sm flex items-start gap-2 shadow-sm animate-scale-up">
          <Shield className="h-5 w-5 flex-shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Add New User Modal / Section */}
      {isAdding && (
        <div className="premium-card p-6 bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 animate-slide-up">
          <div className="flex items-center gap-2 mb-6">
            <div className="h-8 w-8 rounded-lg bg-indigo-50 dark:bg-indigo-950/50 flex items-center justify-center">
              <ShieldCheck className="h-4 w-4 text-brand-indigo" />
            </div>
            <h3 className="text-lg font-semibold text-slate-950 dark:text-slate-50">Add New User</h3>
          </div>

          <form className="space-y-4" onSubmit={handleAdd}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
                  <input
                    type="email"
                    required
                    value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                    className="premium-input pl-9"
                    placeholder="name@company.com"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Password</label>
                <input
                  type="password"
                  required
                  minLength={8}
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  className="premium-input"
                  placeholder="••••••••"
                />
                <p className="mt-1 text-[11px] text-slate-400">Minimum 8 characters</p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">System Role</label>
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                  className="premium-input"
                >
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Department Assignment</label>
                <select
                  value={newUser.department_id}
                  onChange={(e) => setNewUser({ ...newUser, department_id: e.target.value })}
                  className="premium-input"
                >
                  <option value="">No Department</option>
                  {departments.map((d: any) => (
                    <option key={d.id} value={d.id}>{d.name}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex justify-end space-x-3 pt-4 border-t border-slate-100 dark:border-slate-800">
              <button
                type="button"
                onClick={() => setIsAdding(false)}
                className="premium-btn premium-btn-secondary"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="premium-btn premium-btn-primary"
              >
                Save User
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Users list / table container */}
      <div className="premium-card overflow-hidden bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800">
        {loading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
            <div className="h-6 w-6 border-2 border-brand-indigo border-t-transparent rounded-full animate-spin" />
            <span className="text-sm font-medium">Fetching workspace accounts...</span>
          </div>
        ) : users.length === 0 ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
            <HelpCircle className="h-10 w-10 text-slate-300 dark:text-slate-700" />
            <p className="text-sm">No workspace users found.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm border-collapse">
              <thead>
                <tr className="bg-slate-50/50 dark:bg-slate-800/20">
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">User Identity</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">Role</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">Assigned Department</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
                {users.map((user: any) => {
                  const isSelf = user.email === payload?.sub;
                  const dept = departments.find(d => d.id === user.department_id);
                  return (
                    <tr key={user.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/10 transition-colors">
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="h-8 w-8 rounded-full bg-slate-100 dark:bg-slate-800 flex items-center justify-center text-slate-500 dark:text-slate-400">
                            <User className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-1.5 font-mono">
                              {user.email}
                              {isSelf && (
                                <span className="px-1.5 py-0.5 text-[10px] font-bold text-indigo-600 bg-indigo-50 dark:bg-indigo-950/40 dark:text-indigo-400 rounded">
                                  You
                                </span>
                              )}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${
                          user.role === 'admin'
                            ? 'bg-purple-50 dark:bg-purple-950/30 text-purple-600 dark:text-purple-400 border border-purple-100 dark:border-purple-900/55'
                            : 'bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 border border-blue-100 dark:border-blue-900/55'
                        }`}>
                          {user.role}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-slate-600 dark:text-slate-300 font-medium">
                        {dept ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700/60">
                            {dept.name}
                          </span>
                        ) : (
                          <span className="text-slate-400 dark:text-slate-600 italic">None</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-right">
                        {!isSelf && (
                          <button
                            onClick={() => handleDelete(user.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-brand-red hover:bg-red-50 dark:hover:bg-red-950/20 transition-all inline-flex items-center"
                            title="Delete user"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
