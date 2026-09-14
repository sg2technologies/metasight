import React, { useState, useEffect } from 'react';
import { Table as TableIcon, Columns, Search, Plus, Shield, Users, Building2, Save, CheckCircle2, AlertCircle, Edit2, Trash2 } from 'lucide-react';
import { api, fetchDepartments, createDepartment, updateTableVisibility, updateColumnVisibility } from '../api';
import { cn } from '../lib/utils';

interface Department {
  id: number;
  name: string;
}

interface Column {
  id: number;
  name: string;
  type: string;
  allowed_roles: string[];
}

interface Table {
  id: number;
  name: string;
  source_name: string;
  database_name: string;
  department_id: number | null;
  department_name: string | null;
  allowed_roles: string[];
  columns: Column[];
}

interface ManagedTable {
  id: number;
  name: string;
}

interface ManagedResource {
  id: number;
  department_id: number;
  department_name: string;
  source_name: string;
  database_name: string;
  tables: ManagedTable[];
}

export function TableManagement() {
  const [tables, setTables] = useState<Table[]>([]);
  const [managedResources, setManagedResources] = useState<ManagedResource[]>([]);
  const [departments, setDepartments] = useState<Department[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // View state
  const [view, setView] = useState<'list' | 'add'>('list');

  // Form state for 'Add/Edit' view
  const [editingResourceId, setEditingResourceId] = useState<number | null>(null);
  const [targetDeptId, setTargetDeptId] = useState<number | null>(null);
  const [selectedSource, setSelectedSource] = useState('');
  const [selectedDb, setSelectedDb] = useState('');
  const [selectedTableIds, setSelectedTableIds] = useState<number[]>([]);
  
  const [newDeptName, setNewDeptName] = useState('');
  const [isAddingDept, setIsAddingDept] = useState(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [tableData, deptData, managedData] = await Promise.all([
        // /catalog/tables is paginated ({items, total, ...}), not a bare
        // array — page_size=500 is its hard max (see catalog.py); this
        // page wants "every table" for department bulk-assignment, which
        // this endpoint's pagination doesn't fully support past 500, same
        // as it wouldn't in Catalog.tsx's own search UI.
        api.get('/catalog/tables?page_size=500'),
        fetchDepartments(),
        api.get('/catalog/departments/manage')
      ]);
      setTables(tableData.data?.items || []);
      setDepartments(deptData || []);
      setManagedResources(managedData.data || []);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const resetForm = () => {
    setEditingResourceId(null);
    setTargetDeptId(null);
    setSelectedSource('');
    setSelectedDb('');
    setSelectedTableIds([]);
    setIsAddingDept(false);
    setNewDeptName('');
  };

  const handleAddDepartment = async () => {
    if (!newDeptName.trim()) return;
    try {
      await createDepartment(newDeptName.trim());
      const updatedDepts = await fetchDepartments();
      setDepartments(updatedDepts);
      setNewDeptName('');
      setIsAddingDept(false);
      setSuccess('Department added successfully!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to add department');
    }
  };

  const handleSaveAssignment = async () => {
    if (selectedTableIds.length === 0 || !targetDeptId || !selectedSource || !selectedDb) {
      setError('Please select department, source, database and tables');
      return;
    }

    try {
      setLoading(true);
      
      // If editing, remove the old record first
      if (editingResourceId) {
        await api.delete(`/catalog/departments/manage/${editingResourceId}`);
      }

      const selectedTablesList = tables
        .filter(t => selectedTableIds.includes(t.id))
        .map(t => ({ id: t.id, name: t.name }));

      await api.post('/catalog/departments/manage', {
        department_id: targetDeptId,
        source_name: selectedSource,
        database_name: selectedDb,
        tables: selectedTablesList
      });
      
      await fetchData();
      setSuccess(editingResourceId ? 'Management updated successfully.' : `Successfully assigned ${selectedTableIds.length} tables.`);
      setView('list');
      resetForm();
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError('Failed to save assignments');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (itemId: number) => {
    if (!confirm('Are you sure you want to remove these tables from management?')) return;
    try {
      setLoading(true);
      await api.delete(`/catalog/departments/manage/${itemId}`);
      await fetchData();
      setSuccess('Resource unmanaged successfully.');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err) {
      setError('Failed to remove resource.');
    } finally {
      setLoading(false);
    }
  };

  const handleEditTrigger = (resource: ManagedResource) => {
    setEditingResourceId(resource.id);
    setTargetDeptId(resource.department_id);
    setSelectedSource(resource.source_name);
    setSelectedDb(resource.database_name);
    setSelectedTableIds(resource.tables.map(t => t.id));
    setView('add');
  };

  const sources = Array.from(new Set(tables.map(t => t.source_name))).sort();
  const databases = Array.from(new Set(
    tables
      .filter(t => !selectedSource || t.source_name === selectedSource)
      .map(t => t.database_name || 'default')
  )).sort();

  const availableTables = tables.filter(t => 
    (!selectedSource || t.source_name === selectedSource) &&
    (!selectedDb || (t.database_name || 'default') === selectedDb)
  );

  const toggleTable = (id: number) => {
    setSelectedTableIds(prev => 
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  return (
    <div className="space-y-6 animate-fade-in text-slate-800 dark:text-slate-100">
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center gap-3">
            <Building2 className="w-8 h-8 text-brand-indigo" />
            <span>Department Management</span>
          </h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {view === 'list' 
              ? 'View and allocate data source tables to departments for access control.' 
              : editingResourceId ? 'Modify existing departmental database tables assignment.' : 'Map databases and tables to business departments.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {success && (
            <div className="flex items-center gap-2 px-3.5 py-1.5 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400 text-sm font-medium rounded-lg border border-emerald-100 dark:border-emerald-900/30 animate-scale-up">
              <CheckCircle2 className="w-4 h-4" />
              <span>{success}</span>
            </div>
          )}
          {error && (
            <div className="flex items-center gap-2 px-3.5 py-1.5 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400 text-sm font-medium rounded-lg border border-rose-100 dark:border-rose-900/30 animate-scale-up">
              <AlertCircle className="w-4 h-4" />
              <span>{error}</span>
            </div>
          )}
          
          {view === 'list' ? (
            <button
              onClick={() => { resetForm(); setView('add'); }}
              className="premium-btn-primary gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Assignment
            </button>
          ) : (
            <button
              onClick={() => { resetForm(); setView('list'); }}
              className="premium-btn-secondary"
            >
              Back to List
            </button>
          )}
        </div>
      </div>

      {view === 'list' ? (
        /* Managed Resources Table List */
        <div className="premium-card overflow-hidden">
          <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <TableIcon className="w-4 h-4 text-brand-indigo" />
              <h2 className="text-sm font-semibold text-slate-900 dark:text-white uppercase tracking-wider">
                Managed Departmental Assets
              </h2>
            </div>
            <span className="premium-badge bg-slate-100 dark:bg-slate-850 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-800">
              {managedResources.length} mapped
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50/50 dark:bg-slate-900/20 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase border-b border-slate-200 dark:border-slate-800">
                  <th className="px-6 py-3.5">Department</th>
                  <th className="px-6 py-3.5">Data Source</th>
                  <th className="px-6 py-3.5">Database</th>
                  <th className="px-6 py-3.5">Allocated Tables</th>
                  <th className="px-6 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800/80">
                {loading && managedResources.length === 0 ? (
                  [...Array(3)].map((_, i) => (
                    <tr key={i} className="animate-pulse">
                      <td colSpan={5} className="px-6 py-5">
                        <div className="h-4 bg-slate-100 dark:bg-slate-800 rounded w-2/3 mb-2"></div>
                        <div className="h-3 bg-slate-100 dark:bg-slate-800 rounded w-1/2 opacity-60"></div>
                      </td>
                    </tr>
                  ))
                ) : managedResources.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-16 text-center">
                      <div className="flex flex-col items-center justify-center max-w-sm mx-auto">
                        <div className="p-4 bg-slate-100 dark:bg-slate-800/60 text-slate-400 dark:text-slate-500 rounded-full mb-4">
                          <TableIcon className="w-8 h-8 opacity-65" />
                        </div>
                        <p className="font-semibold text-slate-800 dark:text-slate-250 text-base">No Department Assets Mapped</p>
                        <p className="text-xs text-slate-400 dark:text-slate-500 mt-1 mb-4">
                          Assign tables and schemas to departments to restrict database connections.
                        </p>
                        <button
                          onClick={() => setView('add')}
                          className="premium-btn-primary text-xs"
                        >
                          Map First Asset
                        </button>
                      </div>
                    </td>
                  </tr>
                ) : (
                  managedResources.map(t => (
                    <tr key={t.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-900/30 transition-colors group">
                      <td className="px-6 py-4.5 whitespace-nowrap">
                        <span className="premium-badge bg-indigo-50 dark:bg-indigo-950/30 text-brand-indigo dark:text-indigo-400 border border-indigo-100 dark:border-indigo-900/20 font-bold">
                          {t.department_name}
                        </span>
                      </td>
                      <td className="px-6 py-4.5 text-sm font-semibold text-slate-900 dark:text-white whitespace-nowrap">
                        {t.source_name}
                      </td>
                      <td className="px-6 py-4.5 text-sm text-slate-600 dark:text-slate-350 whitespace-nowrap">
                        {t.database_name}
                      </td>
                      <td className="px-6 py-4.5">
                        <div className="flex flex-wrap gap-1.5 max-w-md">
                          {t.tables.map(tbl => (
                            <span 
                              key={tbl.id} 
                              className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-150 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-750"
                            >
                              {tbl.name}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4.5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => handleEditTrigger(t)}
                            className="p-1.5 text-slate-400 hover:text-brand-indigo hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-all"
                            title="Edit Assignment"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDelete(t.id)}
                            className="p-1.5 text-slate-400 hover:text-brand-red hover:bg-rose-50 dark:hover:bg-rose-950/30 rounded-lg transition-all"
                            title="Remove Assignment"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Add/Edit View Form */
        <div className="max-w-3xl mx-auto space-y-6 animate-slide-up">
          <div className="premium-card overflow-hidden">
            <div className="px-6 py-4 bg-slate-50 dark:bg-slate-900/50 border-b border-slate-200 dark:border-slate-800">
              <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                {editingResourceId ? <Edit2 className="w-5 h-5 text-brand-indigo" /> : <Plus className="w-5 h-5 text-brand-indigo" />}
                <span>{editingResourceId ? 'Edit Department Asset Assignment' : 'Map New Department Asset'}</span>
              </h2>
            </div>
            
            <div className="p-6 space-y-6">
              {/* Form Step Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                {/* Department */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    1. Department
                  </label>
                  <div className="flex gap-2">
                    <select
                      value={targetDeptId || ''}
                      onChange={(e) => setTargetDeptId(Number(e.target.value) || null)}
                      className="premium-input py-2 font-medium"
                    >
                      <option value="">Select...</option>
                      {departments.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}
                    </select>
                    <button
                      type="button"
                      onClick={() => setIsAddingDept(true)}
                      className="p-2.5 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700/80 text-brand-indigo rounded-lg transition-all"
                      title="Create Department"
                    >
                      <Plus className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {/* Source Selection */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    2. Data Source
                  </label>
                  <select
                    value={selectedSource}
                    onChange={(e) => { setSelectedSource(e.target.value); setSelectedDb(''); setSelectedTableIds([]); }}
                    className="premium-input py-2 font-medium"
                  >
                    <option value="">Select Source...</option>
                    {sources.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>

                {/* Database Selection */}
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    3. Database
                  </label>
                  <select
                    value={selectedDb}
                    onChange={(e) => { setSelectedDb(e.target.value); setSelectedTableIds([]); }}
                    className="premium-input py-2 font-medium"
                    disabled={!selectedSource}
                  >
                    <option value="">Select Database...</option>
                    {databases.map(db => <option key={db} value={db}>{db}</option>)}
                  </select>
                </div>
              </div>

              {/* Inline Create Department Input Panel */}
              {isAddingDept && (
                <div className="p-4 bg-slate-50 dark:bg-slate-900/60 rounded-xl border border-slate-200 dark:border-slate-800 flex items-center gap-3 animate-scale-up">
                  <input
                    type="text"
                    value={newDeptName}
                    onChange={(e) => setNewDeptName(e.target.value)}
                    placeholder="New department name (e.g. Finance)"
                    className="premium-input py-1.5"
                  />
                  <button
                    type="button"
                    onClick={handleAddDepartment}
                    className="premium-btn-primary px-4 py-1.5 text-xs whitespace-nowrap"
                  >
                    Create
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsAddingDept(false)}
                    className="text-xs font-semibold text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 px-2 py-1.5"
                  >
                    Cancel
                  </button>
                </div>
              )}

              {/* Table Picker */}
              {selectedDb && (
                <div className="space-y-3 pt-4 border-t border-slate-100 dark:border-slate-800 animate-fade-in">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                      4. Select tables to assign ({availableTables.length} available)
                    </label>
                    <span className="text-xs font-semibold text-brand-indigo">
                      {selectedTableIds.length} Selected
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3.5 max-h-72 overflow-y-auto p-1 pr-2">
                    {availableTables.map(t => {
                      const isSelected = selectedTableIds.includes(t.id);
                      return (
                        <button
                          key={t.id}
                          type="button"
                          onClick={() => toggleTable(t.id)}
                          className={cn(
                            "flex items-center gap-3 px-4 py-3 rounded-xl border text-left transition-all",
                            isSelected
                              ? "bg-brand-indigo/5 dark:bg-brand-indigo/10 border-brand-indigo text-slate-900 dark:text-white ring-1 ring-brand-indigo"
                              : "bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-850 text-slate-600 dark:text-slate-300 hover:border-slate-350 dark:hover:border-slate-700"
                          )}
                        >
                          <div className={cn(
                            "w-4 h-4 rounded border flex items-center justify-center transition-all",
                            isSelected
                              ? "bg-brand-indigo border-brand-indigo text-white"
                              : "border-slate-300 dark:border-slate-700 bg-transparent"
                          )}>
                            {isSelected && <CheckCircle2 className="w-3 h-3 stroke-[3]" />}
                          </div>
                          <span className="font-semibold text-sm truncate">{t.name}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Form Actions Footer */}
              <div className="pt-5 border-t border-slate-150 dark:border-slate-800 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => { resetForm(); setView('list'); }}
                  className="premium-btn-secondary"
                >
                  Discard
                </button>
                <button
                  type="button"
                  onClick={handleSaveAssignment}
                  disabled={loading || selectedTableIds.length === 0 || !targetDeptId}
                  className="premium-btn-primary disabled:opacity-50"
                >
                  {loading ? 'Saving...' : editingResourceId ? 'Update Mappings' : 'Save Assignment'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
