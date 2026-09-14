import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const api = axios.create({
  baseURL: API_URL,
});

// Decode JWT payload (no signature verification — backend handles that)
export function getTokenPayload(): { sub: string; role: string; tenant_id: number; department_id?: number } | null {
  const token = localStorage.getItem('token');
  if (!token) return null;
  try {
    return JSON.parse(atob(token.split('.')[1]));
  } catch {
    return null;
  }
}

export function getUserRole(): string | null {
  return getTokenPayload()?.role ?? null;
}

export function isAdmin(): boolean {
  return getUserRole() === 'admin';
}

export function isSuperAdmin(): boolean {
  return getUserRole() === 'superadmin';
}

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export async function fetchSettings() {
  const { data } = await api.get('/settings');
  return data;
}

export async function updateSettings(settings: any) {
  const { data } = await api.put('/settings', settings);
  return data;
}

export async function fetchTables() {
  const { data } = await api.get('/tables');
  return data;
}

export async function fetchTableDetail(tableId: number) {
  const { data } = await api.get(`/tables/${tableId}`);
  return data;
}

export async function fetchColumns(tableId: number) {
  const { data } = await api.get(`/tables/${tableId}/columns`);
  return data;
}

export async function fetchPolicies() {
  const { data } = await api.get('/policies');
  return data;
}

export async function executeQuery(sourceId: number, sql: string, limit: number = 5, bypass_masking: boolean = false) {
  const { data } = await api.post('/query/execute', { source_id: sourceId, sql, limit, bypass_masking });
  return data;
}

export async function fetchDepartments() {
  const { data } = await api.get('/catalog/departments');
  return data;
}

export async function createDepartment(name: string) {
  const { data } = await api.post('/catalog/departments', { name });
  return data;
}

export async function updateTableVisibility(tableId: number, departmentId?: number, allowedRoles?: string[]) {
  const { data } = await api.patch(`/catalog/tables/${tableId}/visibility`, { department_id: departmentId, allowed_roles: allowedRoles });
  return data;
}

export async function updateColumnVisibility(columnId: number, allowedRoles: string[]) {
  const { data } = await api.patch(`/catalog/columns/${columnId}/visibility`, { allowed_roles: allowedRoles });
  return data;
}
