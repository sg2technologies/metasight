/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Login } from './pages/Login';
import { DataSources } from './pages/DataSources';
import { Users } from './pages/Users';
import { Tables } from './pages/Tables';
import { Catalog } from './pages/Catalog';
import { Policies } from './pages/Policies';
import { AuditLog } from './pages/AuditLog';
import { GovernanceAuditCenter } from './pages/GovernanceAuditCenter';
import { Query } from './pages/Query';
import { Settings } from './pages/Settings';
import { Security } from './pages/Security';
import { Discovery } from './pages/Discovery';
import { TableManagement } from './pages/TableManagement';
import { Agents } from './pages/Agents';
import { BlockedCommands } from './pages/BlockedCommands';

import { isSuperAdmin, getUserRole } from './api';
import { SuperAdmin } from './pages/SuperAdmin';
import { pamPlugin } from './plugins/pam';

// Protected Route wrapper
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (isSuperAdmin()) {
    return <Navigate to="/superadmin" replace />;
  }
  return <>{children}</>;
};

const AdminRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  const role = getUserRole();
  if (role !== 'admin' && role !== 'superadmin') {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
};

const SuperAdminRoute = ({ children }: { children: React.ReactNode }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  if (!isSuperAdmin()) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
};

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        <Route
          path="/superadmin"
          element={
            <SuperAdminRoute>
              <SuperAdmin />
            </SuperAdminRoute>
          }
        />

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<DataSources />} />
          <Route path="users" element={<AdminRoute><Users /></AdminRoute>} />
          <Route path="tables" element={<Tables />} />
          <Route path="catalog" element={<Catalog />} />
          <Route path="policies" element={<AdminRoute><Policies /></AdminRoute>} />
          <Route path="audit" element={<AdminRoute><AuditLog /></AdminRoute>} />
          <Route path="governance-audit" element={<AdminRoute><GovernanceAuditCenter /></AdminRoute>} />
          <Route path="query" element={<Query />} />
          <Route path="settings"  element={<AdminRoute><Settings /></AdminRoute>} />
          <Route path="security"  element={<AdminRoute><Security /></AdminRoute>} />
          <Route path="discovery" element={<AdminRoute><Discovery /></AdminRoute>} />
          <Route path="table-management" element={<AdminRoute><TableManagement /></AdminRoute>} />
          <Route path="agents" element={<AdminRoute><Agents /></AdminRoute>} />
          <Route path="blocked-commands" element={<AdminRoute><BlockedCommands /></AdminRoute>} />
          {/* Plugin routes (PAM in Enterprise; empty registry in Community —
              see plugins/pam/index.ts) */}
          {pamPlugin.routes.map(({ path, element, requiresAdmin }) => (
            <Route
              key={path}
              path={path}
              element={requiresAdmin ? <AdminRoute>{element}</AdminRoute> : element}
            />
          ))}
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

