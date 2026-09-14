/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import type { ReactElement } from 'react';
import type { LucideIcon } from 'lucide-react';

/**
 * Frontend plugin seam: Community ships an empty registry (see
 * plugins/pam/index.ts) so App.tsx/Layout.tsx never import Enterprise-only
 * pages directly. Enterprise's frontend build overlays this same file path
 * with the real one — see enterprise/frontend/README.md.
 */

export interface PluginRouteDef {
  path: string;
  element: ReactElement;
  /** Wrap with <AdminRoute> — mirrors the per-route gating in App.tsx. */
  requiresAdmin?: boolean;
}

export interface PluginNavItemDef {
  name: string;
  path: string;
  icon: LucideIcon;
  /** Only shown to admin/superadmin — mirrors the per-item gating in Layout.tsx. */
  requiresAdmin?: boolean;
}

export interface FrontendPlugin {
  /** Section heading shown above this plugin's nav items, when it has any. */
  sectionLabel: string;
  navItems: PluginNavItemDef[];
  routes: PluginRouteDef[];
}
