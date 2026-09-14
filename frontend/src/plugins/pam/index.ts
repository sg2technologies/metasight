/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import type { FrontendPlugin } from '../types';

/**
 * Community stub — no PAM UI in this edition. Enterprise's frontend build
 * overlays this exact file path (frontend/src/plugins/pam/index.ts) with the
 * real one (11 pages: access requests, sessions, DAM, incidents, evidence,
 * risk, compliance, JIT, agents, blocked commands). See
 * enterprise/frontend/README.md for how the overlay is applied.
 */
export const pamPlugin: FrontendPlugin = {
  sectionLabel: 'PRIVILEGED ACCESS',
  navItems: [],
  routes: [],
};
