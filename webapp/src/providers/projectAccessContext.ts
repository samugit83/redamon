'use client'

import { createContext } from 'react'
import type { MyAccess } from '@/lib/authz/projectAccess'

/**
 * The open project and the person's own access to it, in a module of its own like authContext: the
 * permission hooks (hooks/useCan.ts) read it without importing ProjectProvider, which imports them.
 * ProjectProvider provides the header's project; a screen that loaded another project itself (the
 * settings form) provides that one's around its own controls.
 *
 * `myAccess` null: RBAC_SHARING_ENABLED off, or the read did not carry it. Nothing is refused by
 * level then (DV-30).
 */
export interface ProjectAccessContextValue {
  projectId: string | null
  myAccess: MyAccess | null
}

export const ProjectAccessContext = createContext<ProjectAccessContextValue | null>(null)
