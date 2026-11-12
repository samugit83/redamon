'use client'

import { useContext } from 'react'
import { AuthContext } from '@/providers/authContext'
import type { PermissionId } from '@/lib/authz/permissions'
import type { RbacFlags } from '@/lib/authz/flags'

/**
 * Whether the signed-in person may do `permission` (UI-01): what /api/auth/me answered, the set
 * can() decides with (under act-as, what the admin may use while acting). A screen hides what this
 * refuses; the route still decides, so a stale answer costs a refusal, never access. False while
 * the session loads, when the server could not resolve the set, and outside an AuthProvider.
 *
 * `projectId` is the project the action is on. Project access is owner-only in this release and
 * the UI lists only projects the person sees, so it changes no answer yet: step 4.11 adds the
 * access level a share gives.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function useCan(permission: PermissionId, projectId?: string | null): boolean {
  return useContext(AuthContext)?.capabilities.has(permission) ?? false
}

/** The RBAC switch states /api/auth/me answered; null until read and outside an AuthProvider. */
export function useRbacFlags(): Readonly<RbacFlags> | null {
  return useContext(AuthContext)?.flags ?? null
}
