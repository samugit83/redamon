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

/**
 * Whether a control that only works with `permission` should be refused up front (UI-12): true only
 * with RBAC_PERMISSIONS_ENABLED on, once /api/auth/me answered, and the permission missing from its
 * set (a set the server could not resolve holds nothing). With the switch off, while the session
 * loads, or outside an AuthProvider, false: the control is as it was before the switch (DV-30), and
 * its route still decides.
 */
export function usePermissionRefused(permission: PermissionId, projectId?: string | null): boolean {
  const auth = useContext(AuthContext)
  const held = useCan(permission, projectId)
  if (!auth || auth.isLoading) return false
  return auth.flags?.permissions === true && !held
}
