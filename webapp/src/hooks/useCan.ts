'use client'

import { useContext } from 'react'
import { AuthContext } from '@/providers/authContext'
import { PERMISSIONS, type PermissionId } from '@/lib/authz/permissions'
import type { RbacFlags } from '@/lib/authz/flags'
import { myAccessMeets } from '@/lib/readOnlyProject'
import { useProjectAccess, useRefusal } from './useRefusal'

/**
 * Whether the signed-in person may do `permission` (UI-01): what /api/auth/me answered, the set
 * can() decides with (under act-as, what the admin may use while acting). Given the open project's
 * id, also whether the person's access to it reaches the permission's level (step 4.11: a read share
 * reaches `R`, and `R*` with Raw data & files). Without one it answers for the set alone, as a list
 * that spans projects asks (the shell sessions). A screen hides what this refuses; the route still
 * decides, so a stale answer costs a refusal, never access. False while the session loads, when the
 * server could not resolve the set, and outside an AuthProvider.
 */
export function useCan(permission: PermissionId, projectId?: string | null): boolean {
  const held = useContext(AuthContext)?.capabilities.has(permission) ?? false
  const access = useProjectAccess(projectId)
  return held && (!projectId || myAccessMeets(access, PERMISSIONS[permission]?.level ?? null))
}

/** The RBAC switch states /api/auth/me answered; null until read and outside an AuthProvider. */
export function useRbacFlags(): Readonly<RbacFlags> | null {
  return useContext(AuthContext)?.flags ?? null
}

/**
 * Whether a control that only works with `permission` should be refused up front (UI-12): with
 * RBAC_PERMISSIONS_ENABLED on, once /api/auth/me answered, and the permission missing from its set
 * (a set the server could not resolve holds nothing); or, with sharing on, when the person's access
 * to the project does not reach the permission's level (step 4.11). With the switches off, while the
 * session loads, or outside an AuthProvider, false: the control is as it was before (DV-30), and its
 * route still decides.
 */
export function usePermissionRefused(permission: PermissionId, projectId?: string | null): boolean {
  return useRefusal(permission, projectId) !== null
}
