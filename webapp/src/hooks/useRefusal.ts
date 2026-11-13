'use client'

import { useCallback, useContext } from 'react'
import { AuthContext } from '@/providers/authContext'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import type { PermissionId } from '@/lib/authz/permissions'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { levelRefusalText } from '@/lib/readOnlyProject'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'

/**
 * Why a control is refused up front, in the words it shows (step 4.11): `level` when the person's
 * access to the project does not reach what the permission needs ("Read access, shared by
 * <owner>"), else `permission` when the permissions switch is on and the set lacks it
 * (`forbiddenNoticeText`). A module of its own so a test that replaces hooks/useCan keeps these.
 */
export interface Refusal {
  kind: 'level' | 'permission'
  permission: PermissionId
  text: string
}

/**
 * The person's own access to `projectId` as the open project's read answered it, or null: no
 * project in scope, another project than the open one, or RBAC_SHARING_ENABLED off (the read
 * carries no `myAccess`). Omitting `projectId` (or passing '') means the open project.
 */
export function useProjectAccess(projectId?: string | null): MyAccess | null {
  const scope = useContext(ProjectAccessContext)
  if (!scope?.myAccess) return null
  if (projectId && projectId !== scope.projectId) return null
  return scope.myAccess
}

/**
 * A checker for controls that act on a project the caller names with its own `myAccess` (a list
 * row): `check(permission, access)` answers a Refusal or null. The permission half refuses only with
 * RBAC_PERMISSIONS_ENABLED on, once /api/auth/me answered, and the permission missing from its set;
 * while the session loads, signed out or outside an AuthProvider the route decides (DV-30).
 */
export function useRefusalCheck(): (permission: PermissionId, access: MyAccess | null | undefined) => Refusal | null {
  const auth = useContext(AuthContext)
  return useCallback((permission, access) => {
    const levelText = levelRefusalText(access, permission)
    if (levelText) return { kind: 'level', permission, text: levelText }
    if (!auth || auth.isLoading) return null
    if (auth.flags?.permissions === true && !auth.capabilities.has(permission)) {
      return { kind: 'permission', permission, text: forbiddenNoticeText(permission) }
    }
    return null
  }, [auth])
}

/** Why `permission` on `projectId` (the open project when omitted) is refused up front, or null. */
export function useRefusal(permission: PermissionId, projectId?: string | null): Refusal | null {
  const check = useRefusalCheck()
  return check(permission, useProjectAccess(projectId))
}
