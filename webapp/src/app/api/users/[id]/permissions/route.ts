import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { changeUserPermissions, readUserPermissions } from '@/lib/authz/userPermissionAdmin'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * One account's permissions (step 3.11; PE-10, PE-15, PE-30, ID-21). Permissions switch only (404
 * without it). The signed-in person acts, never an account acted as.
 *
 * GET: the account's sets, overrides and (admins) profile, and every permission with its reasons.
 * The account itself; anyone else needs `users:assign_permissions` on a member, and on an admin
 * Root or `admins:manage` over a strict subset (hierarchy.ts).
 * PUT `{sets?, overrides?, stepUpPassword?}` and, for an admin, its profile id: each key sent
 * replaces that part (userPermissionAdmin.ts `parseChange`).
 * Same rule, never on oneself or Root; gives only what the person holds; an admin target, a
 * cross-tenant tool, an exploitation approval, sessions or Kali exec take the person's password.
 * A removal signs the account out everywhere. Same-origin JSON.
 */
export const GET = withRouteErrors('Could not read the account\'s permissions', async (_request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  const { id } = await params
  return readUserPermissions(session, id)
})

export const PUT = withRouteErrors('Could not change the account\'s permissions', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  return changeUserPermissions(request, session, id, parsed.body)
})
