import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requirePermission } from '@/lib/authz/guards'
import { managerOf, requireAnyPermission } from '@/lib/authz/permissionAdmin'
import { createSet, listSets } from '@/lib/authz/permissionSetAdmin'

/**
 * Member permission sets (step 3.11, PE-07, PE-11). Permissions switch only (404 without it).
 *
 * GET: every set, built-ins first, with its holders and the instance default; for `roles:manage`
 * and for `users:assign_permissions` (the people who pick sets for an account).
 * POST `{name, description?, permissions?, cloneFrom?}`: a new set, or a copy of one; only
 * permissions the creator holds (`roles:manage`, same-origin JSON).
 */
export const GET = withRouteErrors('Could not list the permission sets', async () => {
  if (!rbacFlags().permissions) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireAnyPermission(session, ['roles:manage', 'users:assign_permissions'])
  if (refused) return refused
  return listSets('member')
})

export const POST = withRouteErrors('Could not create the permission set', async (request: NextRequest) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const auth = await requirePermission(request, 'roles:manage', { fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  return createSet(request, auth.session, (await managerOf(auth.session)).manager, 'member', parsed.body)
})
