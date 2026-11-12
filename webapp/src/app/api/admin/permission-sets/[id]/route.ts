import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requirePermission } from '@/lib/authz/guards'
import { managerOf } from '@/lib/authz/permissionAdmin'
import { deleteSet, updateSet } from '@/lib/authz/permissionSetAdmin'

interface RouteParams {
  params: Promise<{ id: string }>
}

/**
 * One member permission set (step 3.11, PE-11, PE-17). Permissions switch only (404 without it);
 * `roles:manage`, same-origin.
 *
 * PUT `{name?, description?, permissions?, instanceDefault?, stepUpPassword?}`: a stored set's name,
 * description and permissions, adding only what the editor holds (adding a cross-tenant tool, an
 * exploitation approval, sessions or Kali exec takes the editor's password); `instanceDefault` makes
 * any member set, built-ins included, the default for members never assigned one, or stops it being
 * one: Root's, with Root's password. A removal signs the holders out.
 * DELETE: a stored set nobody holds and that is not the default (else 409).
 */
export const PUT = withRouteErrors('Could not change the permission set', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const auth = await requirePermission(request, 'roles:manage', { fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const { id } = await params
  return updateSet(request, auth.session, (await managerOf(auth.session)).manager, 'member', id, parsed.body)
})

export const DELETE = withRouteErrors('Could not delete the permission set', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const auth = await requirePermission(request, 'roles:manage', { fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const { id } = await params
  return deleteSet(request, auth.session, 'member', id)
})
