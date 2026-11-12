import { NextRequest, NextResponse } from 'next/server'
import { requireSession, type Session } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { managerOf } from '@/lib/authz/permissionAdmin'
import { deleteSet, updateSet } from '@/lib/authz/permissionSetAdmin'
import { requireRootPower } from '@/lib/authz/rootPowers'

interface RouteParams {
  params: Promise<{ id: string }>
}

const ROOT_ONLY = 'Only Root can create or change admin profiles.'

/**
 * One admin profile (step 3.11, PE-07). Permissions switch only (404 without it). Each write is
 * `admin_profiles:manage`: the confirmed Root with its password (`stepUpPassword`), else 403
 * root_only; same-origin JSON.
 *
 * PUT `{name?, description?, permissions?, stepUpPassword}`: a stored profile; a removal signs out
 * the admins holding it.
 * DELETE `{stepUpPassword}`: a stored profile no admin holds (else 409).
 */
async function asRoot(request: NextRequest): Promise<{ session: Session; body: Record<string, unknown> } | NextResponse> {
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const refusal = await requireRootPower(request, session, parsed.body.stepUpPassword, ROOT_ONLY)
  return refusal ?? { session, body: parsed.body }
}

export const PUT = withRouteErrors('Could not change the admin profile', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const root = await asRoot(request)
  if (root instanceof NextResponse) return root
  const { id } = await params
  return updateSet(request, root.session, (await managerOf(root.session)).manager, 'admin', id, root.body)
})

export const DELETE = withRouteErrors('Could not delete the admin profile', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const root = await asRoot(request)
  if (root instanceof NextResponse) return root
  const { id } = await params
  return deleteSet(request, root.session, 'admin', id)
})
