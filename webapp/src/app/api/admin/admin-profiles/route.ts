import { NextRequest, NextResponse } from 'next/server'
import { requireSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { managerOf, requireAnyPermission } from '@/lib/authz/permissionAdmin'
import { createSet, listSets } from '@/lib/authz/permissionSetAdmin'
import { requireRootPower } from '@/lib/authz/rootPowers'

const ROOT_ONLY = 'Only Root can create or change admin profiles.'

/**
 * Admin profiles (step 3.11, PE-07, PE-30). Permissions switch only (404 without it).
 *
 * GET: every profile, built-ins first, with its holders; for `admin_profiles:manage` (Root) and
 * `admins:manage` (who give profiles).
 * POST `{name, description?, permissions?, cloneFrom?, stepUpPassword}`: a new profile or a copy
 * (`admin_profiles:manage`: the confirmed Root with its password, else 403 root_only; same-origin
 * JSON). A profile holds administration and platform permissions; of the Root-only ones only
 * `admins:manage` (OQ-02).
 */
export const GET = withRouteErrors('Could not list the admin profiles', async () => {
  if (!rbacFlags().permissions) return routeNotFound()
  const session = await requireSession()
  if (session instanceof NextResponse) return session
  const refused = await requireAnyPermission(session, ['admin_profiles:manage', 'admins:manage'])
  if (refused) return refused
  return listSets('admin')
})

export const POST = withRouteErrors('Could not create the admin profile', async (request: NextRequest) => {
  if (!rbacFlags().permissions) return routeNotFound()
  const session = await requireSession({ fresh: true })
  if (session instanceof NextResponse) return session
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const refusal = await requireRootPower(request, session, parsed.body.stepUpPassword, ROOT_ONLY)
  if (refusal) return refusal
  return createSet(request, session, (await managerOf(session)).manager, 'admin', parsed.body)
})
