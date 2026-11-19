/**
 * GET /api/navigator/projects/:projectId/status: what the panel shows on this project. `allowed:
 * false` with the reason (owner_disallowed, navigator_not_available, navigator_disabled) puts the
 * Intro's refusal in place of the chat; a missing route's permission is not a refusal (the chat
 * works and explains what it cannot read).
 */
import { NextRequest, NextResponse } from 'next/server'
import { withRouteErrors } from '@/lib/routeErrors'
import { readFeatureModel } from '@/lib/featureModels'
import { requirePermission } from '@/lib/authz/guards'
import { navigatorContext } from '@/lib/navigator/access'
import { navigatorJson, isNavigatorId, navigatorError } from '@/lib/navigator/responses'
import { projectRetentionDays } from '@/lib/navigator/retention'
import { routesFor } from '@/lib/navigator/tools/run'

type Ctx = { params: Promise<{ projectId: string }> }

const REFUSALS = new Set(['owner_disallowed', 'navigator_not_available', 'navigator_disabled'])

export const GET = withRouteErrors('Could not read the AI Navigator status', async (request: NextRequest, { params }: Ctx) => {
  const { projectId } = await params
  if (!isNavigatorId(projectId)) return navigatorError('not_found', 404)
  const nav = await navigatorContext(await requirePermission(request, 'navigator:use', { projectId, allowOversight: false }))
  if (nav instanceof NextResponse) {
    if (nav.status === 403) {
      const body = await nav.clone().json().catch(() => null) as { code?: string } | null
      // The guard asked navigator:use on the project first, so these refusals reach only a person
      // who sees the project.
      if (body?.code && REFUSALS.has(body.code)) return navigatorJson({ allowed: false, reason: body.code })
    }
    return nav
  }
  const person = nav.auth.actingAs ?? nav.auth.principal
  const actor = nav.auth.actingAs ? nav.auth.principal : null
  const { allowed, reasons } = await routesFor({ allowed: true, access: nav.access, person, actor }, nav.projectId)
  return navigatorJson({
    allowed: true,
    isOwner: nav.access.level === 'owner',
    actingAs: actor !== null,
    modelConfigured: (await readFeatureModel(nav.personId, 'navigator')) !== '',
    routes: allowed,
    routeReasons: reasons,
    sqlEnabled: false,
    retentionDays: await projectRetentionDays(nav.projectId),
  })
})
