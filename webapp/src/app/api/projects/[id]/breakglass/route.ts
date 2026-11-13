import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { rbacFlags } from '@/lib/authz/flags'
import { requirePermission } from '@/lib/authz/guards'
import { sharingPolicyForRoutes } from '@/lib/authz/projectShares'
import { requireRootPower } from '@/lib/authz/rootPowers'
import {
  breakGlassProject, closeBreakGlass, openBreakGlass, ownProjectRefusal, parseBreakGlassRequest, refuseWhileActing,
} from '@/lib/authz/breakGlass'

interface RouteParams {
  params: Promise<{ id: string }>
}

const ROOT_ONLY = 'Only Root can open break-glass access to a project.'

/**
 * POST /api/projects/[id]/breakglass {reason, durationMinutes <= 240, stepUpPassword} (step 4.14):
 * Root opens read access to everything the project holds, Raw data & files included, until the time
 * runs out (lib/authz/breakGlass.ts). Sharing in force only (404 otherwise, nothing read);
 * projects:administer, then the confirmed Root with its own password (requireRootPower); same-origin
 * JSON; never while acting as someone; never on Root's own project. 201 with the row's expiry; the
 * owner is notified and sees it in the activity feed.
 */
export const POST = withRouteErrors('Could not open break-glass access', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'projects:administer', { fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!(await sharingPolicyForRoutes({ fresh: true }))) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const acting = await refuseWhileActing(auth.principal, auth.actingAs, 'break_glass')
  if (acting) return acting
  // The form is checked before the password, so a mistake there spends nothing of the step-up budget.
  const asked = parseBreakGlassRequest(parsed.body)
  if (asked instanceof NextResponse) return asked
  const project = await breakGlassProject(id)
  if (!project) return routeNotFound()
  const own = ownProjectRefusal(project, auth.principal.id)
  if (own) return own
  const refusal = await requireRootPower(request, auth.session, parsed.body.stepUpPassword, ROOT_ONLY)
  if (refusal) return refusal
  const opened = await openBreakGlass(auth.principal, project, asked)
  return NextResponse.json({ breakGlass: opened }, { status: 201 })
})

/**
 * DELETE /api/projects/[id]/breakglass (step 4.14): Root ends its own break-glass on the project
 * before the time runs out, audited (project.breakglass.end). Taking access away asks no password;
 * 404 no_break_glass when none is open. Same gates as POST otherwise.
 */
export const DELETE = withRouteErrors('Could not close break-glass access', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'projects:administer', { fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!(await sharingPolicyForRoutes({ fresh: true }))) return routeNotFound()
  // No body to check: a browser form cannot send a DELETE.
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const acting = await refuseWhileActing(auth.principal, auth.actingAs, 'break_glass')
  if (acting) return acting
  const project = await breakGlassProject(id)
  if (!project) return routeNotFound()
  const closed = await closeBreakGlass(auth.principal, project.id)
  if (closed === 0) {
    return NextResponse.json({ error: 'You hold no open break-glass access to this project.', code: 'no_break_glass' }, { status: 404 })
  }
  return NextResponse.json({ closed })
})
