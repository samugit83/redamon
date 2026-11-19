/**
 * GET/POST /api/navigator/projects/:projectId/policy: the owner's "AI Navigator for collaborators"
 * (D3, plan §5.4). AI Navigator runs on each person's own model, so on a shared project the owner's
 * data goes to the provider the collaborator chose; only the owner decides that.
 *
 * Exists only while sharing is in force (404 otherwise, nothing read: without sharing there are no
 * collaborators) and Root's AI Navigator switch is on. GET at project:share; POST at project:share
 * fresh, the owner level, never while an admin acts as the owner, a step-up to turn it on (as
 * granting consent does), and the change and its audit row commit together. Turning it off stops
 * every collaborator's answer in flight (`navigator_disallowed`).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { auditActorOf, sessionActor } from '@/lib/auditActor'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { refuseWhileActingAs } from '@/lib/authz/actAsRefusals'
import { requireLevel, requirePermission } from '@/lib/authz/guards'
import { sharingPolicyInForce } from '@/lib/authz/sharingPolicy'
import { requireStepUp } from '@/lib/authz/stepUp'
import { endCollaboratorNavigator, navigatorCollaboratorsAllowed, writeNavigatorPolicy } from '@/lib/authz/navigatorPolicy'
import { navigatorEnabled } from '@/lib/navigator/switch'
import { isNavigatorId, navigatorJson } from '@/lib/navigator/responses'

type Ctx = { params: Promise<{ projectId: string }> }

async function inForce(fresh = false): Promise<boolean> {
  return (await sharingPolicyInForce({ fresh }))?.enabled === true && (await navigatorEnabled())
}

export const GET = withRouteErrors('Could not read the AI Navigator policy', async (request: NextRequest, { params }: Ctx) => {
  if (!(await inForce())) return routeNotFound()
  const { projectId } = await params
  if (!isNavigatorId(projectId)) return routeNotFound()
  const auth = await requirePermission(request, 'project:share', { projectId })
  if (auth instanceof NextResponse) return auth
  return navigatorJson({ collaboratorsAllowed: await navigatorCollaboratorsAllowed(auth.access!.project.id) })
})

export const POST = withRouteErrors('Could not change the AI Navigator policy', async (request: NextRequest, { params }: Ctx) => {
  if (!(await inForce(true))) return routeNotFound()
  const { projectId } = await params
  if (!isNavigatorId(projectId)) return routeNotFound()
  const auth = await requirePermission(request, 'project:share', { projectId, fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const ownerOnly = requireLevel(auth, 'O')
  if (ownerOnly) return ownerOnly
  const project = auth.access!.project
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: project.userId }, 'change_shares')
  if (acting) return acting
  const wanted = parsed.body.collaboratorsAllowed
  if (typeof wanted !== 'boolean') {
    return NextResponse.json(
      { error: 'collaboratorsAllowed must be true or false', code: 'invalid_field', field: 'collaboratorsAllowed' },
      { status: 400 },
    )
  }
  if (wanted) {
    const stepUp = await requireStepUp(request, parsed.body.stepUpPassword)
    if (stepUp) return stepUp
  }

  const actor = auditActorOf(sessionActor(auth.session), auth.effective.userId)
  const changed = await auditedTransaction(prisma, async (tx) => {
    if (!(await writeNavigatorPolicy(tx, project.id, wanted, auth.effective.userId))) return false
    await writeAuditTx(tx, {
      actorId: actor.actorId,
      ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
      projectId: project.id,
      permission: auth.permission,
      action: wanted ? 'project.navigator_collaborators.allow' : 'project.navigator_collaborators.disallow',
      targetType: 'project',
      targetId: project.id,
      before: { collaboratorsAllowed: !wanted },
      after: { collaboratorsAllowed: wanted },
      source: 'api',
    })
    return true
  })
  if (changed && !wanted) await endCollaboratorNavigator(project.id, project.userId)
  return navigatorJson({ collaboratorsAllowed: wanted, changed })
})
