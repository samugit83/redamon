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
import { now } from '@/lib/authz/clock'
import { rbacFlags } from '@/lib/authz/flags'
import { requireLevel, requirePermission } from '@/lib/authz/guards'
import { ConsentStoreMissing, readOwnerConsent, writeOwnerConsent, type OwnerConsent } from '@/lib/authz/ownerConsent'
import { endCollaboratorSpending } from '@/lib/authz/ownerCredentials'
import { sharingPolicyForRoutes } from '@/lib/authz/projectShares'
import { maxShareLevel } from '@/lib/authz/sharingPolicy'
import { requireStepUp } from '@/lib/authz/stepUp'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** Write sharing in force: the switch, sharing, and Root's policy allowing Read + Write. */
async function writeSharingInForce(fresh: boolean): Promise<boolean> {
  const policy = await sharingPolicyForRoutes({ fresh })
  return policy !== null && maxShareLevel(policy) === 'write'
}

const view = (consent: OwnerConsent | null) => ({
  ownerCredentialConsent: consent !== null,
  consentAt: consent ? consent.at.toISOString() : null,
})

function consentUnavailable(): NextResponse {
  console.error('[rbac] owner consent not written: the project access policy table is not in this build')
  return NextResponse.json(
    { error: 'The consent cannot be recorded on this server yet: update RedAmon and try again.', code: 'consent_unavailable' },
    { status: 503 },
  )
}

/**
 * GET /api/projects/[id]/access-policy (step 5.6, C1): whether the owner lets collaborators spend the
 * project's credentials (its providers and keys), for the owner and a co-owner (`project:share` at
 * Manage) deciding a share's run toggles. Write sharing in force only (the switch, sharing and Root's
 * `maxLevel: 'write'`; 404 otherwise, the consent not read).
 */
export const GET = withRouteErrors('Could not read the project access policy', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharingWrite) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'project:share', { projectId: id })
  if (auth instanceof NextResponse) return auth
  if (!(await writeSharingInForce(false))) return routeNotFound()
  return NextResponse.json(view(await readOwnerConsent(id)))
})

/**
 * POST /api/projects/[id]/access-policy `{ownerCredentialConsent: boolean, stepUpPassword?}` (step 5.6,
 * C1, SH-32, OQ-06): the owner, and only the owner, allows or stops collaborators spending the
 * project's credentials. Granting needs the password (step-up); withdrawing does not. Audited in the
 * change's transaction (`project.owner_consent.grant` / `.withdraw`): no row, no change. A withdrawal
 * then ends what collaborators still spend there (their agent runs and sockets on the project, their
 * queued scans, a live triage run of theirs), best effort: the withdrawal stands when the agent is down.
 * Same-origin JSON; refused while an admin acts as the owner. With write sharing not in force (Root's
 * policy at Read included) it does not exist: no share can spend then, and a consent kept from before
 * counts again only when Root allows Read + Write again.
 */
export const POST = withRouteErrors('Could not change the project access policy', async (request: NextRequest, { params }: RouteParams) => {
  if (!rbacFlags().sharingWrite) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'project:share', { projectId: id, fresh: true })
  if (auth instanceof NextResponse) return auth
  if (!(await writeSharingInForce(true))) return routeNotFound()
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const ownerOnly = requireLevel(auth, 'O')
  if (ownerOnly) return ownerOnly
  const ownerId = auth.access!.project.userId
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: ownerId }, 'change_shares')
  if (acting) return acting
  const wanted = parsed.body.ownerCredentialConsent
  if (typeof wanted !== 'boolean') {
    return NextResponse.json(
      { error: 'ownerCredentialConsent must be true or false', code: 'invalid_field', field: 'ownerCredentialConsent' },
      { status: 400 },
    )
  }
  if (wanted) {
    const stepUp = await requireStepUp(request, parsed.body.stepUpPassword)
    if (stepUp) return stepUp
  }

  const actor = auditActorOf(sessionActor(auth.session), auth.effective.userId)
  let outcome: { changed: boolean; consent: OwnerConsent | null }
  try {
    outcome = await auditedTransaction(prisma, async (tx) => {
      const before = await readOwnerConsent(id, tx)
      if ((before !== null) === wanted) return { changed: false, consent: before }
      const consent = await writeOwnerConsent(tx, id, wanted ? { at: now(), byId: auth.session.userId } : null)
      await writeAuditTx(tx, {
        actorId: actor.actorId,
        ...(actor.actorEmail ? { actorEmail: actor.actorEmail } : {}),
        projectId: id,
        permission: auth.permission,
        action: wanted ? 'project.owner_consent.grant' : 'project.owner_consent.withdraw',
        targetType: 'project',
        targetId: id,
        before: { ownerCredentialConsent: before !== null },
        after: { ownerCredentialConsent: wanted },
        source: 'api',
      })
      return { changed: true, consent }
    })
  } catch (err) {
    if (err instanceof ConsentStoreMissing) return consentUnavailable()
    throw err
  }
  if (!outcome.changed || wanted) return NextResponse.json({ ...view(outcome.consent), changed: outcome.changed })
  const ended = await endCollaboratorSpending(id, ownerId)
  return NextResponse.json({ ...view(outcome.consent), changed: true, ended })
})
