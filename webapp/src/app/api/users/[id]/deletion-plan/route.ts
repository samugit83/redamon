import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/session'
import { withRouteErrors } from '@/lib/routeErrors'
import { readJsonBody } from '@/lib/jsonBody'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { requireSessionPermission } from '@/lib/authz/adminPermission'
import { refuseWhileActingAs } from '@/lib/authz/actAsRefusals'
import { rootProtectedRefusal } from '@/lib/authz/rootProtection'
import { adminTargetGate, requireRootPower } from '@/lib/authz/rootPowers'
import { requireStepUp } from '@/lib/authz/stepUp'
import { cancelForDeletion, forceTransferForDeletion, offerForDeletion, writeSharingInForce } from '@/lib/authz/ownershipTransfer'
import { deletionPlan, deletionWizardOff, isOwnAccount, isProjectOf } from '@/lib/authz/userDeletion'

interface RouteParams {
  params: Promise<{ id: string }>
}

const ACTIONS = ['offer', 'force', 'cancel'] as const
const ROOT_ONLY_FORCE = 'Only Root can give a project to a collaborator without their acceptance.'
const ROOT_ONLY_ADMIN = "Only Root can decide what happens to another admin's projects."

const ownAccount = () => NextResponse.json(
  { error: 'Your own account cannot be deleted, so it has no deletion plan.', code: 'own_account' }, { status: 400 },
)
const invalid = (field: string, error: string) => NextResponse.json({ error, code: 'invalid_field', field }, { status: 400 })

/**
 * GET /api/users/[id]/deletion-plan (step 5.13; SH-16, SH-17): what deleting the account does, for the
 * Users page's wizard (lib/authz/userDeletion.ts): its projects shared and unshared with what runs on
 * each and each shared project's open offer, its shares in other people's projects, its conversations
 * there, its live work, what ends with it, and whether the viewer may force a transfer. Write sharing
 * switched on only (404 otherwise, nothing read); users:delete; never one's own account; Root's account
 * is refused as its deletion is.
 */
export const GET = withRouteErrors('Could not read the deletion plan', async (request: NextRequest, { params }: RouteParams) => {
  if (deletionWizardOff()) return routeNotFound()
  const session = await getSession({ fresh: true })
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const denied = await requireSessionPermission(session, 'users:delete', { fresh: true })
  if (denied) return denied
  const { id } = await params
  if (isOwnAccount(session, id)) return ownAccount()
  const root = await rootProtectedRefusal(request, session, id, 'delete')
  if (root) return root
  const plan = await deletionPlan(id, session)
  if (!plan) return NextResponse.json({ error: 'User not found' }, { status: 404 })
  return NextResponse.json({ plan })
})

/**
 * POST /api/users/[id]/deletion-plan `{action, projectId, toUserId?, stepUpPassword?}` resolves one shared
 * project of the account before its deletion (lib/authz/ownershipTransfer.ts):
 * - `offer`: offers it to one of its active collaborators, who accepts or declines (the old owner leaves);
 *   the admin's own password (another admin's projects: what deleting that admin takes);
 * - `force`: gives it to the collaborator now, without their acceptance: projects:administer, then the
 *   confirmed Root's own password; audited `project.transfer.forced`;
 * - `cancel`: withdraws the project's open offer (no password for a member's project).
 * Same gates as GET, then same-origin JSON, never while acting as anyone, and only on the account's own
 * projects (404 otherwise). Offers and forced transfers need Root's sharing policy at Read + Write (409
 * `transfers_unavailable`: such a project can only be deleted anyway).
 */
export const POST = withRouteErrors('Could not change the deletion plan', async (request: NextRequest, { params }: RouteParams) => {
  if (deletionWizardOff()) return routeNotFound()
  const session = await getSession({ fresh: true })
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  const denied = await requireSessionPermission(session, 'users:delete', { fresh: true })
  if (denied) return denied
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const acting = await refuseWhileActingAs({ session }, 'transfer_projects')
  if (acting) return acting
  const { id } = await params
  if (isOwnAccount(session, id)) return ownAccount()
  const root = await rootProtectedRefusal(request, session, id, 'delete')
  if (root) return root

  // The form is checked before any password, so a mistake spends nothing of the step-up budget.
  const { action, projectId, toUserId, stepUpPassword } = parsed.body as Record<string, unknown>
  if (typeof action !== 'string' || !(ACTIONS as readonly string[]).includes(action)) {
    return invalid('action', 'action must be "offer", "force" or "cancel".')
  }
  if (typeof projectId !== 'string' || !projectId) return invalid('projectId', 'Name the project (projectId).')
  if (action !== 'cancel' && (typeof toUserId !== 'string' || !toUserId)) {
    return invalid('toUserId', 'Name the collaborator to give the project to (toUserId).')
  }
  if (!(await isProjectOf(id, projectId))) {
    return NextResponse.json({ error: "This project is not one of the account's own.", code: 'project_not_found' }, { status: 404 })
  }
  if (action !== 'cancel' && !(await writeSharingInForce({ fresh: true }))) {
    return NextResponse.json({
      error: "Root's sharing policy is at Read only, so a project cannot change owner: delete it anyway, or ask Root to allow Read + Write.",
      code: 'transfers_unavailable',
    }, { status: 409 })
  }
  const recipient = toUserId as string

  if (action === 'force') {
    const notHeld = await requireSessionPermission(session, 'projects:administer', { fresh: true })
    if (notHeld) return notHeld
    const refusal = await requireRootPower(request, session, stepUpPassword, ROOT_ONLY_FORCE)
    if (refusal) return refusal
    return forceTransferForDeletion({ session }, projectId, id, recipient)
  }

  // Another admin's projects follow that admin's deletion rule: the confirmed Root, or an admins:manage
  // holder over a strict subset, each with their own password.
  const gate = await adminTargetGate(request, session, id, stepUpPassword, ROOT_ONLY_ADMIN, 'delete')
  if (gate instanceof NextResponse) return gate
  if (action === 'cancel') return cancelForDeletion({ session }, projectId)
  if (!gate.adminTarget) {
    const stepUp = await requireStepUp(request, stepUpPassword)
    if (stepUp) return stepUp
  }
  return offerForDeletion({ session }, projectId, id, recipient)
})
