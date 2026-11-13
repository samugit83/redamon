/**
 * Ownership transfer with the recipient's acceptance (step 5.12; SH-15, DV-15, DV-40; feature document
 * §6.6): the writers behind /api/projects/[id]/transfer/** and /api/projects/transfers.
 *
 * - Only with write sharing in force (RBAC_SHARING_WRITE_ENABLED, sharing, and Root's policy at Read +
 *   Write): otherwise every transfer route answers 404 having read nothing (DV-30).
 * - The owner offers the project to an active collaborator, with their own password, saying whether
 *   they stay as a co-owner or leave. One open offer per project; it lapses after TRANSFER_OFFER_DAYS.
 *   The recipient accepts with their own password, or declines; the owner may cancel. Nothing here is
 *   done by an admin acting as someone (`transfer_projects`).
 * - Accepting holds the in-process graph lock and the project lock (`transferring`), so no scan, ticket
 *   or settings save starts meanwhile; it is refused with 409 `project_busy`, naming what runs, while an
 *   agent run, a triage or CodeFix run, a scan or a queued job is live (running work keeps the old owner
 *   as its tenant; the offer stays open). Then: the offer is `in_progress` and every socket of the
 *   project is closed (each ticket names the old owner as tenant); the agent re-tenants the graph; one
 *   Postgres transaction moves the project and ends with the status `completed`. When that transaction
 *   fails the graph move is run back; a failed attempt can be accepted again. A failure that may have
 *   left the graph split (the agent's answer lost, a run back that failed) is put right by accepting
 *   again, or undone by a cancel or decline, which runs the graph back first.
 * - Every change writes its audit row in its own transaction (no row, no change); an operator reads
 *   `[rbac] transfer <code> project=<id>` lines for every failure. Both people get a notice.
 */
import { NextResponse } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { auditActorOf, sessionActor, type AuditActor } from '@/lib/auditActor'
import { agentFetch } from '@/lib/agentFetch'
import { closeAgentSockets } from '@/lib/agentSockets'
import { acquireTransferLock, graphHold, refreshTransferLock, releaseTransferLock } from '@/lib/activationLock'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import { GRAPH_LOCK_HOLDER_PHRASE, tryWithGraphLock } from '@/lib/projectGraphLock'
import { withoutUnselectableTemplates, NUCLEI_TEMPLATE_FIELDS, type NucleiTemplateField } from '@/lib/nucleiTemplateOwnership'
import { normalizeUserSkillToggles, trimImportedSkillToggles, UserSkillError } from '@/lib/userSkills'
import { safeErrorCode } from '@/lib/routeErrors'
import type { AuthzIdentity } from '@/lib/session'
import { WS_SOCKETS } from '@/lib/wsTicket'
import { invalidateCache } from '@/app/api/graph/cache'
import { refuseWhileActingAs } from './actAsRefusals'
import { appendNotice, projectTransferNotice } from './accountNotices'
import { now } from './clock'
import { rbacFlags } from './flags'
import type { PermissionContext } from './guards'
import { projectAccess } from './projectAccess'
import { maxShareLevel, sharingPolicyInForce } from './sharingPolicy'
import { requireStepUp } from './stepUp'

export const TRANSFER_PERMISSION = 'project:transfer'
export const TRANSFER_OFFER_DAYS = 7
export const OLD_OWNER_ROLES = ['co-owner', 'leave'] as const
export type OldOwnerRole = (typeof OLD_OWNER_ROLES)[number]
export type TransferStatus = 'pending' | 'in_progress' | 'completed' | 'declined' | 'cancelled' | 'expired' | 'failed'

/** An offer that still waits for an answer (a failed attempt included: it can be accepted again). */
const OPEN: TransferStatus[] = ['pending', 'in_progress', 'failed']
const DAY_MS = 86_400_000
const LIVE_CHECK_TIMEOUT_MS = 5_000
const LOCK_HEARTBEAT_MS = 60_000
const ACTIVE_JOB_STATUSES = ['queued', 'dispatching', 'running']

/**
 * Failures after which the graph may sit partly under each owner: the agent's answer was lost, or a
 * run back failed. Such an offer never lapses on its own; accepting again completes the move, and a
 * cancel or decline runs it back first.
 */
const GRAPH_MAY_HAVE_MOVED = new Set(['agent_unreachable', 'agent_bad_answer', 'retenant_rollback_failed', 'rollback_failed'])

/**
 * The columns a project stores a `custom/<providerId>` model id in, with the value each is set back to
 * when that provider is the old owner's (its Prisma default, ownershipTransfer.test.ts checks them).
 */
export const MODEL_COLUMNS = [
  { field: 'agentOpenaiModel', label: 'Agent model', reset: 'claude-opus-4-6' },
  { field: 'aiPipelineModel', label: 'AI pipeline model', reset: 'claude-opus-4-6' },
  { field: 'cypherfixLlmModel', label: 'CypherFix model', reset: '' },
] as const

const NUCLEI_LABELS: Record<NucleiTemplateField, string> = {
  nucleiSelectedCustomTemplates: 'Nuclei custom templates selected',
  nucleiTemplates: 'Nuclei templates',
  nucleiCustomTemplates: 'Nuclei custom template paths',
}

/** A setting the move cleared because it named the old owner's own provider, templates or token. */
export interface ClearedSetting {
  field: string
  label: string
  /** What it named, when that can be shown: a provider's name, template paths, skill names. */
  values?: string[]
}

export interface TransferPerson {
  id: string
  name: string | null
  email: string | null
}

/** An offer as its screens show it. */
export interface TransferView {
  id: string
  project: { id: string; name: string }
  from: TransferPerson
  to: TransferPerson
  oldOwnerRole: OldOwnerRole
  status: TransferStatus
  error: string | null
  createdAt: string
  expiresAt: string
  decidedAt: string | null
}

/** What the new owner is asked to re-pick, until they dismiss it. */
export interface ClearedView {
  transferId: string
  project: { id: string; name: string }
  from: TransferPerson
  completedAt: string | null
  cleared: ClearedSetting[]
}

type Tx = Prisma.TransactionClient

interface TransferRow {
  id: string
  projectId: string
  fromUserId: string
  toUserId: string
  oldOwnerRole: string
  status: string
  error: string | null
  clearedSettings: unknown
  clearedSeenAt: Date | null
  createdAt: Date
  decidedAt: Date | null
}

const refusal = (status: number, code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status })

const NO_OFFER = () => refusal(409, 'no_transfer_offer', 'There is no open ownership transfer offer for you on this project.')
const EXPIRED = () => refusal(409, 'transfer_expired', 'This ownership transfer offer has expired. Ask the owner to offer it again.')
const alreadyOffered = () => refusal(409, 'transfer_already_offered',
  'This project already has an open transfer offer: cancel it before making another.')
const IN_PROGRESS = () => refusal(409, 'project_transfer_in_progress',
  "This project's ownership is being transferred. Try again in a moment, once it finishes.")

const expiresAt = (row: Pick<TransferRow, 'createdAt'>) => new Date(row.createdAt.getTime() + TRANSFER_OFFER_DAYS * DAY_MS)
const lapsed = (row: TransferRow) =>
  (row.status === 'pending' || (row.status === 'failed' && !GRAPH_MAY_HAVE_MOVED.has(row.error ?? '')))
  && expiresAt(row).getTime() <= now().getTime()

/** The transfer routes exist only with the write switch on; nothing is read to answer 404 otherwise. */
export function transfersSwitchedOff(): boolean {
  return !rbacFlags().sharingWrite
}

/** Write sharing in force: sharing, its policy enabled and at Read + Write (with the switch). */
export async function writeSharingInForce({ fresh = false }: { fresh?: boolean } = {}): Promise<boolean> {
  if (!rbacFlags().sharing) return false
  const policy = await sharingPolicyInForce({ fresh })
  return policy?.enabled === true && maxShareLevel(policy) === 'write'
}

// ---------------------------------------------------------------------------------------------------
// Reading offers

/** The project's open offer (expiring a lapsed one first, audited), or null. */
async function openOffer(projectId: string): Promise<TransferRow | null> {
  const row = await prisma.projectTransfer.findFirst({
    where: { projectId, status: { in: OPEN } },
    orderBy: { createdAt: 'desc' },
  }) as TransferRow | null
  if (!row || !lapsed(row)) return row
  await expire(row)
  return null
}

async function expire(row: TransferRow): Promise<void> {
  try {
    await auditedTransaction(prisma, async (tx) => {
      const { count } = await tx.projectTransfer.updateMany({
        where: { id: row.id, status: row.status },
        data: { status: 'expired', decidedAt: now() },
      })
      if (count !== 1) return
      await writeAuditTx(tx, {
        actorId: null,
        projectId: row.projectId,
        permission: TRANSFER_PERMISSION,
        action: 'project.transfer.expired',
        targetType: 'user',
        targetId: row.toUserId,
        before: { status: row.status, expiresAt: expiresAt(row).toISOString() },
        source: 'system',
      })
    })
  } catch (err) {
    // The offer reads as lapsed either way; the next read writes it.
    console.error(`[rbac] transfer expire_failed project=${row.projectId} code=${safeErrorCode(err)}`)
  }
}

async function people(ids: string[]): Promise<Map<string, TransferPerson>> {
  const rows = await prisma.user.findMany({ where: { id: { in: [...new Set(ids)] } }, select: { id: true, name: true, email: true } })
  return new Map(rows.map((r) => [r.id, { id: r.id, name: r.name ?? null, email: r.email ?? null }]))
}

const personOf = (byId: Map<string, TransferPerson>, id: string): TransferPerson =>
  byId.get(id) ?? { id, name: null, email: null }

function viewOf(row: TransferRow, project: { id: string; name: string }, byId: Map<string, TransferPerson>): TransferView {
  return {
    id: row.id,
    project,
    from: personOf(byId, row.fromUserId),
    to: personOf(byId, row.toUserId),
    oldOwnerRole: row.oldOwnerRole as OldOwnerRole,
    status: row.status as TransferStatus,
    error: row.error,
    createdAt: row.createdAt.toISOString(),
    expiresAt: expiresAt(row).toISOString(),
    decidedAt: row.decidedAt ? row.decidedAt.toISOString() : null,
  }
}

export function readClearedSettings(value: unknown): ClearedSetting[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((v) => {
    if (!v || typeof v !== 'object') return []
    const { field, label, values } = v as Record<string, unknown>
    if (typeof field !== 'string' || typeof label !== 'string') return []
    const list = Array.isArray(values) ? values.filter((x): x is string => typeof x === 'string') : undefined
    return [{ field, label, ...(list ? { values: list } : {}) }]
  })
}

/** The latest transfer that gave `ownerId` this project with a cleared list not yet dismissed. */
async function unseenCleared(projectId: string, ownerId: string): Promise<TransferRow | null> {
  return prisma.projectTransfer.findFirst({
    where: { projectId, toUserId: ownerId, status: 'completed', clearedSeenAt: null },
    orderBy: { decidedAt: 'desc' },
  }) as Promise<TransferRow | null>
}

function clearedViewOf(row: TransferRow, project: { id: string; name: string }, byId: Map<string, TransferPerson>): ClearedView | null {
  const cleared = readClearedSettings(row.clearedSettings)
  if (cleared.length === 0) return null
  return {
    transferId: row.id,
    project,
    from: personOf(byId, row.fromUserId),
    completedAt: row.decidedAt ? row.decidedAt.toISOString() : null,
    cleared,
  }
}

/**
 * GET /api/projects/[id]/transfer: the offer as the asker may see it. The owner sees their open offer
 * and the settings a transfer to them cleared; the recipient sees the offer made to them; anyone else
 * with access to the project sees nothing (`role: 'none'`). No access: 404.
 */
export async function transferStateFor(userId: string, projectId: string): Promise<NextResponse> {
  const access = await projectAccess({ userId }, projectId)
  if (!access) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  const project = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true, name: true } })
  if (!project) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  const offer = await openOffer(projectId)
  const owner = access.level === 'owner' && access.via === 'owner'
  const cleared = owner ? await unseenCleared(projectId, userId) : null
  const role = owner ? 'owner' : offer?.toUserId === userId ? 'recipient' : 'none'
  const visible = role === 'none' ? null : offer
  const byId = await people([visible?.fromUserId, visible?.toUserId, cleared?.fromUserId].filter((x): x is string => !!x))
  return NextResponse.json({
    role,
    offer: visible ? viewOf(visible, project, byId) : null,
    cleared: cleared ? clearedViewOf(cleared, project, byId) : null,
  })
}

/**
 * GET /api/projects/transfers: what the header's banners show the account. Offers made to it (its
 * shared projects), offers it made, and the settings a transfer to it cleared, not yet dismissed.
 */
export async function transfersForAccount(userId: string): Promise<{
  incoming: TransferView[]; outgoing: TransferView[]; cleared: ClearedView[]
}> {
  const rows = await prisma.projectTransfer.findMany({
    where: {
      OR: [
        { toUserId: userId, status: { in: OPEN } },
        { fromUserId: userId, status: { in: OPEN } },
        { toUserId: userId, status: 'completed', clearedSeenAt: null },
      ],
    },
    orderBy: { createdAt: 'desc' },
    take: 50,
  }) as TransferRow[]
  const live: TransferRow[] = []
  for (const row of rows) {
    if (OPEN.includes(row.status as TransferStatus) && lapsed(row)) await expire(row)
    else live.push(row)
  }
  const projects = await prisma.project.findMany({
    where: { id: { in: [...new Set(live.map((r) => r.projectId))] } },
    select: { id: true, name: true, userId: true },
  })
  const byProject = new Map(projects.map((p) => [p.id, p]))
  const byId = await people(live.flatMap((r) => [r.fromUserId, r.toUserId]))
  const incoming: TransferView[] = []
  const outgoing: TransferView[] = []
  const cleared: ClearedView[] = []
  for (const row of live) {
    const project = byProject.get(row.projectId)
    if (!project) continue
    const name = { id: project.id, name: project.name }
    if (row.status === 'completed') {
      // Only while it is still theirs: a project given on again shows its new owner nothing stale.
      const view = project.userId === userId ? clearedViewOf(row, name, byId) : null
      if (view && !cleared.some((c) => c.project.id === project.id)) cleared.push(view)
    } else if (row.toUserId === userId) {
      // Still a collaborator: an offer whose share ended is no offer to show.
      if (await projectAccess({ userId }, project.id)) incoming.push(viewOf(row, name, byId))
    } else if (project.userId === userId) {
      outgoing.push(viewOf(row, name, byId))
    }
  }
  return { incoming, outgoing, cleared }
}

// ---------------------------------------------------------------------------------------------------
// Offer, cancel, decline, dismiss

type RecipientProblem = 'recipient_not_collaborator' | 'account_not_active'

/** The recipient as a transfer needs them: an active account holding a share of the project that has not expired. */
async function recipientProblem(db: Pick<Tx, 'projectCollaborator' | 'user'>, projectId: string, userId: string): Promise<RecipientProblem | null> {
  const share = await db.projectCollaborator.findUnique({
    where: { projectId_userId: { projectId, userId } },
    select: { expiresAt: true },
  })
  if (!share || (share.expiresAt !== null && share.expiresAt.getTime() <= now().getTime())) return 'recipient_not_collaborator'
  const account = await db.user.findUnique({ where: { id: userId }, select: { status: true } })
  return account?.status === 'active' ? null : 'account_not_active'
}

function recipientRefusal(problem: RecipientProblem): NextResponse {
  return problem === 'recipient_not_collaborator'
    ? refusal(409, problem, 'The project can only go to one of its current collaborators.')
    : refusal(409, problem, 'This account is not active: it cannot receive the project.')
}

class Refused extends Error {
  constructor(readonly response: NextResponse) {
    super('refused')
  }
}

async function refusable<T>(run: () => Promise<T>): Promise<T | NextResponse> {
  try {
    return await run()
  } catch (err) {
    if (err instanceof Refused) return err.response
    throw err
  }
}

/** One writer of a project's offers at a time, across copies (two offers at once make one). */
async function lockOffers(tx: Tx, projectId: string): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`project_transfer:${projectId}`}))`
}

function actorOf(identity: Pick<AuthzIdentity, 'session'>, effectiveUserId: string): AuditActor {
  return auditActorOf(sessionActor(identity.session), effectiveUserId)
}

/**
 * POST /api/projects/[id]/transfer `{toUserId, oldOwnerRole, stepUpPassword}`: the owner offers the
 * project to one of its active collaborators. The route checked `project:transfer` (the owner only).
 */
export async function offerTransfer(request: Request, auth: PermissionContext, body: Record<string, unknown>): Promise<NextResponse> {
  const access = auth.access
  if (!access) throw new Error('[rbac] a transfer route checked no project')
  const projectId = access.project.id
  const ownerId = access.project.userId
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: ownerId }, 'transfer_projects')
  if (acting) return acting
  const { toUserId, oldOwnerRole } = body
  if (typeof toUserId !== 'string' || !toUserId) {
    return refusal(400, 'invalid_field', 'Name the collaborator to give the project to (toUserId).', { field: 'toUserId' })
  }
  if (typeof oldOwnerRole !== 'string' || !(OLD_OWNER_ROLES as readonly string[]).includes(oldOwnerRole)) {
    return refusal(400, 'invalid_field', 'oldOwnerRole must be "co-owner" or "leave".', { field: 'oldOwnerRole' })
  }
  if (toUserId === ownerId) return refusal(400, 'own_account', 'You own this project already: pick one of its collaborators.')
  const recipient = await recipientProblem(prisma, projectId, toUserId)
  if (recipient) return recipientRefusal(recipient)
  if (await openOffer(projectId)) return alreadyOffered()
  const stepUp = await requireStepUp(request, body.stepUpPassword)
  if (stepUp) return stepUp

  const created = await refusable(() => auditedTransaction(prisma, async (tx) => {
    await lockOffers(tx, projectId)
    const open = await tx.projectTransfer.findFirst({ where: { projectId, status: { in: OPEN } } }) as TransferRow | null
    if (open && !lapsed(open)) throw new Refused(alreadyOffered())
    if (open) {
      await tx.projectTransfer.updateMany({ where: { id: open.id, status: open.status }, data: { status: 'expired', decidedAt: now() } })
      await writeAuditTx(tx, {
        actorId: null, projectId, permission: TRANSFER_PERMISSION, action: 'project.transfer.expired',
        targetType: 'user', targetId: open.toUserId, before: { status: open.status }, source: 'system',
      })
    }
    const problem = await recipientProblem(tx, projectId, toUserId)
    if (problem) throw new Refused(recipientRefusal(problem))
    const row = await tx.projectTransfer.create({
      data: { projectId, fromUserId: ownerId, toUserId, oldOwnerRole, status: 'pending' },
    }) as TransferRow
    await writeAuditTx(tx, {
      ...actorOf(auth, auth.effective.userId),
      projectId,
      permission: TRANSFER_PERMISSION,
      action: 'project.transfer.offer',
      targetType: 'user',
      targetId: toUserId,
      after: { transferId: row.id, oldOwnerRole, expiresAt: expiresAt(row).toISOString() },
      source: 'api',
    })
    return row
  }))
  if (created instanceof NextResponse) return created
  const project = await prisma.project.findUnique({ where: { id: projectId }, select: { id: true, name: true } })
  const byId = await people([ownerId, toUserId])
  return NextResponse.json({ offer: viewOf(created, project ?? { id: projectId, name: '' }, byId) }, { status: 201 })
}

/**
 * Ends an open offer without a transfer: the owner's cancel or the recipient's decline. An attempt that
 * may have left the graph split is first run back, under the same locks an accept takes.
 */
async function withdraw(
  identity: Pick<AuthzIdentity, 'session'>,
  effectiveUserId: string,
  projectId: string,
  by: 'owner' | 'recipient',
): Promise<NextResponse> {
  const offer = await openOffer(projectId)
  if (!offer || (by === 'recipient' && offer.toUserId !== effectiveUserId)) return NO_OFFER()
  if (offer.status === 'in_progress' && (await graphHold(projectId)) === 'transferring') return IN_PROGRESS()
  // A failed attempt that may have moved part of the graph, or one a crashed copy left in progress.
  if ((offer.status === 'failed' && GRAPH_MAY_HAVE_MOVED.has(offer.error ?? '')) || offer.status === 'in_progress') {
    const back = await runBackUnderLocks(offer)
    if (back) return back
  }
  const status = by === 'owner' ? 'cancelled' : 'declined'
  const done = await auditedTransaction(prisma, async (tx) => {
    await lockOffers(tx, projectId)
    const { count } = await tx.projectTransfer.updateMany({
      where: { id: offer.id, status: { in: ['pending', 'failed', 'in_progress'] } },
      data: { status, decidedAt: now() },
    })
    if (count !== 1) return false
    await writeAuditTx(tx, {
      ...actorOf(identity, effectiveUserId),
      projectId,
      permission: TRANSFER_PERMISSION,
      action: by === 'owner' ? 'project.transfer.cancel' : 'project.transfer.decline',
      targetType: 'user',
      targetId: offer.toUserId,
      before: { transferId: offer.id, status: offer.status },
      source: 'api',
    })
    return true
  })
  if (!done) return NO_OFFER()
  return NextResponse.json({ withdrawn: true, status })
}

/**
 * The reverse re-tenant of an attempt that may have moved part of the graph (an answer lost, a failed
 * run back), held like an accept: a scan writing meanwhile would write under the old owner too, but a
 * key both owners hold would refuse the move. Null when done, else the answer to return.
 */
async function runBackUnderLocks(offer: TransferRow): Promise<NextResponse | null> {
  const held = await tryWithGraphLock(offer.projectId, 'transfer', async () => {
    if (!(await acquireTransferLock(offer.projectId, offer.id, offer.fromUserId))) return lockRefusal(offer.projectId)
    try {
      const back = await retenant(offer.projectId, offer.toUserId, offer.fromUserId)
      if (back.ok) return null
      console.error(`[rbac] transfer run_back_failed project=${offer.projectId} transfer=${offer.id} code=${back.code}`)
      return refusal(502, 'run_back_failed',
        "The project's graph could not be moved back to its owner, so the offer stays open. Try again, or accept it to complete the transfer.",
        { cause: back.code })
    } finally {
      await releaseTransferLock(offer.projectId)
    }
  })
  return held.acquired ? held.value : busyResponse(GRAPH_LOCK_HOLDER_PHRASE[held.heldBy])
}

/** POST /api/projects/[id]/transfer/cancel: the owner withdraws the open offer. */
export async function cancelTransfer(auth: PermissionContext): Promise<NextResponse> {
  const access = auth.access
  if (!access) throw new Error('[rbac] a transfer route checked no project')
  const acting = await refuseWhileActingAs({ session: auth.session, targetUserId: access.project.userId }, 'transfer_projects')
  if (acting) return acting
  return withdraw(auth, auth.effective.userId, access.project.id, 'owner')
}

/** The recipient's own routes: the person signed in, never an admin acting as them; 404 without access. */
async function recipientContext(identity: AuthzIdentity, projectId: string): Promise<{ userId: string } | Response> {
  const acting = await refuseWhileActingAs({ session: identity.session }, 'transfer_projects')
  if (acting) return acting
  const userId = (identity.actingAs ?? identity.principal).id
  if (!(await projectAccess({ userId }, projectId, { fresh: true, principal: identity.principal }))) {
    return NextResponse.json({ error: 'Not found' }, { status: 404 })
  }
  return { userId }
}

/** POST /api/projects/[id]/transfer/decline: the recipient turns the offer down. */
export async function declineTransfer(identity: AuthzIdentity, projectId: string): Promise<NextResponse> {
  const me = await recipientContext(identity, projectId)
  if (me instanceof Response) return me as NextResponse
  return withdraw(identity, me.userId, projectId, 'recipient')
}

/** POST /api/projects/[id]/transfer/acknowledge: the new owner dismisses the list of settings to re-pick. */
export async function acknowledgeCleared(auth: PermissionContext): Promise<NextResponse> {
  const access = auth.access
  if (!access) throw new Error('[rbac] a transfer route checked no project')
  const { count } = await prisma.projectTransfer.updateMany({
    where: { projectId: access.project.id, toUserId: access.project.userId, status: 'completed', clearedSeenAt: null },
    data: { clearedSeenAt: now() },
  })
  return NextResponse.json({ acknowledged: count })
}

// ---------------------------------------------------------------------------------------------------
// Accept

/** Why the project lock could not be taken: another transfer, an activation, or the project changed owner. */
async function lockRefusal(projectId: string): Promise<NextResponse> {
  const hold = await graphHold(projectId)
  if (hold === 'transferring') return IN_PROGRESS()
  if (hold === 'activating') return busyResponse('a version activation is in progress')
  return NO_OFFER()
}

function busyResponse(busy: string): NextResponse {
  return refusal(409, 'project_busy',
    `The project cannot change owner while ${busy}. Stop it, or wait for it to finish, and accept again: the offer stays open.`,
    { busy })
}

/**
 * What runs on the project now, or null. Fail closed: what cannot be verified is reported as running.
 * The graph writers (scans, partial recon, GVM, GitHub hunt, TruffleHog, supply chain, AI attack
 * surface, a triage run, a flagged agent session, a node-filter apply), the agent's own view (any run
 * it holds, flagged or not, and the CodeFix runs, which exist only as their socket), and the queue.
 */
export async function transferBusy(projectId: string): Promise<string | null> {
  const writer = await describeLiveGraphWriters(projectId)
  if (writer) return writer
  let res: Response
  try {
    res = await agentFetch(`/agent-sessions/project-work?project_id=${encodeURIComponent(projectId)}`, { method: 'GET' },
      { timeoutMs: LIVE_CHECK_TIMEOUT_MS })
  } catch {
    return "the agent's live work could not be verified"
  }
  const work = res.ok ? await res.json().catch(() => null) as Record<string, unknown> | null : null
  if (!work || !Array.isArray(work.session_ids) || typeof work.codefix_sockets !== 'number' || typeof work.triage_run !== 'boolean') {
    return "the agent's live work could not be verified"
  }
  if (work.session_ids.length > 0) return 'an agent session is running'
  if (work.codefix_sockets > 0) return 'a CodeFix run is in progress'
  if (work.triage_run) return 'a triage run is in progress'
  const queued = await prisma.jobQueue.count({ where: { projectId, status: { in: ACTIVE_JOB_STATUSES } } })
  return queued > 0 ? 'a queued scan is waiting to run' : null
}

type RetenantOutcome =
  | { ok: true; totalNodes: number; relationships: number }
  | { ok: false; code: string; status: number; busy?: unknown }

/** The agent's POST /graph/retenant. No time limit: a lost answer would leave the move's outcome unknown. */
async function retenant(projectId: string, fromUserId: string, toUserId: string): Promise<RetenantOutcome> {
  let res: Response
  try {
    res = await agentFetch('/graph/retenant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: projectId, from_user_id: fromUserId, to_user_id: toUserId }),
    }, { timeoutMs: 0 })
  } catch {
    return { ok: false, code: 'agent_unreachable', status: 502 }
  }
  const body = await res.json().catch(() => null) as Record<string, unknown> | null
  if (res.ok) {
    if (!body || typeof body.total_nodes !== 'number') return { ok: false, code: 'agent_bad_answer', status: 502 }
    return { ok: true, totalNodes: body.total_nodes, relationships: typeof body.relationships === 'number' ? body.relationships : 0 }
  }
  const code = typeof body?.code === 'string' ? body.code : 'agent_bad_answer'
  return { ok: false, code, status: res.status, ...(body?.busy ? { busy: body.busy } : {}) }
}

/** Ends an attempt as `failed` with its code (audited); the offer can be accepted again. */
async function failAttempt(offer: TransferRow, actor: AuditActor, code: string): Promise<void> {
  console.error(`[rbac] transfer ${code} project=${offer.projectId} transfer=${offer.id}`)
  try {
    await auditedTransaction(prisma, async (tx) => {
      const { count } = await tx.projectTransfer.updateMany({
        where: { id: offer.id, status: 'in_progress' },
        data: { status: 'failed', error: code },
      })
      if (count !== 1) return
      await writeAuditTx(tx, {
        ...actor,
        projectId: offer.projectId,
        permission: TRANSFER_PERMISSION,
        action: 'project.transfer.failed',
        targetType: 'user',
        targetId: offer.toUserId,
        after: { transferId: offer.id, error: code },
        source: 'api',
      })
    })
  } catch (err) {
    console.error(`[rbac] transfer status_write_failed project=${offer.projectId} transfer=${offer.id} code=${safeErrorCode(err)}`)
  }
}

const FAILURE_ANSWERS: Record<string, [number, string]> = {
  project_busy: [409, 'The agent started work on the project while it was changing owner. Nothing moved; accept again once it ends.'],
  retenant_conflict: [409, "Nodes the new owner already holds in this project collide with the project's own. Nothing moved."],
  socket_close_failed: [503, "The agent could not confirm that the project's open connections closed. Nothing moved; accept again."],
  graph_unavailable: [503, 'The graph database could not be reached. Nothing moved; accept again.'],
  agent_not_ready: [503, 'The agent is not ready. Nothing moved; accept again.'],
  retenant_failed: [502, "The project's graph could not be moved and was put back. Nothing changed; accept again."],
  postgres_failed: [500, "The project could not be moved to the new owner, and its graph was put back. Nothing changed; accept again."],
  recipient_not_collaborator: [409, 'You no longer hold a share of this project, so it cannot be given to you. Its graph was put back.'],
  account_not_active: [409, 'Your account is not active, so the project cannot be given to you. Its graph was put back.'],
  owner_changed: [409, "The project's owner changed meanwhile. Its graph was put back."],
}

function failureResponse(code: string, status?: number): NextResponse {
  const known = FAILURE_ANSWERS[code]
  if (known) return refusal(known[0], code, known[1])
  // The graph may sit partly under each owner: accepting again completes the move.
  return refusal(status && status >= 500 ? status : 502, code,
    "The transfer did not complete and the project's graph may be partly moved. Accept again to complete it, or decline to put it back.")
}

/** Thrown inside the Postgres move to roll it back with a code. */
class MoveAborted extends Error {
  constructor(readonly code: string) {
    super(code)
  }
}

/**
 * POST /api/projects/[id]/transfer/accept `{stepUpPassword}`: the recipient takes the project. The
 * project's graph moves first, then Postgres in one transaction with the status; either the transfer
 * completes everywhere or the project stays as it was (a lost answer excepted, which accepting again
 * completes).
 */
export async function acceptTransfer(request: Request, identity: AuthzIdentity, projectId: string, stepUpPassword: unknown): Promise<NextResponse> {
  const me = await recipientContext(identity, projectId)
  if (me instanceof Response) return me as NextResponse
  const offer = await openOffer(projectId)
  if (!offer || offer.toUserId !== me.userId) return NO_OFFER()
  if (offer.status === 'in_progress' && (await graphHold(projectId)) === 'transferring') return IN_PROGRESS()
  const eligible = await recipientProblem(prisma, projectId, me.userId)
  if (eligible) return recipientRefusal(eligible)
  const stepUp = await requireStepUp(request, stepUpPassword)
  if (stepUp) return stepUp
  const actor = actorOf(identity, me.userId)

  const held = await tryWithGraphLock(projectId, 'transfer', () => acceptUnderLock(offer, actor))
  if (held.acquired) return held.value
  return held.heldBy === 'transfer' ? IN_PROGRESS() : busyResponse(GRAPH_LOCK_HOLDER_PHRASE[held.heldBy])
}

async function acceptUnderLock(offer: TransferRow, actor: AuditActor): Promise<NextResponse> {
  const { projectId } = offer
  if (!(await acquireTransferLock(projectId, offer.id, offer.fromUserId))) return lockRefusal(projectId)
  const beat = setInterval(() => { void refreshTransferLock(projectId).catch(() => undefined) }, LOCK_HEARTBEAT_MS)
  try {
    const busy = await transferBusy(projectId)
    if (busy) return busyResponse(busy)

    const started = await auditedTransaction(prisma, async (tx) => {
      await lockOffers(tx, projectId)
      const { count } = await tx.projectTransfer.updateMany({
        where: { id: offer.id, status: offer.status },
        data: { status: 'in_progress', error: null },
      })
      if (count !== 1) return false
      await writeAuditTx(tx, {
        ...actor,
        projectId,
        permission: TRANSFER_PERMISSION,
        action: 'project.transfer.accept',
        targetType: 'user',
        targetId: offer.toUserId,
        before: { transferId: offer.id, status: offer.status },
        after: { status: 'in_progress' },
        source: 'api',
      })
      return true
    })
    if (!started) return NO_OFFER()

    // Every open ticket names the old owner as the graph's tenant: one left open would write there.
    const closed = await closeAgentSockets({ projectId, kinds: [...WS_SOCKETS] })
    if (!closed.ok) {
      await failAttempt(offer, actor, 'socket_close_failed')
      return failureResponse('socket_close_failed')
    }

    const moved = await retenant(projectId, offer.fromUserId, offer.toUserId)
    if (!moved.ok) {
      await failAttempt(offer, actor, moved.code)
      return failureResponse(moved.code, moved.status)
    }
    await refreshTransferLock(projectId)

    let completed: { cleared: ClearedSetting[]; projectName: string }
    try {
      completed = await auditedTransaction(prisma, (tx) => moveInPostgres(tx, offer, actor, moved))
    } catch (err) {
      const code = err instanceof MoveAborted ? err.code : 'postgres_failed'
      if (!(err instanceof MoveAborted)) console.error(`[rbac] transfer postgres_failed project=${projectId} code=${safeErrorCode(err)}`)
      const back = await retenant(projectId, offer.toUserId, offer.fromUserId)
      if (!back.ok) {
        console.error(`[rbac] transfer rollback_failed project=${projectId} transfer=${offer.id} code=${back.code}`)
        await failAttempt(offer, actor, 'rollback_failed')
        return failureResponse('rollback_failed', 500)
      }
      await failAttempt(offer, actor, code)
      return failureResponse(code)
    }

    invalidateCache(projectId)
    await tellBoth(offer, completed.projectName, completed.cleared.length)
    return NextResponse.json({
      transferred: { projectId, from: offer.fromUserId, to: offer.toUserId, oldOwnerRole: offer.oldOwnerRole },
      cleared: completed.cleared,
      graph: { nodes: moved.totalNodes, relationships: moved.relationships },
    })
  } finally {
    clearInterval(beat)
    await releaseTransferLock(projectId)
  }
}

/** Notices to both people, best effort: the transfer stands when one cannot be written (logged). */
async function tellBoth(offer: TransferRow, projectName: string, clearedCount: number): Promise<void> {
  const byId = await people([offer.fromUserId, offer.toUserId]).catch(() => new Map<string, TransferPerson>())
  const label = (id: string) => {
    const p = byId.get(id)
    return { id, name: p?.name ?? '', email: p?.email ?? '' }
  }
  const at = now()
  const project = { id: offer.projectId, name: projectName }
  const oldOwnerRole = offer.oldOwnerRole as OldOwnerRole
  for (const [userId, notice] of [
    [offer.fromUserId, projectTransferNotice({ at, by: label(offer.toUserId), project, direction: 'given', oldOwnerRole, cleared: 0 })],
    [offer.toUserId, projectTransferNotice({ at, by: label(offer.fromUserId), project, direction: 'received', oldOwnerRole, cleared: clearedCount })],
  ] as const) {
    try {
      await appendNotice(userId, notice)
    } catch (err) {
      console.error(`[rbac] transfer notice_failed project=${offer.projectId} user=${userId} code=${safeErrorCode(err)}`)
    }
  }
}

const PROJECT_SELECT = {
  userId: true, name: true, jevProviderId: true, attackSkillConfig: true, cypherfixGithubToken: true,
  agentOpenaiModel: true, aiPipelineModel: true, cypherfixLlmModel: true,
  nucleiSelectedCustomTemplates: true, nucleiTemplates: true, nucleiCustomTemplates: true,
} as const

type MovingProject = { userId: string; name: string } & Record<string, unknown>

/**
 * The project columns that name something of the old owner's own, which the new owner cannot use: a
 * `custom/<providerId>` model of the old owner's providers (set back to its default), the Jev provider,
 * the user attack-skill toggles (normalizeUserSkillToggles keeps only the new owner's skills), the old
 * owner's own Nuclei templates (an instance template stays) and the CypherFix GitHub token (a person's
 * credential never passes on). Tradecraft has no project column; target credentials stay with the
 * engagement.
 */
export async function clearedForNewOwner(tx: Tx, project: MovingProject, newOwnerId: string): Promise<{
  data: Record<string, unknown>; cleared: ClearedSetting[]
}> {
  const data: Record<string, unknown> = {}
  const cleared: ClearedSetting[] = []

  const providerIds = [
    ...MODEL_COLUMNS.map((c) => project[c.field]).filter((v): v is string => typeof v === 'string' && v.startsWith('custom/'))
      .map((v) => v.slice('custom/'.length)),
    ...(typeof project.jevProviderId === 'string' ? [project.jevProviderId] : []),
  ]
  const providers = providerIds.length
    ? await tx.userLlmProvider.findMany({ where: { id: { in: providerIds } }, select: { id: true, userId: true, name: true } })
    : []
  const providerById = new Map(providers.map((p) => [p.id, p]))
  const foreign = (id: string) => providerById.get(id)?.userId !== newOwnerId
  const providerName = (id: string) => providerById.get(id)?.name
  for (const column of MODEL_COLUMNS) {
    const value = project[column.field]
    if (typeof value !== 'string' || !value.startsWith('custom/')) continue
    const id = value.slice('custom/'.length)
    if (!foreign(id)) continue
    data[column.field] = column.reset
    const name = providerName(id)
    cleared.push({ field: column.field, label: column.label, ...(name ? { values: [name] } : {}) })
  }
  if (typeof project.jevProviderId === 'string' && foreign(project.jevProviderId)) {
    data.jevProviderId = null
    const name = providerName(project.jevProviderId)
    cleared.push({ field: 'jevProviderId', label: 'TypeSafe Jev provider', ...(name ? { values: [name] } : {}) })
  }

  const config = project.attackSkillConfig as { user?: Record<string, unknown> } | null
  const toggles = config && typeof config === 'object' && config.user && typeof config.user === 'object' ? config.user : {}
  if (Object.keys(toggles).length > 0) {
    let next: { user?: Record<string, boolean> } | undefined
    try {
      next = await normalizeUserSkillToggles(tx, newOwnerId, project.attackSkillConfig)
    } catch (err) {
      if (!(err instanceof UserSkillError)) throw err
      next = (await trimImportedSkillToggles(tx, newOwnerId, project.attackSkillConfig)).value
    }
    if (next) {
      const kept = new Set(Object.keys(next.user ?? {}))
      const droppedOn = Object.keys(toggles).filter((id) => !kept.has(id) && toggles[id] === true)
      if (Object.keys(toggles).some((id) => !kept.has(id))) data.attackSkillConfig = next
      if (droppedOn.length) {
        const skills = await tx.userAttackSkill.findMany({ where: { id: { in: droppedOn } }, select: { name: true } })
        cleared.push({ field: 'attackSkillConfig', label: 'Agent skills of the previous owner that were on', values: skills.map((s) => s.name).sort() })
      }
    }
  }

  const { project: kept, dropped } = await withoutUnselectableTemplates<MovingProject>(tx, { ...project, userId: newOwnerId })
  for (const field of NUCLEI_TEMPLATE_FIELDS) {
    if (!dropped[field]) continue
    const before = Array.isArray(project[field]) ? (project[field] as unknown[]).filter((v): v is string => typeof v === 'string') : []
    const after = new Set((kept[field] as string[] | undefined) ?? [])
    data[field] = [...after]
    cleared.push({ field, label: NUCLEI_LABELS[field], values: before.filter((v) => !after.has(v)) })
  }

  if (typeof project.cypherfixGithubToken === 'string' && project.cypherfixGithubToken !== '') {
    data.cypherfixGithubToken = ''
    cleared.push({ field: 'cypherfixGithubToken', label: 'CypherFix GitHub token' })
  }
  return { data, cleared }
}

/**
 * Step (3), in the caller's transaction: the project, its shares, its captured traffic, the old owner's
 * schedules, the consent, the authenticated-session profile's owner, the conversations that follow the
 * owner, and the settings that named the old owner's own things; then the status `completed` and its
 * audit row. Any refusal throws (MoveAborted), rolling it all back.
 */
async function moveInPostgres(
  tx: Tx,
  offer: TransferRow,
  actor: AuditActor,
  graph: { totalNodes: number; relationships: number },
): Promise<{ cleared: ClearedSetting[]; projectName: string }> {
  const { projectId, fromUserId: from, toUserId: to } = offer
  const project = await tx.project.findUnique({ where: { id: projectId }, select: PROJECT_SELECT }) as MovingProject | null
  if (!project || project.userId !== from) throw new MoveAborted('owner_changed')
  const recipient = await recipientProblem(tx, projectId, to)
  if (recipient) throw new MoveAborted(recipient)

  const { data, cleared } = await clearedForNewOwner(tx, project, to)
  const { count } = await tx.project.updateMany({ where: { id: projectId, userId: from }, data: { ...data, userId: to, updatedById: to } as Prisma.ProjectUncheckedUpdateManyInput })
  if (count !== 1) throw new MoveAborted('owner_changed')

  await tx.projectCollaborator.deleteMany({ where: { projectId, userId: { in: [to, from] } } })
  if (offer.oldOwnerRole === 'co-owner') {
    await tx.projectCollaborator.create({
      data: {
        projectId, userId: from, access: 'write', rawData: true, runScans: true, useAgent: true, exploit: true, manage: true,
        grantedById: to, note: 'Previous owner of the project',
      },
    })
  }
  const traffic = await tx.capturedHttpTransaction.updateMany({ where: { projectId, userId: from }, data: { userId: to } })
  // A schedule runs as the person who set it up; the old owner's wait for a confirmation, which makes the
  // confirmer its actor (step 5.5). The other collaborators' schedules keep running as them.
  const paused = await tx.scanSchedule.updateMany({
    where: { projectId, userId: from, enabled: true },
    data: { enabled: false, pausedReason: 'ownership_transferred' },
  })
  // The consent named the old owner's keys; the new owner's are spent only once they consent.
  await tx.projectAccessPolicy.updateMany({
    where: { projectId },
    data: { ownerCredentialConsentAt: null, ownerCredentialConsentById: null },
  })
  await tx.projectAuthProfile.updateMany({ where: { projectId, userId: from }, data: { userId: to } })
  // Conversations reassigned to the project's owner from a deleted account (T24) follow the project;
  // a leaving owner's own conversations stay with the project too, keeping who wrote them, as T24 does.
  const inherited = await tx.conversation.updateMany({
    where: { projectId, userId: from, formerAuthorId: { not: null } },
    data: { userId: to },
  })
  let reassigned = 0
  if (offer.oldOwnerRole === 'leave') {
    const author = await tx.user.findUnique({ where: { id: from }, select: { name: true, email: true } })
    reassigned = (await tx.conversation.updateMany({
      where: { projectId, userId: from },
      data: { userId: to, formerAuthorId: from, formerAuthorLabel: author?.name || author?.email || from },
    })).count
  }

  const { count: done } = await tx.projectTransfer.updateMany({
    where: { id: offer.id, status: 'in_progress' },
    // Nothing to re-pick is nothing to show: such a list reads as seen.
    data: {
      status: 'completed', decidedAt: now(), error: null,
      clearedSettings: cleared as unknown as Prisma.InputJsonValue, clearedSeenAt: cleared.length ? null : now(),
    },
  })
  if (done !== 1) throw new MoveAborted('owner_changed')
  await writeAuditTx(tx, {
    ...actor,
    projectId,
    permission: TRANSFER_PERMISSION,
    action: 'project.transfer.completed',
    targetType: 'project',
    targetId: projectId,
    before: { ownerId: from },
    after: {
      ownerId: to,
      transferId: offer.id,
      oldOwnerRole: offer.oldOwnerRole,
      cleared: cleared.map((c) => c.field),
      moved: {
        graphNodes: graph.totalNodes, graphRelationships: graph.relationships, traffic: traffic.count,
        schedulesPaused: paused.count, conversations: inherited.count + reassigned,
      },
    },
    source: 'api',
  })
  return { cleared, projectName: project.name }
}
