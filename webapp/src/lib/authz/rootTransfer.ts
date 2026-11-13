/**
 * Root transfer (step 2.6, ID-07; feature document §4.4): the confirmed Root offers Root to an
 * admin who can sign in, with Root's own password; the offer lasts ROOT_TRANSFER_OFFER_HOURS; the
 * admin accepts with its own password, or declines; Root may cancel. Accepting moves Root
 * (confirmed, `rootAssignedBy: transfer`), raises both accounts' session versions so both sign
 * in again (a stolen Root cookie does not outlive the transfer) and closes their sockets; the old
 * Root stays a Full admin. The offer lives in the instance settings row
 * (`pendingRootTransferTo`, `pendingRootTransferExpires`).
 *
 * Every write takes the Root lock (root.ts ROOT_LOCK, the boot backfill's and the host
 * commands'), reads the Root and the offer again under it and writes conditionally, with its
 * audit row in the same transaction (fail closed): two accepts make one transfer, and a host
 * set-root (which clears the offer) or a boot landing in between is seen. Only reached with the
 * identity switch on (the routes answer 404 without it).
 */
import { NextResponse, type NextRequest } from 'next/server'
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { userAuditEntry, type UserAuditFields } from '@/lib/userAudit'
import type { Session } from '@/lib/session'
import { now } from './clock'
import { INSTANCE_SETTINGS_ROW, invalidateInstanceRoot, loadInstanceRoot, lockedInstanceRoot } from './root'
import { invalidatePrincipal } from './principal'
import { rootOnlyRefusal, rootStanding } from './rootPowers'
import { requireStepUp } from './stepUp'
import { agentWorkOf, onAccessReduced, type AgentWorkEnded } from './revocation'

/** `requireAdmin`'s 403, coded with the permission a transfer needs (master §9.8); any other answer as is. */
export function transferForbidden(res: NextResponse): NextResponse {
  if (res.status !== 403) return res
  return NextResponse.json(
    { error: 'Only Root and the admin it offers Root to take part in a Root transfer.', code: 'forbidden', permission: 'root:transfer' },
    { status: 403 },
  )
}

/** How long an offer waits for the recipient. */
export const ROOT_TRANSFER_OFFER_HOURS = 24

const ROOT_ONLY = 'Only Root can transfer Root.'

type Tx = Prisma.TransactionClient

const answer = (status: number, code: string, error: string) => NextResponse.json({ error, code }, { status })

const NO_OFFER = () => answer(409, 'no_transfer_offer', 'There is no Root transfer offer for this account.')
const EXPIRED = () => answer(409, 'transfer_expired', 'The Root transfer offer has expired. Ask Root to offer it again.')
const CANNOT_SIGN_IN = () => answer(400, 'target_cannot_sign_in', 'Root can only go to an active admin with a password.')

/** The pending offer as stored, or null; an expired one is still returned (the caller tells). */
async function readOffer(db: Pick<Tx, 'instanceSettings'> = prisma) {
  const row = await db.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { rootUserId: true, pendingRootTransferTo: true, pendingRootTransferExpires: true },
  })
  if (!row?.pendingRootTransferTo || !row.pendingRootTransferExpires) return row ? { ...row, pending: null } : null
  return { ...row, pending: { toUserId: row.pendingRootTransferTo, expiresAt: row.pendingRootTransferExpires } }
}

const expired = (expiresAt: Date) => expiresAt.getTime() <= now().getTime()

/** An admin who can sign in: the only account Root may go to. */
function eligible(account: { role: string; status: string; password: string } | null): boolean {
  return !!account && account.role === 'admin' && account.status === 'active' && account.password !== ''
}

async function audit(tx: Tx, request: NextRequest, session: Session, entry: UserAuditFields): Promise<void> {
  await writeAuditTx(tx, await userAuditEntry(request, session, entry))
}

/** Thrown inside a transaction to roll it back and answer `response`. */
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

/** What the header tells Root and the recipient about a pending offer; nobody else learns of it. */
export async function pendingTransferFor(session: Session): Promise<{
  toUserId: string; toEmail: string; fromEmail: string; expiresAt: string; forYou: boolean
} | null> {
  const row = await readOffer()
  if (!row?.pending || expired(row.pending.expiresAt)) return null
  const forYou = row.pending.toUserId === session.userId
  if (!forYou && row.rootUserId !== session.userId) return null
  const root = await loadInstanceRoot({ fresh: true })
  if (!root || root.userId !== row.rootUserId) return null
  const to = await prisma.user.findUnique({ where: { id: row.pending.toUserId }, select: { email: true } })
  if (!to) return null
  return { toUserId: row.pending.toUserId, toEmail: to.email, fromEmail: root.email, expiresAt: row.pending.expiresAt.toISOString(), forYou }
}

/** POST /api/root/transfer: the confirmed Root offers Root to `targetUserId`, with its password. */
export async function offerRootTransfer(
  request: NextRequest, session: Session, targetUserId: unknown, stepUpPassword: unknown,
): Promise<NextResponse> {
  const standing = await rootStanding(session.userId)
  if (standing !== 'confirmed') return rootOnlyRefusal(standing, ROOT_ONLY)
  if (typeof targetUserId !== 'string' || !targetUserId) {
    return answer(400, 'target_required', 'Name the admin to transfer Root to (targetUserId).')
  }
  if (targetUserId === session.userId) return answer(400, 'own_account', 'You are Root already: pick another admin.')
  const select = { role: true, status: true, password: true } as const
  const target = await prisma.user.findUnique({ where: { id: targetUserId }, select })
  if (!target) return answer(404, 'user_not_found', 'User not found')
  if (target.role !== 'admin') {
    return answer(400, 'target_not_admin', 'Root can only go to an admin: make the account an admin first.')
  }
  if (!eligible(target)) return CANNOT_SIGN_IN()
  const refusal = await requireStepUp(request, stepUpPassword)
  if (refusal) return refusal

  const expiresAt = new Date(now().getTime() + ROOT_TRANSFER_OFFER_HOURS * 60 * 60 * 1000)
  const offered = await refusable(() => auditedTransaction(prisma, async (tx) => {
    const root = await lockedInstanceRoot(tx)
    if (!root || root.userId !== session.userId || !root.confirmed) throw new Refused(rootOnlyRefusal('none', ROOT_ONLY))
    if (!eligible(await tx.user.findUnique({ where: { id: targetUserId }, select }))) throw new Refused(CANNOT_SIGN_IN())
    const previous = (await readOffer(tx))?.pending ?? null
    await tx.instanceSettings.update({
      where: { id: INSTANCE_SETTINGS_ROW },
      data: { pendingRootTransferTo: targetUserId, pendingRootTransferExpires: expiresAt, updatedById: session.userId },
    })
    await audit(tx, request, session, {
      action: 'root.transfer_offered',
      targetId: targetUserId,
      before: { toUserId: previous?.toUserId ?? null },
      after: { toUserId: targetUserId, expiresAt: expiresAt.toISOString() },
    })
  }))
  if (offered instanceof NextResponse) return offered
  return NextResponse.json({ offered: true, toUserId: targetUserId, expiresAt: expiresAt.toISOString() })
}

/**
 * POST /api/root/transfer/accept: the recipient takes Root, with its own password. Both
 * accounts sign in again; this browser's cookies are cleared by the route.
 */
export async function acceptRootTransfer(
  request: NextRequest, session: Session, stepUpPassword: unknown,
): Promise<NextResponse | { rootUserId: string; previousRootUserId: string; agent: Record<string, AgentWorkEnded> }> {
  const offer = (await readOffer())?.pending
  if (!offer || offer.toUserId !== session.userId) return NO_OFFER()
  if (expired(offer.expiresAt)) return EXPIRED()
  const refusal = await requireStepUp(request, stepUpPassword)
  if (refusal) return refusal

  const moved = await refusable(() => auditedTransaction(prisma, async (tx): Promise<string> => {
    const root = await lockedInstanceRoot(tx)
    const row = await readOffer(tx)
    if (!row?.pending || row.pending.toUserId !== session.userId) throw new Refused(NO_OFFER())
    if (expired(row.pending.expiresAt)) throw new Refused(EXPIRED())
    // The offer is the confirmed Root's: a Root the host or a boot replaced since is no offer.
    if (!root || !root.confirmed || root.userId !== row.rootUserId) throw new Refused(NO_OFFER())
    const me = await tx.user.findUnique({ where: { id: session.userId }, select: { role: true, status: true, password: true } })
    if (!eligible(me)) throw new Refused(CANNOT_SIGN_IN())
    const written = await tx.instanceSettings.updateMany({
      where: { id: INSTANCE_SETTINGS_ROW, rootUserId: root.userId, pendingRootTransferTo: session.userId },
      data: {
        rootUserId: session.userId, rootConfirmedAt: now(), rootAssignedBy: 'transfer',
        pendingRootTransferTo: null, pendingRootTransferExpires: null, updatedById: session.userId,
      },
    })
    if (written.count !== 1) throw new Refused(NO_OFFER())
    await tx.user.update({ where: { id: session.userId }, data: { sessionVersion: { increment: 1 } } })
    // The old Root stays an admin with every admin right (Full admin: no profile).
    await tx.user.update({ where: { id: root.userId }, data: { sessionVersion: { increment: 1 }, adminProfileId: null } })
    await audit(tx, request, session, {
      action: 'root.transfer',
      targetId: session.userId,
      before: { rootUserId: root.userId },
      after: { rootUserId: session.userId, previousRootUserId: root.userId, rootAssignedBy: 'transfer' },
    })
    return root.userId
  }))
  if (moved instanceof NextResponse) return moved
  const previousRootUserId = moved
  invalidateInstanceRoot()
  invalidatePrincipal(session.userId)
  invalidatePrincipal(previousRootUserId)
  const agent = {
    recipient: agentWorkOf(await onAccessReduced(null, session.userId, 'root_transferred')),
    previousRoot: agentWorkOf(await onAccessReduced(null, previousRootUserId, 'root_transferred')),
  }
  return { rootUserId: session.userId, previousRootUserId, agent }
}

/**
 * POST /api/root/transfer/cancel: Root cancels its offer, or the recipient declines it. Nothing
 * pending for Root is `withdrawn: false`; an account that is neither has nothing to withdraw.
 */
export async function withdrawRootTransfer(request: NextRequest, session: Session): Promise<NextResponse> {
  const by = await refusable(() => auditedTransaction(prisma, async (tx) => {
    await lockedInstanceRoot(tx)
    const row = await readOffer(tx)
    const isRoot = !!row && row.rootUserId === session.userId
    const isRecipient = !!row?.pending && row.pending.toUserId === session.userId
    if (!isRoot && !isRecipient) throw new Refused(NO_OFFER())
    if (!row?.pending) return null
    await tx.instanceSettings.update({
      where: { id: INSTANCE_SETTINGS_ROW },
      data: { pendingRootTransferTo: null, pendingRootTransferExpires: null, updatedById: session.userId },
    })
    const by = isRoot ? 'root' as const : 'recipient' as const
    await audit(tx, request, session, {
      action: by === 'root' ? 'root.transfer_cancelled' : 'root.transfer_declined',
      targetId: row.pending.toUserId,
      before: { toUserId: row.pending.toUserId, expiresAt: row.pending.expiresAt.toISOString() },
    })
    return by
  }))
  if (by instanceof NextResponse) return by
  return NextResponse.json(by ? { withdrawn: true, by } : { withdrawn: false })
}
