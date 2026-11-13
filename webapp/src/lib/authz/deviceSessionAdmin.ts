/**
 * Listing and revoking device sessions (step 6.10, GV-17, UI-09), for My account → Sessions
 * (`/api/account/sessions`) and an admin's user detail (`/api/users/[id]/sessions`, users:revoke_sessions).
 * The routes decide who may ask; this module reads and writes the rows (authz/deviceSessions.ts).
 *
 * A revoke marks the row and writes its `user.session_revoked` row in one transaction (fail closed:
 * no audit row, no revoke), then drops the row from this process's cache, so the browser is refused
 * at its next request here and within RBAC_AUTHZ_CACHE_MS on the other copies; then the agent closes
 * the sockets the account opened itself (`onAccessReduced`, `device_session_revoked`, step 5.9:
 * `scope: 'access'`, its own and its act-as ones, not an admin's acting as it). A WebSocket ticket names no device session, so every such socket of the
 * account closes, and its other browsers reconnect with a new ticket; a close the agent does not
 * confirm logs `[rbac] socket-close failed` and the revoke stands. Revoking a row that is already
 * revoked, signed out, ended by a version bump or expired changes nothing and writes no row: a second
 * click, or two admins at once, give one audit row.
 *
 * The audit row names the session id, never its address or browser (master §9.8).
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import { userAuditEntry } from '@/lib/userAudit'
import type { Session } from '@/lib/session'
import { now } from './clock'
import { deviceSessionState, invalidateDeviceSession, type DeviceSessionState, type EndedBy } from './deviceSessions'
import { onAccessReduced } from './revocation'

export const SESSION_REVOKED_ACTION = 'user.session_revoked'
/** Rows listed per account, newest activity first; older ones are still swept. */
export const MAX_LISTED = 100

export interface DeviceSessionView {
  id: string
  createdAt: string
  lastSeenAt: string
  expiresAt: string
  ip: string | null
  ipTrusted: boolean
  userAgent: string | null
  state: DeviceSessionState
  revokedAt: string | null
  /** The browser asking (My account only). */
  current: boolean
}

const ROW_SELECT = {
  id: true, sessionVersion: true, createdAt: true, lastSeenAt: true, expiresAt: true, ip: true, ipTrusted: true,
  userAgent: true, revokedAt: true, endedBy: true,
} as const

const STATE_ORDER: Record<DeviceSessionState, number> = { active: 0, revoked: 1, signed_out: 1, ended: 1, expired: 1 }

/**
 * The account's device sessions: live ones first (the asking browser on top), then the ended ones
 * still kept, each group by last activity. Null when the account does not exist.
 */
export async function listDeviceSessions(userId: string, { currentId = null }: { currentId?: string | null } = {}): Promise<DeviceSessionView[] | null> {
  const account = await prisma.user.findUnique({ where: { id: userId }, select: { sessionVersion: true } })
  if (!account) return null
  const rows = await prisma.userSession.findMany({
    where: { userId },
    select: ROW_SELECT,
    orderBy: { lastSeenAt: 'desc' },
    take: MAX_LISTED,
  })
  const at = now()
  const views = rows.map((r): DeviceSessionView => ({
    id: r.id,
    createdAt: r.createdAt.toISOString(),
    lastSeenAt: r.lastSeenAt.toISOString(),
    expiresAt: r.expiresAt.toISOString(),
    ip: r.ip ?? null,
    ipTrusted: r.ipTrusted === true,
    userAgent: r.userAgent ?? null,
    state: deviceSessionState(r, account.sessionVersion, at),
    revokedAt: r.revokedAt ? r.revokedAt.toISOString() : null,
    current: r.id === currentId,
  }))
  const rank = (v: DeviceSessionView) => (v.current && v.state === 'active' ? -1 : STATE_ORDER[v.state])
  return views.sort((a, b) => rank(a) - rank(b) || b.lastSeenAt.localeCompare(a.lastSeenAt))
}

export type SocketsClosed = { closed: number } | { error: string }

export type RevokeOutcome =
  | { kind: 'missing' }
  | { kind: 'unchanged'; state: DeviceSessionState }
  | { kind: 'revoked'; agent: { sockets: SocketsClosed } }

export interface RevokeOptions {
  /** `self`: the account revoked its own (the real signed-in account); `admin`: an administrator did. */
  by: Exclude<EndedBy, 'sign_out'>
  /** The session revoked is the asking browser's own (My account). */
  current?: boolean
}

/**
 * Revokes `sid`, one of `targetId`'s device sessions, for `session` (the real signed-in person; an
 * admin acting as someone is recorded as such by the audit row). The route checked who may.
 */
export async function revokeDeviceSession(
  request: NextRequest, session: Session, targetId: string, sid: string, { by, current = false }: RevokeOptions,
): Promise<RevokeOutcome> {
  type Written = { kind: 'missing' } | { kind: 'unchanged'; state: DeviceSessionState } | { kind: 'revoked' }
  const written = await auditedTransaction(prisma, async (tx): Promise<Written> => {
    const row = await tx.userSession.findFirst({ where: { id: sid, userId: targetId }, select: ROW_SELECT })
    if (!row) return { kind: 'missing' }
    const account = await tx.user.findUnique({ where: { id: targetId }, select: { sessionVersion: true } })
    if (!account) return { kind: 'missing' }
    const at = now()
    const state = deviceSessionState(row, account.sessionVersion, at)
    if (state !== 'active') return { kind: 'unchanged', state }
    // Conditional on the row still being live: of two revokes at once, the second matches nothing.
    const { count } = await tx.userSession.updateMany({
      where: { id: sid, userId: targetId, revokedAt: null },
      data: { revokedAt: at, revokedById: session.userId, endedBy: by },
    })
    if (count !== 1) return { kind: 'unchanged', state: 'revoked' }
    await writeAuditTx(tx, await userAuditEntry(request, session, {
      action: SESSION_REVOKED_ACTION,
      targetId,
      after: { sessionId: sid, by, ...(current ? { current: true } : {}) },
    }))
    return { kind: 'revoked' }
  })
  // Also when nothing changed here: another copy's revoke may still sit in this process's cache.
  invalidateDeviceSession(sid)
  if (written.kind !== 'revoked') return written
  const { sockets } = await onAccessReduced(null, targetId, 'device_session_revoked')
  return { kind: 'revoked', agent: { sockets } }
}

export function sessionNotFound(): NextResponse {
  return NextResponse.json({ error: 'Session not found', code: 'session_not_found' }, { status: 404 })
}

/** The answer to a revoke: 404 for a session this account does not have, else what it is now. */
export function revokeAnswer(sid: string, outcome: RevokeOutcome): NextResponse {
  if (outcome.kind === 'missing') return sessionNotFound()
  if (outcome.kind === 'unchanged') return NextResponse.json({ id: sid, changed: false, state: outcome.state })
  return NextResponse.json({ id: sid, changed: true, state: 'revoked', agent: outcome.agent })
}

/** The admin routes never take the own account: My account → Sessions is where it is (400 `own_account`). */
export function ownDevicesRefusal(sessionUserId: string, targetId: string): NextResponse | null {
  if (sessionUserId !== targetId) return null
  return NextResponse.json(
    { error: 'Your own sessions are under My account: GET /api/account/sessions.', code: 'own_account' },
    { status: 400 },
  )
}
