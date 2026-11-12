/**
 * Account status (step 2.3: ID-13, ID-21, UP-05): disabling an account, enabling it again,
 * and signing it out everywhere. Each change and its audit row commit together
 * (`writeAuditTx`, fail closed); the agent work the account still holds is ended after the
 * commit, best effort, because a refused agent call must never undo a revoke.
 *
 * Disabling keeps the account and its projects: the password moves to `passwordOnHold` and
 * the column is emptied, so the login's passwordless path refuses it even on a release that
 * knows nothing of `status`; the session version is raised (every login cookie ends) and every
 * MCP token is revoked. Enabling puts the held password back, unless a password was set while
 * the account was disabled, which then stays.
 *
 * Who acts on whom (§4.8, D-02): admins act on members. An admin target is the confirmed Root's
 * (step 2.6): its route checks Root's power and password and passes `adminTarget`; without it an
 * admin target is refused with `root_only`. Disabling runs in the last-admin guard, so even Root
 * can never disable the last admin with a password.
 */
import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import type { Prisma } from '@prisma/client'
import { writeAuditTx } from '@/lib/audit'
import { userAuditEntry, type UserAuditFields } from '@/lib/userAudit'
import { closeAgentSockets } from '@/lib/agentSockets'
import { AgentUnreachableError, agentFetch } from '@/lib/agentFetch'
import { safeErrorCode } from '@/lib/routeErrors'
import { WS_SOCKETS } from '@/lib/wsTicket'
import type { Session } from '@/lib/session'
import { LAST_ADMIN_REFUSAL, withLastAdminGuard } from './adminSet'
import { invalidatePrincipal } from './principal'
import { now } from './clock'
import { rbacFlags } from './flags'
import { rootProtectedAnswer } from './rootProtection'

export type StatusPermission = 'users:disable' | 'users:revoke_sessions'

export interface StatusOptions {
  /** Root's path (step 2.6): another admin may be the target; the route checked Root's power. */
  adminTarget?: boolean
}

/** What the agent did for an account that lost its sessions; each part is an error when it did not answer. */
export interface AgentWorkEnded {
  runs?: { stopped: number } | { error: string }
  sockets: { closed: number } | { error: string }
}

type Tx = Prisma.TransactionClient

const AGENT_TIMEOUT_MS = 10_000

/** The routes of this step do not exist while the identity switch is off (DV-30): the answer before them. */
export function routeNotFound(): NextResponse {
  return NextResponse.json({ error: 'Not found' }, { status: 404 })
}

/** `requireAdmin`'s 403, coded with the permission the action needs (master §9.8); any other answer as is. */
export function forbiddenAs(res: NextResponse, permission: StatusPermission): NextResponse {
  if (res.status !== 403) return res
  return NextResponse.json(
    { error: 'Only an administrator can change another account\'s status or sessions.', code: 'forbidden', permission },
    { status: 403 },
  )
}

const USER_NOT_FOUND = () => NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })

export const ROOT_ONLY_REFUSAL = {
  error: 'Only Root can disable, enable or sign out an admin account.',
  code: 'root_only',
} as const

const ROOT_ONLY = () => NextResponse.json(ROOT_ONLY_REFUSAL, { status: 403 })

const ACCOUNT_CHANGED = () => NextResponse.json(
  { error: 'The account changed while this request ran. Reload the list and try again.', code: 'account_changed' },
  { status: 409 },
)

/** Thrown inside a transaction when the row moved since it was read: the transaction rolls back. */
class AccountChanged extends Error {
  constructor() {
    super('account changed')
    this.name = 'AccountChanged'
  }
}

/**
 * The own account is never a target of the per-account routes: an admin cannot disable
 * itself, and signs itself out everywhere through `/api/auth/sessions/revoke-all`.
 */
export function ownAccountRefusal(session: Session, targetId: string, what: 'disable' | 'revoke'): NextResponse | null {
  if (session.userId !== targetId) return null
  const error = what === 'disable'
    ? 'You cannot disable your own account.'
    : 'To sign your own account out everywhere, use POST /api/auth/sessions/revoke-all.'
  return NextResponse.json({ error, code: 'own_account' }, { status: 400 })
}

/** Whether `id` names an admin account now (false for an account that does not exist). */
export async function isAdminAccount(id: string): Promise<boolean> {
  const row = await prisma.user.findUnique({ where: { id }, select: { role: true } })
  return row?.role === 'admin'
}

async function revokeTokens(tx: Tx, userId: string): Promise<number> {
  const { count } = await tx.mcpAccessToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: now() },
  })
  return count
}

async function audit(tx: Tx, request: NextRequest, session: Session, entry: UserAuditFields): Promise<void> {
  await writeAuditTx(tx, await userAuditEntry(request, session, entry))
}

/** Runs `write` in a transaction; a row that moved under it answers 409 instead of a 500. */
async function changedAware<T>(write: () => Promise<T>): Promise<T | NextResponse> {
  try {
    return await write()
  } catch (err) {
    if (err instanceof AccountChanged) return ACCOUNT_CHANGED()
    throw err
  }
}

async function stopAgentRuns(userId: string): Promise<{ stopped: number } | { error: string }> {
  const failed = (reason: string) => {
    console.error(`[rbac] agent-stop failed user=${userId}: ${reason}`)
    return { error: reason }
  }
  let res: Response
  try {
    res = await agentFetch('/agent-sessions/stop-for', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_id: userId }),
    }, { timeoutMs: AGENT_TIMEOUT_MS })
  } catch (err) {
    return failed(err instanceof AgentUnreachableError ? 'agent_unreachable' : safeErrorCode(err))
  }
  if (!res.ok) return failed(`agent_http_${res.status}`)
  const body = await res.json().catch(() => null) as { stopped?: unknown } | null
  return { stopped: typeof body?.stopped === 'number' ? body.stopped : 0 }
}

/**
 * Ends what the agent still runs for the account: its agent runs (`stopRuns`), then every
 * socket of the four kinds that names it, an admin's act-as sockets as the account included
 * (`scope: 'account'`). Never throws; a failure is logged (`[rbac] agent-stop failed`,
 * `[rbac] socket-close failed user=<id>`) and reported in the answer.
 */
export async function endAgentWork(userId: string, { stopRuns }: { stopRuns: boolean }): Promise<AgentWorkEnded> {
  const out: AgentWorkEnded = { sockets: { closed: 0 } }
  if (stopRuns) out.runs = await stopAgentRuns(userId)
  const close = await closeAgentSockets({ userId, kinds: [...WS_SOCKETS], scope: 'account' })
  out.sockets = close.ok ? { closed: close.closed } : { error: close.reason }
  return out
}

/**
 * Disable `targetId`: status `disabled`, the password on hold, the session version raised and
 * every MCP token revoked, with the `user.disable` row, in the last-admin guard's transaction;
 * then the account's agent runs and sockets end. An account already disabled is left as it is.
 * With the identity switch on the transaction also holds the Root lock and reads the Root again:
 * a disabled Root could not sign in, and an admin target is Root's power (`adminTarget`).
 */
export async function disableAccount(
  request: NextRequest, session: Session, targetId: string, opts: StatusOptions = {},
): Promise<NextResponse> {
  type Outcome = { kind: 'missing' | 'root_only' | 'unchanged' } | { kind: 'not_active'; status: string } | { kind: 'disabled'; tokensRevoked: number }
  const result = await changedAware(() => withLastAdminGuard(targetId, async (tx): Promise<Outcome> => {
    const row = await tx.user.findUnique({
      where: { id: targetId },
      select: { role: true, status: true, password: true, sessionVersion: true },
    })
    if (!row) return { kind: 'missing' }
    if (row.role === 'admin' && !opts.adminTarget) return { kind: 'root_only' }
    if (row.status === 'disabled') return { kind: 'unchanged' }
    if (row.status !== 'active') return { kind: 'not_active', status: row.status }
    // Conditional on the password read above, so the hash put on hold is exactly the one removed.
    const moved = await tx.user.updateMany({
      where: { id: targetId, status: 'active', password: row.password },
      data: { status: 'disabled', passwordOnHold: row.password, password: '', sessionVersion: { increment: 1 } },
    })
    if (moved.count !== 1) throw new AccountChanged()
    const tokensRevoked = await revokeTokens(tx, targetId)
    await audit(tx, request, session, {
      action: 'user.disable',
      targetId,
      before: { status: 'active' },
      after: { status: 'disabled', sessionVersion: row.sessionVersion + 1, tokensRevoked },
    })
    return { kind: 'disabled', tokensRevoked }
  }, rbacFlags().identity ? { root: { actorId: session.userId, needsRoot: !!opts.adminTarget } } : {}))
  if (result instanceof NextResponse) return result
  if (!result.ok) {
    if (result.refused === 'root_protected') return rootProtectedAnswer(request, session, targetId, 'disable')
    if (result.refused === 'root_only') return ROOT_ONLY()
    return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
  }
  const outcome = result.value
  switch (outcome.kind) {
    case 'missing': return USER_NOT_FOUND()
    case 'root_only': return ROOT_ONLY()
    case 'unchanged': return NextResponse.json({ id: targetId, status: 'disabled', changed: false })
    case 'not_active':
      return NextResponse.json(
        { error: `Only an active account can be disabled; this one is ${outcome.status}.`, code: 'not_active' },
        { status: 409 },
      )
  }
  invalidatePrincipal(targetId)
  const agent = await endAgentWork(targetId, { stopRuns: true })
  return NextResponse.json({ id: targetId, status: 'disabled', changed: true, tokensRevoked: outcome.tokensRevoked, agent })
}

/**
 * Enable `targetId` again: status `active` and the held password back (a password set while
 * it was disabled stays), with the `user.enable` row in the same transaction. Nothing else
 * returns: the tokens revoked at the disable stay revoked, and the account signs in anew.
 */
export async function enableAccount(
  request: NextRequest, session: Session, targetId: string, opts: StatusOptions = {},
): Promise<NextResponse> {
  type Outcome = { kind: 'missing' | 'root_only' | 'unchanged' } | { kind: 'not_disabled'; status: string } | { kind: 'enabled' }
  const outcome = await changedAware(() => prisma.$transaction(async (tx): Promise<Outcome> => {
    const row = await tx.user.findUnique({
      where: { id: targetId },
      select: { role: true, status: true, password: true, passwordOnHold: true },
    })
    if (!row) return { kind: 'missing' }
    if (row.role === 'admin' && !opts.adminTarget) return { kind: 'root_only' }
    if (row.status === 'active') return { kind: 'unchanged' }
    if (row.status !== 'disabled') return { kind: 'not_disabled', status: row.status }
    const restored = row.password === '' && row.passwordOnHold !== ''
    const moved = await tx.user.updateMany({
      where: { id: targetId, status: 'disabled', password: row.password, passwordOnHold: row.passwordOnHold },
      data: { status: 'active', password: restored ? row.passwordOnHold : row.password, passwordOnHold: '' },
    })
    if (moved.count !== 1) throw new AccountChanged()
    await audit(tx, request, session, {
      action: 'user.enable',
      targetId,
      before: { status: 'disabled' },
      after: { status: 'active', passwordRestored: restored },
    })
    return { kind: 'enabled' }
  }))
  if (outcome instanceof NextResponse) return outcome
  switch (outcome.kind) {
    case 'missing': return USER_NOT_FOUND()
    case 'root_only': return ROOT_ONLY()
    case 'unchanged': return NextResponse.json({ id: targetId, status: 'active', changed: false })
    case 'not_disabled':
      return NextResponse.json(
        { error: `Only a disabled account can be enabled; this one is ${outcome.status}.`, code: 'not_disabled' },
        { status: 409 },
      )
  }
  invalidatePrincipal(targetId)
  return NextResponse.json({ id: targetId, status: 'active', changed: true })
}

/**
 * Sign `targetId` out everywhere: the session version raised and every MCP token revoked, with
 * the `user.sessions_revoked` row in the same transaction; then its sockets close. Repeating
 * it raises the version again, which ends nothing more.
 */
export async function revokeSessions(
  request: NextRequest, session: Session, targetId: string, opts: StatusOptions = {},
): Promise<NextResponse> {
  type Outcome = { kind: 'missing' | 'root_only' } | { kind: 'revoked'; sessionVersion: number; tokensRevoked: number }
  const outcome = await prisma.$transaction(async (tx): Promise<Outcome> => {
    const row = await tx.user.findUnique({ where: { id: targetId }, select: { role: true } })
    if (!row) return { kind: 'missing' }
    if (row.role === 'admin' && !opts.adminTarget && targetId !== session.userId) return { kind: 'root_only' }
    const { sessionVersion } = await tx.user.update({
      where: { id: targetId },
      data: { sessionVersion: { increment: 1 } },
      select: { sessionVersion: true },
    })
    const tokensRevoked = await revokeTokens(tx, targetId)
    await audit(tx, request, session, {
      action: 'user.sessions_revoked',
      targetId,
      after: { sessionVersion, tokensRevoked },
    })
    return { kind: 'revoked', sessionVersion, tokensRevoked }
  })
  if (outcome.kind !== 'revoked') return outcome.kind === 'missing' ? USER_NOT_FOUND() : ROOT_ONLY()
  invalidatePrincipal(targetId)
  const agent = await endAgentWork(targetId, { stopRuns: false })
  return NextResponse.json({ id: targetId, revoked: true, tokensRevoked: outcome.tokensRevoked, agent })
}
