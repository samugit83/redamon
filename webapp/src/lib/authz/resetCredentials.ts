/**
 * Reset credentials (step 2.10, ID-18, ID-19, PE-12; feature document §4.7, §7.1): an admin gives
 * a person who lost their password a way back in, either a reset link (the password is emptied,
 * so the account signs in only through the link) or a temporary password (to change at the next
 * sign-in). Either way every login cookie of the account ends (the session version rises), its
 * MCP tokens are revoked and its open invite or reset links are cancelled.
 *
 * Whoever issues a reset can use it before the person does, so a reset is takeover-equivalent
 * and made visible rather than prevented: an account that has signed in before needs a reason,
 * the person finds a notice at their next sign-in (accountNotices.ts), and the first sign-in
 * after it records its address and browser. The change, the link, the notice and
 * `user.credentials_reset` commit together (`writeAuditTx`, fail closed); the account's sockets
 * close after the commit, best effort.
 *
 * Who resets whom (§4.8): admins reset members; another admin is the confirmed Root's, with its
 * own password (the route checks it and passes `adminTarget`); nobody resets Root. The write runs
 * in the last-admin guard's transaction with the Root re-check (adminSet.ts), so a Root chosen
 * between the route's check and the write is refused, and a link reset never leaves the instance
 * without an admin who can sign in. Reached only with the identity switch on.
 */
import { NextResponse, type NextRequest } from 'next/server'
import type { Prisma } from '@prisma/client'
import { writeAuditTx } from '@/lib/audit'
import { userAuditEntry } from '@/lib/userAudit'
import type { Session } from '@/lib/session'
import { LAST_ADMIN_REFUSAL, withLastAdminGuard, type RootGuardRefusal } from './adminSet'
import { agentWorkOf, onAccessReduced, type AgentWorkEnded } from './revocation'
import { credentialsResetNotice, withNotice, type ResetMode } from './accountNotices'
import { createLink, type CreatedLink } from './invites'
import { invalidatePrincipal } from './principal'
import { now } from './clock'
import { rootProtectedAnswer, type RootProtectedAttempt } from './rootProtection'

export const RESET_REASON_MAX = 500

export const ROOT_ONLY_RESET = "Only Root can reset another admin's credentials."

export interface ResetInput {
  mode: ResetMode
  /** Temporary mode: the hash of the password the admin chose. */
  passwordHash?: string
  /** Temporary mode: the person replaces it at the next sign-in (default true). */
  requireChange?: boolean
  reason: string | null
  /** Root's path: the route checked Root's power and password for an admin target. */
  adminTarget: boolean
  /** Temporary mode: the address the password was judged against; the write needs it unchanged. */
  judgedEmail?: string
  /** How a refused write on Root is recorded (`rbac.root_protected_refused`). */
  attempted: RootProtectedAttempt
}

export interface ResetDone {
  sessionVersion: number
  tokensRevoked: number
  cancelledLinks: number
  mustChangePassword: boolean
  /** Link mode: the link, shown once to the admin. */
  link: CreatedLink | null
  agent: AgentWorkEnded
}

const invalidReason = () => NextResponse.json(
  { error: `The reason must be text of at most ${RESET_REASON_MAX} characters.`, code: 'invalid_field', field: 'reason' },
  { status: 400 },
)

/** A body's `reason`: null when absent or blank; a 400 for anything but text, or text too long. */
export function parseReason(raw: unknown): string | null | NextResponse {
  if (raw === undefined || raw === null) return null
  if (typeof raw !== 'string') return invalidReason()
  const reason = raw.trim()
  if (reason.length > RESET_REASON_MAX) return invalidReason()
  return reason || null
}

export function reasonRequired(): NextResponse {
  return NextResponse.json(
    {
      error: 'This person has signed in before: give the reason for the reset. They will read it at their next sign-in.',
      code: 'reason_required',
      field: 'reason',
    },
    { status: 400 },
  )
}

/**
 * Who can be reset in `mode`: an active account; a disabled one only with a temporary password
 * (it stays disabled, and enabling it keeps that password); never an invited one, whose way in is
 * its invite link. Null when allowed.
 */
export function resetStatusRefusal(status: string, mode: ResetMode): NextResponse | null {
  if (status === 'active' || (status === 'disabled' && mode === 'temporary')) return null
  const error = status === 'invited'
    ? 'This account has not accepted its invite yet: resend the invite instead.'
    : status === 'disabled'
      ? 'A reset link works only for an active account: enable this one first, or set a temporary password.'
      : `This account cannot be reset; it is ${status}.`
  return NextResponse.json({ error, code: 'not_active' }, { status: 409 })
}

const USER_NOT_FOUND = () => NextResponse.json({ error: 'User not found', code: 'user_not_found' }, { status: 404 })
const ROOT_ONLY = () => NextResponse.json({ error: ROOT_ONLY_RESET, code: 'root_only' }, { status: 403 })
const ACCOUNT_CHANGED = () => NextResponse.json(
  { error: 'The account changed while this request ran. Reload the list and try again.', code: 'account_changed' },
  { status: 409 },
)

/** Thrown inside the transaction when the row moved since it was read: everything rolls back. */
class AccountChanged extends Error {
  constructor() {
    super('account changed')
    this.name = 'AccountChanged'
  }
}

type Outcome =
  | { kind: 'missing' | 'root_only' | 'reason_required' }
  | { kind: 'refused'; answer: NextResponse }
  | { kind: 'reset'; sessionVersion: number; tokensRevoked: number; cancelledLinks: number; link: CreatedLink | null }

async function write(
  tx: Prisma.TransactionClient,
  request: NextRequest,
  session: Session,
  targetId: string,
  input: ResetInput,
): Promise<Outcome> {
  const row = await tx.user.findUnique({
    where: { id: targetId },
    select: {
      role: true, status: true, email: true, password: true, sessionVersion: true, lastLoginAt: true, pendingNotices: true,
    },
  })
  if (!row) return { kind: 'missing' }
  if (row.role === 'admin' && !input.adminTarget) return { kind: 'root_only' }
  const refused = resetStatusRefusal(row.status, input.mode)
  if (refused) return { kind: 'refused', answer: refused }
  if (row.lastLoginAt && !input.reason) return { kind: 'reason_required' }
  if (input.judgedEmail !== undefined && row.email !== input.judgedEmail) throw new AccountChanged()

  const at = now()
  const actor = await tx.user.findUnique({ where: { id: session.userId }, select: { name: true, email: true } })
  const notice = credentialsResetNotice({
    by: { id: session.userId, name: actor?.name ?? '', email: actor?.email ?? '' },
    at,
    reason: input.reason,
    mode: input.mode,
  })
  const mustChangePassword = input.mode === 'temporary' && input.requireChange !== false
  const moved = await tx.user.updateMany({
    // Conditional on what was read: a sign-in, a password change or another reset in between
    // makes this one refuse instead of overwriting it.
    where: { id: targetId, status: row.status, password: row.password, sessionVersion: row.sessionVersion },
    data: {
      password: input.mode === 'link' ? '' : input.passwordHash!,
      mustChangePassword,
      sessionVersion: { increment: 1 },
      pendingNotices: withNotice(row.pendingNotices, notice) as unknown as Prisma.InputJsonValue,
    },
  })
  if (moved.count !== 1) throw new AccountChanged()
  const { count: tokensRevoked } = await tx.mcpAccessToken.updateMany({
    where: { userId: targetId, revokedAt: null },
    data: { revokedAt: at },
  })
  // An older reset link would otherwise still replace the password chosen now.
  const { count: cancelledLinks } = await tx.userInvite.updateMany({
    where: { userId: targetId, usedAt: null, cancelledAt: null },
    data: { cancelledAt: at },
  })
  const link = input.mode === 'link'
    ? await createLink(tx, { userId: targetId, kind: 'reset', createdById: session.userId, reason: input.reason })
    : null
  const sessionVersion = row.sessionVersion + 1
  await writeAuditTx(tx, await userAuditEntry(request, session, {
    action: 'user.credentials_reset',
    targetId,
    after: {
      mode: input.mode,
      mustChangePassword,
      sessionVersion,
      revokedMcpTokens: tokensRevoked,
      cancelledLinks,
      reason: input.reason,
      ...(link ? { expiresAt: link.expiresAt.toISOString() } : {}),
    },
  }))
  return { kind: 'reset', sessionVersion, tokensRevoked, cancelledLinks, link }
}

/**
 * Resets `targetId`'s credentials as `input` says; the answer to send back, or what was done. The
 * route has already refused the own account and Root, checked an admin target's Root power, and
 * hashed a temporary password that meets the policy in force.
 */
export async function resetCredentials(
  request: NextRequest,
  session: Session,
  targetId: string,
  input: ResetInput,
): Promise<ResetDone | NextResponse> {
  let result: { ok: true; value: Outcome } | { ok: false; refused?: RootGuardRefusal }
  try {
    result = await withLastAdminGuard(
      targetId,
      (tx) => write(tx, request, session, targetId, input),
      { root: { actorId: session.userId, needsRoot: input.adminTarget } },
    )
  } catch (err) {
    if (err instanceof AccountChanged) return ACCOUNT_CHANGED()
    throw err
  }
  if (!result.ok) {
    if (result.refused === 'root_protected') return rootProtectedAnswer(request, session, targetId, input.attempted)
    if (result.refused === 'root_only') return ROOT_ONLY()
    return NextResponse.json(LAST_ADMIN_REFUSAL, { status: 409 })
  }
  const outcome = result.value
  switch (outcome.kind) {
    case 'missing': return USER_NOT_FOUND()
    case 'root_only': return ROOT_ONLY()
    case 'reason_required': return reasonRequired()
    case 'refused': return outcome.answer
  }
  invalidatePrincipal(targetId)
  const agent = agentWorkOf(await onAccessReduced(null, targetId, 'credentials_reset'))
  return {
    sessionVersion: outcome.sessionVersion,
    tokensRevoked: outcome.tokensRevoked,
    cancelledLinks: outcome.cancelledLinks,
    mustChangePassword: input.mode === 'temporary' && input.requireChange !== false,
    link: outcome.link,
    agent,
  }
}
