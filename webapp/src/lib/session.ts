import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken, verifyActAsToken, readActAsToken, AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from './auth'
import { constantTimeEqual } from './constantTimeEqual'
import { cachedPrincipal, loadPrincipal, type LoadPrincipalOptions, type Principal } from './authz/principal'
import { rememberSessionPrincipal, sessionPrincipal } from './authz/sessionPrincipal'
import { rbacFlags } from './authz/flags'
import {
  actAsBindingInForce, actAsRuleRefusal, actsAsOthers, bindingOf, endForRefusal, recordActAsEndQuietly,
  type ActAsActor, type ActAsEnd,
} from './authz/actAs'
import { sessionHolds } from './authz/adminPermission'
import { forbiddenResponse } from './authz/guards'
import { internalError } from './routeErrors'

export interface Session {
  userId: string
  role: string
}

/**
 * The user whose data a request is authorized to touch. For a standard user this
 * is always their own id; for an admin it is their own id unless they are
 * actively simulating another user (see getEffectiveUser).
 */
export interface EffectiveUser {
  userId: string
}

/** `fresh`: read the account from the database even when this process holds it (critical paths). */
export type SessionOptions = LoadPrincipalOptions

type CookieStore = Awaited<ReturnType<typeof cookies>>

/**
 * Whether the account still accepts this login token. The session version is compared
 * strictly whatever the identity switch (a token without one is version 0), so raising it
 * signs the account out everywhere. The status and the must-change claim count only with the
 * switch on: a cookie whose `pwc` disagrees with the account (flagged without a version bump,
 * or the flag cleared from another browser) signs in again, into the right flow.
 */
function tokenAccepted(token: { sv: number; pwc?: true }, principal: Principal): boolean {
  if (token.sv !== principal.sessionVersion) return false
  if (!rbacFlags().identity) return true
  return principal.status === 'active' && (token.pwc === true) === principal.mustChangePassword
}

/**
 * A refused cookie can never become valid again, and the Edge middleware, which cannot
 * read the database, would keep loading pages with it while every API answers 401: with the
 * identity switch on, clear it on this answer, so the next page goes to /login. With the
 * switch off the cookie stays, as after Phase 1 (DV-30): it is dead either way. Route
 * handlers can write cookies; a read-only store (a Server Component) still refuses, it just
 * cannot clear.
 */
function refuse(cookieStore: CookieStore): null {
  if (!rbacFlags().identity) return null
  try {
    cookieStore.delete(AUTH_COOKIE_NAME)
  } catch {
    // read-only cookie store: the refusal stands
  }
  return null
}

/**
 * The signed-in account, or null (the caller answers 401). The login JWT proves who
 * signed in; whether that account still exists, its role, its session version and its
 * status are read from the database, so the role claim in the token is never trusted.
 * A refused cookie is cleared (identity switch on). A failed database read throws: it never
 * reads as signed in, and it keeps the cookie.
 */
export async function getSession({ fresh = false }: SessionOptions = {}): Promise<Session | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get(AUTH_COOKIE_NAME)?.value
  if (!token) return null
  const payload = await verifyToken(token)
  if (!payload) return refuse(cookieStore)
  const cached = fresh ? null : cachedPrincipal(payload.sub)
  let principal = cached ?? (await loadPrincipal(payload.sub, { fresh }))
  // A cached account may predate the change that made this token valid (a sign-in after a
  // version bump in another process, an account enabled again): a refusal stands only on an
  // account read from the database, so only a cached answer is read again (DV-25).
  if (cached && !tokenAccepted(payload, cached)) principal = await loadPrincipal(payload.sub, { fresh: true })
  if (!principal || !tokenAccepted(payload, principal)) return refuse(cookieStore)
  const session = { userId: principal.id, role: principal.role }
  rememberSessionPrincipal(session, principal)
  return session
}

/**
 * Resolves the EFFECTIVE user for authorization decisions:
 *   - standard user       -> own id (any `redamon-act-as` cookie is IGNORED)
 *   - admin, not simulating -> own id
 *   - admin, simulating X   -> X, but only when the act-as cookie was minted by
 *                              THIS admin (claims.sub === session.userId) and X
 *                              still exists; otherwise own id
 * Returns null when there is no valid login session (caller returns 401).
 *
 * The real identity comes from the untouched login JWT and the role from the
 * database (getSession); the act-as cookie can only ever narrow an admin to a
 * single other user, never grant a standard user cross-user access.
 */
export async function getEffectiveUser(opts: SessionOptions = {}): Promise<EffectiveUser | null> {
  const session = await getSession(opts)
  if (!session) return null
  const target = await actAsTarget(session, opts)
  return { userId: target ? target.id : session.userId }
}

/** Who a request is: what `can()` decides on (authz/guards.ts). */
export interface AuthzIdentity {
  /** The real signed-in account; act-as never changes it. */
  session: Session
  /** The same account as this request read it. */
  principal: Principal
  /** The account an admin is acting as (the effective user), or null. */
  actingAs: Principal | null
}

/**
 * The signed-in account and the account it acts as, read as `getSession` and `getEffectiveUser`
 * read them (the effective user is `actingAs ?? principal`). Null without a valid session; a
 * failed read throws.
 */
export async function getAuthzIdentity(opts: SessionOptions = {}): Promise<AuthzIdentity | null> {
  const session = await getSession(opts)
  if (!session) return null
  return authzIdentityOf(session, opts)
}

/**
 * getAuthzIdentity for a session getSession already answered (a route that reads the session
 * itself): the act-as cookie is read, the login cookie and the account not again. Throws for a
 * session object getSession did not answer, and on a failed read.
 */
export async function authzIdentityOf(session: Session, opts: SessionOptions = {}): Promise<AuthzIdentity> {
  const principal = sessionPrincipal(session)
  // getSession remembers the principal of every session it answers.
  if (!principal) throw new Error('session: no account read for this session')
  const target = await actAsTarget(session, opts)
  return { session, principal, actingAs: target && target.id !== principal.id ? target : null }
}

/**
 * Whether the session acts as the account `userId` names, by the act-as cookie getEffectiveUser
 * honours. The path naming the account acted as is that account's own data (§4.7: what both people
 * may do; a member permission is asked through can()'s actingAs, the intersection), not another
 * account's administration, so the user directory's permissions do not decide it.
 */
export async function actsAsAccount(session: Session, userId: string, opts: SessionOptions = {}): Promise<boolean> {
  return (await actAsTarget(session, opts))?.id === userId
}

/**
 * The act-as rule (authz/actAs.ts `actAsRuleRefusal`): whether `actor` may act as `target`. The
 * act-as cookie (actAsTarget) and `can()`'s `actingAs` both answer to it, so a caller that builds an
 * `actingAs` by hand cannot skip it. Only an admin acts as anyone, and nobody acts as Root (identity
 * switch on); with the permissions switch on the admin also needs `users:impersonate`, an admin
 * target is Root's, and a disabled account is acted as by nobody. Acting as oneself is no act-as.
 */
export async function mayActAs(
  actor: ActAsActor,
  target: Pick<Principal, 'id' | 'role'> & { status?: string },
  opts: SessionOptions = {},
): Promise<boolean> {
  return (await actAsRuleRefusal(actor, target, opts)) === null
}

/** The impersonation a request carries: the account acted as, and when its token expires (seconds). */
export interface ActAsInForce {
  target: Principal
  expiresAt: number | null
}

/** A refused act-as cookie is cleared where the store allows it (a route handler); a Server Component only ignores it. */
function forgetActAs(cookieStore: CookieStore): void {
  try {
    cookieStore.delete(ACT_AS_COOKIE_NAME)
  } catch {
    // read-only cookie store: the cookie is ignored all the same
  }
}

/**
 * Permissions switch on (step 3.14): the act-as cookie is judged again on every request. It is
 * this admin's, unexpired, minted at the admin's current session version (a cookie from before
 * the switch carries none and keeps its own expiry, IM-12), the impersonation it names is still
 * the one the act-as log shows running (authz/actAs.ts `ActAsBinding`: one indexed read), and the
 * rule still allows the pair. Otherwise the impersonation ends here: its end row is written once
 * with how it ended, and the cookie is cleared. A copy of a cookie whose impersonation already
 * ended (a Stop, a sign-out, a newer act-as) is cleared and records nothing; so is a cookie
 * another admin minted.
 */
async function impersonation(session: Session, token: string, cookieStore: CookieStore, opts: SessionOptions): Promise<ActAsInForce | null> {
  const read = await readActAsToken(token)
  if (!read || read.claims.sub !== session.userId || read.claims.act === session.userId) return null
  const { claims } = read
  const actor = sessionPrincipal(session) ?? (await loadPrincipal(session.userId, opts))
  if (!actor) return null
  const binding = bindingOf(claims)
  const end = async (endedBy: ActAsEnd): Promise<null> => {
    await recordActAsEndQuietly({ adminId: actor.id, targetUserId: claims.act, endedBy, adminEmail: actor.email, binding })
    forgetActAs(cookieStore)
    return null
  }
  if (read.expired) return end('expired')
  if (claims.asv !== undefined && claims.asv !== actor.sessionVersion) return end('invalidated')
  // Minted under the rule before tokens named their start row: nothing tells a replay apart.
  if ('open' in binding) return end('invalidated')
  if (!(await actAsBindingInForce(actor.id, claims.act, binding))) {
    forgetActAs(cookieStore)
    return null
  }
  const target = await loadPrincipal(claims.act, opts)
  if (!target) return end('target_deleted')
  const refusal = await actAsRuleRefusal(actor, target, opts)
  if (refusal) return end(endForRefusal(refusal, claims.asv !== undefined))
  return { target, expiresAt: read.expiresAt }
}

/** One act-as decision per session object, i.e. per request (switch on): `fresh` when it read the accounts fresh. */
const judged = new WeakMap<Session, { fresh: boolean; decision: Promise<ActAsInForce | null> }>()

/**
 * The impersonation an admin session carries: the act-as cookie must have been minted by this
 * admin and name an account that still exists, which the act-as rule allows. Null for anyone else.
 * Permissions switch on: judged once per session object, so every check of a request (the effective
 * user, can()'s intersection, the audit rows) follows one decision, and the act-as log is read
 * once (DV-25); a fresh call over a decision made from cached accounts judges again.
 */
export async function actAsInForce(session: Session, opts: SessionOptions = {}): Promise<ActAsInForce | null> {
  if (!actsAsOthers(session)) return null
  const enforced = rbacFlags().permissions
  const made = enforced ? judged.get(session) : undefined
  if (made && (made.fresh || !opts.fresh)) return made.decision
  const cookieStore = await cookies()
  const actAsToken = cookieStore.get(ACT_AS_COOKIE_NAME)?.value
  if (!actAsToken) return null
  if (enforced) {
    const decision = impersonation(session, actAsToken, cookieStore, opts)
    judged.set(session, { fresh: opts.fresh === true, decision })
    return decision
  }
  const claims = await verifyActAsToken(actAsToken)
  if (!claims || claims.sub !== session.userId) return null
  const target = await loadPrincipal(claims.act, opts)
  return target && (await mayActAs({ id: session.userId, role: session.role }, target, opts)) ? { target, expiresAt: null } : null
}

async function actAsTarget(session: Session, opts: SessionOptions = {}): Promise<Principal | null> {
  return (await actAsInForce(session, opts))?.target ?? null
}

/**
 * Returns session or a 401 NextResponse (a coded 500 when the account could not be
 * read). Caller must check and return the response.
 * Usage: const result = await requireSession(); if (result instanceof NextResponse) return result;
 */
export async function requireSession(opts: SessionOptions = {}): Promise<Session | NextResponse> {
  let session: Session | null
  try {
    session = await getSession(opts)
  } catch (err) {
    return internalError(err, 'Could not read the signed-in account')
  }
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  return session
}

/**
 * Returns the session of an administrator ACCOUNT (Root or an admin), or a 401/403 NextResponse.
 * An account type, not a permission: a route that administers something then checks the
 * permission it needs (authz/adminPermission.ts `requireSessionPermission`), so an admin whose
 * profile lacks it is refused. Caller must check and return the response.
 * Usage: const result = await requireAdmin(); if (result instanceof NextResponse) return result;
 */
export async function requireAdmin(opts: SessionOptions = {}): Promise<Session | NextResponse> {
  const result = await requireSession(opts)
  if (result instanceof NextResponse) return result
  if (result.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  return result
}

export function isInternalRequest(request: NextRequest): boolean {
  const key = request.headers.get('x-internal-key')
  const expected = process.env.INTERNAL_API_KEY
  if (!key || !expected || expected === 'changeme') return false
  return constantTimeEqual(key, expected)
}

/**
 * S3/E6: the LOWER-TIER scanner principal. Scan containers carry SCANNER_API_KEY
 * (not the master INTERNAL_API_KEY) and legitimately read only their OSINT
 * settings + project config. This returns true for a valid scanner key; callers
 * must scope it to exactly GET /api/users/[id]/settings and GET /api/projects/[id]
 * (the middleware allowlist enforces the route scope; these route handlers accept
 * the principal). It is deliberately NOT accepted on llm-providers, tradecraft,
 * or any user-CRUD route. On its own it reads nothing: each of those routes also
 * requires the scan's job credential (`scannerJobRefusal`, step 1.16).
 */
export function isScannerRequest(request: NextRequest): boolean {
  const key = request.headers.get('x-internal-key')
  const expected = process.env.SCANNER_API_KEY
  if (!key || !expected || expected === 'changeme') return false
  return constantTimeEqual(key, expected)
}

export type UserAccessMode = 'read' | 'write' | 'revoke'

const OWN_ACCOUNT_ONLY =
  "Only the account itself can change this. An administrator can read another account's settings (secrets masked), but not change them."

/**
 * The write rule of an account's settings, LLM providers, skills, MCP servers and
 * tradecraft (HD-23, F-19): the REAL signed-in user must be the account. An admin
 * passes only while acting as a passwordless managed account, which has no session
 * of its own, so act-as is how it is run (OQ-49). Acting as an account that has a
 * password does not count: that account can sign in and write for itself.
 *
 * Session only: whether the internal key also writes is the caller's decision.
 * Returns null when allowed, or a 401/403 NextResponse the caller must return.
 */
export async function requireAccountWrite(targetUserId: string): Promise<NextResponse | null> {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (session.userId === targetUserId) return null
  // Only someone who acts as others can pass below, through act-as.
  if (!actsAsOthers(session)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  const target = await actAsTarget(session)
  if (target && target.id === targetUserId && !target.hasPassword) return null
  return NextResponse.json({ error: OWN_ACCOUNT_ONLY, code: 'own_account_only' }, { status: 403 })
}

/**
 * Ownership gate for user-scoped secret/data routes (settings, llm-providers,
 * tradecraft, skills, MCP servers and tokens). Internal-key callers (the agent +
 * scanners) pass in every mode.
 *  - `read`: the account itself, the account the session acts as (its own data,
 *    actsAsAccount), or the user directory (`users:read`, every admin with the
 *    permissions switch off). Every secret these routes return is masked for a
 *    browser caller, so an admin's read never sees one.
 *  - `write`: requireAccountWrite. The admin write bypass is gone: an admin cannot
 *    change another account, through act-as or not, except a passwordless managed
 *    account it is acting as.
 *  - `revoke`: the account itself or `users:revoke_sessions` (every admin with the
 *    permissions switch off), which revokes another account's MCP tokens (§5.1): an
 *    MCP token reached on another account to narrow or delete it during an incident
 *    (HD-23's one exception), never by the directory read alone.
 *
 * These routes expose or mutate a user's plaintext secrets (STRIDE I1). Returns null
 * when allowed, or a 401/403 NextResponse the caller must return.
 */
export async function requireUserAccess(
  request: NextRequest,
  targetUserId: string,
  { mode }: { mode: UserAccessMode },
): Promise<NextResponse | null> {
  if (isInternalRequest(request)) return null
  if (mode === 'write') return requireAccountWrite(targetUserId)
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const permission = mode === 'revoke' ? 'users:revoke_sessions' : 'users:read'
  if (session.userId === targetUserId || (await sessionHolds(session, permission))) return null
  // Revoking stays the real person's administration (§4.7), even of the account acted as.
  if (mode === 'read' && (await actsAsAccount(session, targetUserId))) return null
  return forbiddenResponse(permission)
}
