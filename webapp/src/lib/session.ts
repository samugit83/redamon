import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken, verifyActAsToken, AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from './auth'
import { constantTimeEqual } from './constantTimeEqual'
import { cachedPrincipal, loadPrincipal, type LoadPrincipalOptions, type Principal } from './authz/principal'
import { rememberSessionPrincipal } from './authz/sessionPrincipal'
import { rbacFlags } from './authz/flags'
import { isRootAccount } from './authz/root'
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
 * signs the account out everywhere; the status counts only with the switch on.
 */
function tokenAccepted(sv: number, principal: Principal): boolean {
  if (sv !== principal.sessionVersion) return false
  return !rbacFlags().identity || principal.status === 'active'
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
  if (cached && !tokenAccepted(payload.sv, cached)) principal = await loadPrincipal(payload.sub, { fresh: true })
  if (!principal || !tokenAccepted(payload.sv, principal)) return refuse(cookieStore)
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

/**
 * The account an admin session is acting as: the act-as cookie must have been minted
 * by this admin and name an account that still exists. Null for anyone else.
 */
async function actAsTarget(session: Session, opts: SessionOptions = {}): Promise<Principal | null> {
  if (session.role !== 'admin') return null
  const cookieStore = await cookies()
  const actAsToken = cookieStore.get(ACT_AS_COOKIE_NAME)?.value
  if (!actAsToken) return null
  const claims = await verifyActAsToken(actAsToken)
  if (!claims || claims.sub !== session.userId) return null
  const target = await loadPrincipal(claims.act, opts)
  // Nobody acts as Root (identity switch on). A cookie minted before it was Root, or before
  // the switch, acts for nobody; Root is an admin, so a member target costs no instance read.
  if (target && target.role === 'admin' && target.id !== session.userId && await isRootAccount(target.id, opts)) return null
  return target
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
 * Returns admin session or a 401/403 NextResponse. Caller must check and return the response.
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

export type UserAccessMode = 'read' | 'write'

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
  if (session.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  const target = await actAsTarget(session)
  if (target && target.id === targetUserId && !target.hasPassword) return null
  return NextResponse.json({ error: OWN_ACCOUNT_ONLY, code: 'own_account_only' }, { status: 403 })
}

/**
 * Ownership gate for user-scoped secret/data routes (settings, llm-providers,
 * tradecraft, skills, MCP servers and tokens). Internal-key callers (the agent +
 * scanners) pass in both modes.
 *  - `read`: the account itself or an admin. Every secret these routes return is
 *    masked for a browser caller, so an admin's read never sees one.
 *  - `write`: requireAccountWrite. The admin write bypass is gone: an admin cannot
 *    change another account, through act-as or not, except a passwordless managed
 *    account it is acting as.
 *
 * Enforcement is IMMEDIATE (not the log-only ACCESS_ENFORCE path) because these
 * routes expose or mutate a user's plaintext secrets (STRIDE I1). Returns null
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
  if (session.userId !== targetUserId && session.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  return null
}
