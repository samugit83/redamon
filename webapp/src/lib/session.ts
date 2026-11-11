import { cookies } from 'next/headers'
import { NextRequest, NextResponse } from 'next/server'
import { verifyToken, verifyActAsToken, AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from './auth'
import { constantTimeEqual } from './constantTimeEqual'
import { loadPrincipal } from './authz/principal'
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

/**
 * The signed-in account, or null (the caller answers 401). The login JWT proves who
 * signed in; whether that account still exists and its role are read from the
 * database, so the role claim in the token is never trusted. A failed database
 * read throws: it never reads as signed in.
 */
export async function getSession(): Promise<Session | null> {
  const cookieStore = await cookies()
  const token = cookieStore.get(AUTH_COOKIE_NAME)?.value
  if (!token) return null
  const payload = await verifyToken(token)
  if (!payload) return null
  const principal = await loadPrincipal(payload.sub)
  if (!principal) return null
  return { userId: principal.id, role: principal.role }
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
export async function getEffectiveUser(): Promise<EffectiveUser | null> {
  const session = await getSession()
  if (!session) return null
  if (session.role !== 'admin') {
    return { userId: session.userId }
  }
  const cookieStore = await cookies()
  const actAsToken = cookieStore.get(ACT_AS_COOKIE_NAME)?.value
  if (actAsToken) {
    const claims = await verifyActAsToken(actAsToken)
    if (claims && claims.sub === session.userId && (await loadPrincipal(claims.act))) {
      return { userId: claims.act }
    }
  }
  return { userId: session.userId }
}

/**
 * Returns session or a 401 NextResponse (a coded 500 when the account could not be
 * read). Caller must check and return the response.
 * Usage: const result = await requireSession(); if (result instanceof NextResponse) return result;
 */
export async function requireSession(): Promise<Session | NextResponse> {
  let session: Session | null
  try {
    session = await getSession()
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
export async function requireAdmin(): Promise<Session | NextResponse> {
  const result = await requireSession()
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
 * or any user-CRUD route.
 */
export function isScannerRequest(request: NextRequest): boolean {
  const key = request.headers.get('x-internal-key')
  const expected = process.env.SCANNER_API_KEY
  if (!key || !expected || expected === 'changeme') return false
  return constantTimeEqual(key, expected)
}

/**
 * Ownership gate for user-scoped secret/data routes (settings, llm-providers,
 * tradecraft). Internal-key callers (the agent + scanners) pass through; every
 * other caller must have a session and either own `targetUserId` or be an admin.
 *
 * Enforcement is IMMEDIATE (not the log-only ACCESS_ENFORCE path) because these
 * routes expose or mutate a user's plaintext secrets - this is the closure of
 * STRIDE I1 for the single-item routes the list-route fix missed. Returns null
 * when allowed, or a 401/403 NextResponse the caller must return.
 *
 * Note: the admin bypass here is a masked-read/write convenience preserved from
 * the shipped I1 model; the stricter effective-user scoping of admins (admin sees
 * a user's data only while explicitly simulating them) is applied to the data
 * routes in the BOLA rollout and may later subsume this bypass.
 */
export async function requireUserAccess(
  request: NextRequest,
  targetUserId: string
): Promise<NextResponse | null> {
  if (isInternalRequest(request)) return null
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  if (session.userId !== targetUserId && session.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  return null
}
