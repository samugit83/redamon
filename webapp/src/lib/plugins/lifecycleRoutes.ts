import { NextRequest, NextResponse } from 'next/server'
import { readJsonBody } from '@/lib/jsonBody'
import { safeErrorCode } from '@/lib/routeErrors'
import { getSession } from '@/lib/session'
import { accountHolds } from '@/lib/authz/adminPermission'
import { LifecycleError } from './lifecycleCommon'
import { PluginConflictError } from './registry'
import { crossOriginResponse, sameOrigin } from './sameOrigin'

/**
 * The guard of every plugin lifecycle route. These routes put code on the host, so the
 * admin role is read from the database on each request: the role inside the login JWT
 * lasts seven days after a demotion (RV-11). The login session is the real admin's even
 * while they act as another user (`getSession` ignores the act-as cookie), so acting as a
 * standard user neither removes nor lends these rights, and the admin is the actor.
 */
const NO_STORE = { 'Cache-Control': 'no-store' }

export function errorResponse(
  status: number,
  code: string,
  error: string,
  details?: string[],
  extra?: Record<string, unknown>,
): NextResponse {
  return NextResponse.json({ error, code, ...(details?.length ? { details } : {}), ...extra }, { status, headers: NO_STORE })
}

/**
 * The 500 of a plugin route: the fixed sentence and the error's safe code (a Prisma or Node
 * code, else its class), never its message, which can quote a query's values.
 */
export function internalErrorResponse(e: unknown, what: string, error: string, extra?: Record<string, unknown>): NextResponse {
  const code = safeErrorCode(e)
  console.error(`[plugins] ${what} failed (${code}): ${(e as Error)?.stack ?? String(e)}`)
  return errorResponse(500, code, error, undefined, extra)
}

/**
 * Wraps a plugin route that has no catch of its own, so a throw (a database timeout) answers
 * `{error, code}` in the platform's shape instead of Next's empty 500 no client can read.
 */
export function pluginRoute<A extends unknown[]>(
  what: string,
  error: string,
  handler: (...args: A) => Promise<Response>,
): (...args: A) => Promise<Response> {
  return async (...args: A) => {
    try {
      return await handler(...args)
    } catch (e) {
      return internalErrorResponse(e, what, error)
    }
  }
}

/**
 * The signed-in person when they hold `platform:plugins`. The account is read again (fresh): a
 * change of the person's role or profile reaches the next plugin action at once.
 */
export async function requirePluginAdmin(): Promise<{ userId: string } | NextResponse> {
  const session = await getSession()
  if (!session) return errorResponse(401, 'unauthorized', 'Sign in first.')
  if (!(await accountHolds(session.userId, 'platform:plugins', { fresh: true }))) {
    return errorResponse(403, 'admin_required', 'Only an administrator can manage plugins.')
  }
  return { userId: session.userId }
}

export function lifecycleErrorResponse(e: unknown, what: string): NextResponse {
  if (e instanceof LifecycleError) return errorResponse(e.status, e.code, e.message, e.details, e.extra)
  if (e instanceof PluginConflictError) return errorResponse(409, 'plugin_busy', e.message)
  return internalErrorResponse(e, what, 'The plugin operation failed; see the webapp log.')
}

/** The admin check, its database read failing as a 500 the page can read. */
async function adminOrResponse(what: string): Promise<{ userId: string } | NextResponse> {
  try {
    return await requirePluginAdmin()
  } catch (e) {
    return lifecycleErrorResponse(e, what)
  }
}

/** A state-changing route: admin, same origin, a JSON object body, then `run`. */
export async function lifecyclePost(
  request: NextRequest,
  what: string,
  run: (body: Record<string, unknown>, adminId: string) => Promise<unknown>,
): Promise<NextResponse> {
  const admin = await adminOrResponse(what)
  if (admin instanceof NextResponse) return admin
  if (!sameOrigin(request)) return crossOriginResponse(request)
  const parsed = await readJsonBody(request)
  if (parsed instanceof NextResponse) return parsed
  const started = Date.now()
  try {
    const out = await run(parsed.body, admin.userId)
    console.log(`[plugins] ${what} by ${admin.userId}: ok in ${Date.now() - started} ms`)
    return NextResponse.json(out, { headers: NO_STORE })
  } catch (e) {
    const res = lifecycleErrorResponse(e, what)
    console.warn(`[plugins] ${what} by ${admin.userId}: ${res.status} in ${Date.now() - started} ms`)
    return res
  }
}

/** A read-only admin route: admin, then `run`. */
export async function lifecycleGet(what: string, run: (adminId: string) => Promise<NextResponse>): Promise<NextResponse> {
  const admin = await adminOrResponse(what)
  if (admin instanceof NextResponse) return admin
  try {
    return await run(admin.userId)
  } catch (e) {
    return lifecycleErrorResponse(e, what)
  }
}
