import { NextRequest, NextResponse } from 'next/server'
import { jwtVerify } from 'jose'
import { constantTimeEqual } from './lib/constantTimeEqual'

const AUTH_COOKIE_NAME = 'redamon-auth'

const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/logout', '/api/health', '/api/version/check', '/api/global/tunnel-config/sync']

// S2/E2: the internal-key bypass is scoped to exactly the routes that internal
// services (agent / orchestrator / recon) legitimately reach with X-Internal-Key.
// A valid key on ANY OTHER route no longer skips JWT once enforcement is on.
// method 'ANY' = any verb (routes with their own in-route isInternalRequest
// carve-outs, e.g. chat persistence + cypherfix remediations from the BOLA work).
const INTERNAL_ALLOWLIST: { method: string; pattern: RegExp }[] = [
  { method: 'GET', pattern: /^\/api\/users\/[^/]+\/llm-providers$/ },
  { method: 'GET', pattern: /^\/api\/users\/[^/]+\/settings$/ },
  { method: 'GET', pattern: /^\/api\/users\/[^/]+\/tradecraft-resources$/ },
  { method: 'GET', pattern: /^\/api\/projects\/[^/]+$/ },
  { method: 'ANY', pattern: /^\/api\/internal\/codefix-sandbox\// },
  // Agent-driven one-shot GuardDog (execute_guarddog, L3): X-Internal-Key
  // passthrough to the orchestrator, same lane as codefix-sandbox.
  { method: 'POST', pattern: /^\/api\/internal\/supply-chain\/guarddog$/ },
  // Global TrafficMind capture config, polled by the orchestrator to materialise
  // the DB settings to the proxy's config file (DB = single source of truth).
  { method: 'GET', pattern: /^\/api\/internal\/capture-config$/ },
  // Operator-recording session extraction: the ingest worker POSTs the login
  // material it pulled (pre-redaction) from operator-source traffic. The route
  // resolves the tenant from the recording session, never the body (G6).
  { method: 'POST', pattern: /^\/api\/internal\/auth-profile\/[^/]+\/observe$/ },
  { method: 'ANY', pattern: /^\/api\/conversations\/by-session\// },
  { method: 'ANY', pattern: /^\/api\/remediations(\/|$)/ },
  { method: 'GET', pattern: /^\/api\/global\/tunnel-config$/ },
  // Captured HTTP traffic ingest (recon via scanner key, agent via internal key).
  { method: 'POST', pattern: /^\/api\/traffic\/[^/]+\/ingest$/ },
  // Periodic traffic housekeeping (retention/quota/orphan GC), internal cron only.
  { method: 'POST', pattern: /^\/api\/traffic\/maintenance$/ },
  // Scan Timeline scheduler: the orchestrator worker polls for due schedules and
  // asks the webapp to run or defer them (the webapp owns the version freeze).
  { method: 'GET', pattern: /^\/api\/internal\/scan-schedules\/due$/ },
  { method: 'POST', pattern: /^\/api\/internal\/scan-schedules\/[^/]+\/run$/ },
  // Scan Queue: the orchestrator dispatcher peeks candidates, asks the webapp to
  // dispatch one (same start path the button uses), and posts terminal state.
  // The allowlist is FAIL-OPEN unless INTERNAL_KEY_ALLOWLIST_ENFORCE=true, so the
  // real control is isInternalRequest() in each route body, never this entry.
  { method: 'GET', pattern: /^\/api\/internal\/job-queue\/candidates$/ },
  { method: 'POST', pattern: /^\/api\/internal\/job-queue\/[^/]+\/dispatch$/ },
  { method: 'POST', pattern: /^\/api\/internal\/job-queue\/reconcile$/ },
  // Triage runs: the agent authorises a run, heartbeats it, claims the right to
  // publish, upserts the remediations and records how it ended. Exact paths, and
  // each route re-checks isInternalRequest plus the run's own project, because
  // the internal key is global and is therefore not a tenant boundary.
  { method: 'POST', pattern: /^\/api\/internal\/triage-runs$/ },
  { method: 'POST', pattern: /^\/api\/internal\/triage-runs\/[^/]+\/heartbeat$/ },
  { method: 'POST', pattern: /^\/api\/internal\/triage-runs\/[^/]+\/publish$/ },
  { method: 'POST', pattern: /^\/api\/internal\/triage-runs\/[^/]+\/remediations$/ },
  { method: 'POST', pattern: /^\/api\/internal\/triage-runs\/[^/]+\/finish$/ },
]

// Fail-open rollout: default log-only (never blocks), so an omitted route shows
// up in logs BEFORE it can break a caller. Flip to enforce with
// INTERNAL_KEY_ALLOWLIST_ENFORCE=true once the logs confirm only known routes.
const ENFORCE_ALLOWLIST = process.env.INTERNAL_KEY_ALLOWLIST_ENFORCE === 'true'

export function internalKeyRouteAllowed(method: string, pathname: string): boolean {
  return INTERNAL_ALLOWLIST.some(
    (a) => (a.method === 'ANY' || a.method === method) && a.pattern.test(pathname),
  )
}

// S3/E6: the scanner token is a strict SUBSET - only the two GET routes recon
// legitimately reads (its OSINT settings + project config). Excluded from
// llm-providers, tradecraft, and all user-CRUD. Enforced directly (SCANNER_API_KEY
// is a brand-new principal with no legacy callers, so there is nothing to break).
const SCANNER_ALLOWLIST: { method: string; pattern: RegExp }[] = [
  { method: 'GET', pattern: /^\/api\/users\/[^/]+\/settings$/ },
  { method: 'GET', pattern: /^\/api\/projects\/[^/]+$/ },
  // Recon POSTs captured HTTP transactions here (Phase 0 traffic capture). The
  // route handler resolves the tenant from the project owner, never the body.
  { method: 'POST', pattern: /^\/api\/traffic\/[^/]+\/ingest$/ },
]

export function scannerKeyRouteAllowed(method: string, pathname: string): boolean {
  return SCANNER_ALLOWLIST.some(
    (a) => (a.method === 'ANY' || a.method === method) && a.pattern.test(pathname),
  )
}

function getSecret() {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') return null
  return new TextEncoder().encode(secret)
}

async function verifyJwt(token: string): Promise<{ sub: string; role: string } | null> {
  try {
    const secret = getSecret()
    if (!secret) return null
    const { payload } = await jwtVerify(token, secret)
    if (!payload.sub || !payload.role) return null
    return { sub: payload.sub, role: payload.role as string }
  } catch {
    return null
  }
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow public paths
  if (PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))) {
    return NextResponse.next()
  }

  // Allow static assets and Next.js internals
  if (
    pathname.startsWith('/_next') ||
    pathname.startsWith('/favicon') ||
    pathname === '/logo.png' ||
    pathname === '/js_logo.png'
  ) {
    return NextResponse.next()
  }

  // Internal service-to-service calls (Docker network). S2/E2: constant-time
  // compare + route allowlist so a valid key does not blanket-skip JWT.
  const internalKey = request.headers.get('x-internal-key')
  const expectedKey = process.env.INTERNAL_API_KEY
  if (internalKey && expectedKey && expectedKey !== 'changeme' && constantTimeEqual(internalKey, expectedKey)) {
    if (internalKeyRouteAllowed(request.method, pathname)) {
      return NextResponse.next()
    }
    // Valid key but off-allowlist route.
    if (ENFORCE_ALLOWLIST) {
      // Fall through to the JWT check below - a service call has no auth cookie,
      // so it becomes 401 (or a redirect for a page). This is the closure.
      console.warn(`[internal-key] BLOCKED off-allowlist ${request.method} ${pathname}`)
    } else {
      console.warn(`[internal-key] off-allowlist ${request.method} ${pathname} (log-only; set INTERNAL_KEY_ALLOWLIST_ENFORCE=true to block)`)
      return NextResponse.next()
    }
  }

  // S3/E6: the scoped scanner token. Accepted ONLY on its two GET routes;
  // any other route with the scanner key falls through to JWT (401 for a
  // service). Enforced directly - no legacy callers hold this new token.
  const scannerKey = process.env.SCANNER_API_KEY
  if (internalKey && scannerKey && scannerKey !== 'changeme' && constantTimeEqual(internalKey, scannerKey)) {
    if (scannerKeyRouteAllowed(request.method, pathname)) {
      return NextResponse.next()
    }
    console.warn(`[scanner-key] BLOCKED out-of-scope ${request.method} ${pathname}`)
  }

  // Check JWT cookie
  const token = request.cookies.get(AUTH_COOKIE_NAME)?.value
  if (!token) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    return NextResponse.redirect(new URL('/login', request.url))
  }

  const payload = await verifyJwt(token)
  if (!payload) {
    // Invalid/expired token
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }
    const response = NextResponse.redirect(new URL('/login', request.url))
    response.cookies.delete(AUTH_COOKIE_NAME)
    return response
  }

  // Inject user info into request headers for downstream API routes
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-user-id', payload.sub)
  requestHeaders.set('x-user-role', payload.role)

  return NextResponse.next({ request: { headers: requestHeaders } })
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|favicon.png|logo.png|js_logo.png).*)'],
}
