import { NextRequest, NextResponse } from 'next/server'
import { SignJWT, jwtVerify, type JWTPayload } from 'jose'
import { constantTimeEqual } from './lib/constantTimeEqual'
import { rbacFlags } from './lib/authz/flags'
import { now } from './lib/authz/clock'
import { isSecureRequest } from './lib/cookieSecurity'
import { MUST_CHANGE_CODE, MUST_CHANGE_MESSAGE, MUST_CHANGE_PAGE, mustChangeAllows } from './lib/authz/mustChangeGate'
import { SESSION_IDLE_CODE, SESSION_IDLE_MESSAGE, idleVerdict, lifetimeClaimsValid } from './lib/authz/sessionIdle'

const AUTH_COOKIE_NAME = 'redamon-auth'

// '/api/mcp-server' follows the /api/auth/login precedent: public at the
// middleware layer, with the handler performing its own credential check and
// failing closed. An MCP client presents a bearer and no cookie, so without
// this entry every MCP request is rejected before reaching the handler.
//
// It must NOT be written as '/api/mcp': matching is
// `pathname === p || pathname.startsWith(p + '/')`, so that entry would make
// the OUTBOUND plugin-admin routes (/api/mcp/manifest|reload|test) public too.
const PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/logout', '/api/health', '/api/version/check', '/api/global/tunnel-config/sync', '/api/mcp-server']

// Invite links (step 2.9): the page a link opens and its API are sessionless while
// RBAC_IDENTITY_ENABLED is on; with it off they do not exist and answer as any unknown path
// (sign-in redirect, 401). Matched as PUBLIC_PATHS are, so '/invitex' is not public.
const INVITE_PUBLIC_PATHS = ['/invite', '/api/invite']

// Plugin platform routes that authenticate with their own credential and no cookie:
// plugin code calls the Gateway with a call token, the runner fetches its run list with
// the runner key. Their handlers never honour X-Internal-Key, getSession or the
// effective user (RV-33). Each entry is an exact prefix ending at the version segment's
// `/`: without it, `/api/plugin-gateway/v10/` or `/api/plugin-gatewayx` would be public.
const TOKEN_AUTH_PREFIXES = ['/api/plugin-gateway/v1/', '/api/plugin-runner/v1/']

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
  // Periodic pruning of long-dead MCP access tokens. The webapp has no
  // scheduler of its own, so the orchestrator's maintenance loop drives it.
  { method: 'POST', pattern: /^\/api\/internal\/mcp-tokens\/prune$/ },
  // Plugin reconciliation (TD-20), driven by the same loop; the route re-checks the key.
  { method: 'POST', pattern: /^\/api\/internal\/plugins\/reconcile$/ },
  // The RBAC expiry sweep (step 4.15), driven by the same loop; the route re-checks the key.
  { method: 'POST', pattern: /^\/api\/internal\/rbac\/sweep$/ },
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
  // Node-filter apply runs: the agent reads the run it was handed, heartbeats
  // it and records how it ended. Each route re-checks isInternalRequest.
  { method: 'GET', pattern: /^\/api\/internal\/node-filter-runs\/[^/]+$/ },
  { method: 'POST', pattern: /^\/api\/internal\/node-filter-runs\/[^/]+\/heartbeat$/ },
  { method: 'POST', pattern: /^\/api\/internal\/node-filter-runs\/[^/]+\/finish$/ },
  // The agent records who answered an approval it accepted (step 3.9b); the route re-checks the key.
  { method: 'POST', pattern: /^\/api\/internal\/agent\/decisions$/ },
  // ...and asks, before it accepts an answer, whether that person may still take it (step 5.4).
  { method: 'POST', pattern: /^\/api\/internal\/agent\/authorize-decision$/ },
  // The daily budget on instance LLM providers (step 6.11): the agent reads a person's limit and use,
  // and reports its counts every minute. The route re-checks the master key.
  { method: 'GET', pattern: /^\/api\/internal\/llm-usage$/ },
  { method: 'POST', pattern: /^\/api\/internal\/llm-usage$/ },
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

const isPluginPage = (pathname: string) => pathname === '/plugins' || pathname.startsWith('/plugins/')

/**
 * The Content-Security-Policy of plugin pages (/plugins and /plugins/*), where plugin
 * screens are drawn. Strict, but with 'unsafe-inline' because Next.js inlines its
 * bootstrap scripts and styles; dev mode also needs 'unsafe-eval'. Plugin text shown
 * elsewhere (the chat drawer, project settings) gets no CSP here, since a strict one would
 * break those pages: SafeMarkdown and React escaping are the controls there.
 */
export function pluginPagesCsp(): string {
  const script = process.env.NODE_ENV === 'production' ? "'self' 'unsafe-inline'" : "'self' 'unsafe-inline' 'unsafe-eval'"
  return [
    "default-src 'self'",
    `script-src ${script}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ')
}

/**
 * The invite page's policy (`/invite`, `/invite/<token>`): a signed-out browser holding a
 * one-time link, so the same strict policy as the plugin pages, which still lets the Next.js
 * bootstrap run; the page loads nothing from another origin.
 */
export function invitePagesCsp(): string {
  return pluginPagesCsp()
}

function getSecret() {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') return null
  return new TextEncoder().encode(secret)
}

async function verifyJwt(token: string): Promise<{ sub: string; role: string; pwc: boolean; claims: JWTPayload } | null> {
  try {
    const secret = getSecret()
    if (!secret) return null
    const { payload } = await jwtVerify(token, secret)
    if (!payload.sub || !payload.role) return null
    // As lib/auth.ts verifyToken: a must-change claim other than 1, or a malformed lifetime
    // claim, makes the token invalid.
    if (payload.pwc !== undefined && payload.pwc !== 1) return null
    if (!lifetimeClaimsValid(payload)) return null
    return { sub: payload.sub, role: payload.role as string, pwc: payload.pwc === 1, claims: payload }
  } catch {
    return null
  }
}

/**
 * The same login token with its last activity moved to `nowSeconds`: same claims, same expiry,
 * so activity never stretches a session past the lifetime it was signed with.
 */
async function withActivity(claims: JWTPayload, nowSeconds: number): Promise<string | null> {
  const secret = getSecret()
  if (!secret) return null
  return new SignJWT({ ...claims, lat: nowSeconds }).setProtectedHeader({ alg: 'HS256' }).sign(secret)
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  // Allow public paths
  if (PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))) {
    return NextResponse.next()
  }
  if (rbacFlags().identity && INVITE_PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/'))) {
    // No session here: user headers can only be the caller's own.
    const headers = new Headers(request.headers)
    headers.delete('x-user-id')
    headers.delete('x-user-role')
    const response = NextResponse.next({ request: { headers } })
    // The token is in the address until the route trades it for a cookie: never sent on.
    response.headers.set('Referrer-Policy', 'no-referrer')
    if (!pathname.startsWith('/api/')) response.headers.set('Content-Security-Policy', invitePagesCsp())
    return response
  }
  if (TOKEN_AUTH_PREFIXES.some(p => pathname.startsWith(p))) {
    // No session on these routes: user headers can only be the caller's own.
    const headers = new Headers(request.headers)
    headers.delete('x-user-id')
    headers.delete('x-user-role')
    return NextResponse.next({ request: { headers } })
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

  // Step 2.11 (identity switch on): an admin's token idle longer than its limit ends here; the
  // API answer's code sends the browser to sign-in (AuthProvider), as for any ended session.
  const identity = rbacFlags().identity
  const nowSeconds = Math.floor(now().getTime() / 1000)
  const idle = identity ? idleVerdict(payload.claims, nowSeconds) : 'none'
  if (idle === 'idle') {
    const response = pathname.startsWith('/api/')
      ? NextResponse.json({ error: SESSION_IDLE_MESSAGE, code: SESSION_IDLE_CODE }, { status: 401 })
      : NextResponse.redirect(new URL('/login', request.url))
    response.cookies.delete(AUTH_COOKIE_NAME)
    return response
  }

  // Step 2.8 (identity switch on): an account whose password must change reaches only the
  // change page and what it needs. The handlers compare the claim with the account (session.ts).
  if (payload.pwc && identity && !mustChangeAllows(request.method, pathname, payload.sub)) {
    if (pathname.startsWith('/api/')) {
      return NextResponse.json({ error: MUST_CHANGE_MESSAGE, code: MUST_CHANGE_CODE }, { status: 403 })
    }
    return NextResponse.redirect(new URL(MUST_CHANGE_PAGE, request.url))
  }

  // Inject user info into request headers for downstream API routes
  const requestHeaders = new Headers(request.headers)
  requestHeaders.set('x-user-id', payload.sub)
  requestHeaders.set('x-user-role', payload.role)

  const response = NextResponse.next({ request: { headers: requestHeaders } })
  if (isPluginPage(pathname)) response.headers.set('Content-Security-Policy', pluginPagesCsp())
  if (idle === 'refresh' && typeof payload.claims.exp === 'number') {
    const refreshed = await withActivity(payload.claims, nowSeconds)
    if (refreshed) {
      // The attributes of lib/loginCookie.ts setLoginCookie, which this module cannot import.
      response.cookies.set(AUTH_COOKIE_NAME, refreshed, {
        httpOnly: true,
        sameSite: 'lax',
        secure: isSecureRequest(request),
        path: '/',
        maxAge: Math.max(payload.claims.exp - nowSeconds, 0),
      })
    }
  }
  return response
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|favicon.png|logo.png|js_logo.png).*)'],
}
