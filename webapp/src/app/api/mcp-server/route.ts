/**
 * The inbound MCP server.
 *
 * RedAmon is the SERVER here: an external agent connects in and acts as one
 * RedAmon user. That single fact drives every guard below.
 *
 * The path is `/api/mcp-server`, never `/api/mcp`. `/api/mcp/` is already the
 * OUTBOUND MCP-plugin admin namespace, and the middleware matches public paths
 * as `pathname === p || pathname.startsWith(p + '/')`, so a PUBLIC_PATHS entry
 * of `/api/mcp` would expose all three of those routes unauthenticated.
 *
 * BEARER ONLY. Being in PUBLIC_PATHS also skips the middleware's
 * X-Internal-Key / X-Scanner-Key handling, so this route authenticates solely
 * by `Authorization: Bearer` and explicitly ignores everything else:
 *
 *  - honouring the session cookie would make a middleware-exempt,
 *    state-changing POST CSRF-reachable from a logged-in operator's browser.
 *    sameSite: 'lax' blocks a cross-site POST today, but SameSite must not be
 *    the only control.
 *  - honouring X-Scanner-Key would let a leaked scanner token - held by every
 *    spawned scan container, the least-trusted tier - authenticate to the
 *    control plane. That inverts the trust model.
 *
 * Stateless JSON mode: no server-held session, so the route never depends on
 * SSE buffering behaviour at the edge, and GET/DELETE have no stream to manage.
 */
import { NextRequest, NextResponse } from 'next/server'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'

import { writeAudit } from '@/lib/audit'
import { resolveMcpUser, type McpAuthFailure } from '@/lib/mcpAuth'
import { buildMcpServer } from '@/lib/mcp/server'
import { buildInstructions } from '@/lib/mcp/instructions'
import { mcpServerEnabled } from '@/lib/mcpServerEnabled'

export const runtime = 'nodejs'
/** The tools read live data; a cached MCP response would be actively wrong. */
export const dynamic = 'force-dynamic'

/**
 * 1 MiB. Sized for the one large legitimate call: a mute or unmute naming
 * 5,000 findings by id, and an id runs to 200 characters. Every other tool
 * call is a small JSON-RPC envelope; anything larger than this is abuse.
 */
const MAX_BODY_BYTES = 1024 * 1024

/**
 * Read the body, aborting once it exceeds `limit` BYTES.
 *
 * Bytes, not `String.length`: the latter counts UTF-16 code units, so a body
 * of three-byte characters is three times its length in bytes and passed a
 * check documented in bytes.
 * Streaming means a huge body costs the limit, not its own size.
 */
async function readBounded(request: NextRequest, limit: number): Promise<string> {
  const body = request.body
  if (!body) return ''
  const reader = body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > limit) throw new Error('body too large')
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const joined = new Uint8Array(total)
  let offset = 0
  for (const c of chunks) { joined.set(c, offset); offset += c.byteLength }
  return new TextDecoder().decode(joined)
}

// One audit row per prefix per minute. Bounded and lazily swept, the same shape
// as loginThrottle: a flood of DISTINCT prefixes must not turn an anti-abuse
// record into the memory-exhaustion vector it exists to detect.
const AUTH_AUDIT_WINDOW_MS = 60_000
const AUTH_AUDIT_MAX_KEYS = 5_000
const globalForAuthAudit = globalThis as unknown as { __mcpAuthAudit?: Map<string, number> }
const authAuditSeen: Map<string, number> = globalForAuthAudit.__mcpAuthAudit ?? new Map()
globalForAuthAudit.__mcpAuthAudit = authAuditSeen

export function shouldAuditAuthFailure(key: string, now = Date.now()): boolean {
  const prev = authAuditSeen.get(key) ?? 0
  if (now - prev < AUTH_AUDIT_WINDOW_MS) return false
  if (authAuditSeen.size >= AUTH_AUDIT_MAX_KEYS) {
    for (const [k, t] of authAuditSeen) {
      if (now - t >= AUTH_AUDIT_WINDOW_MS) authAuditSeen.delete(k)
    }
    // Still full of live entries: drop the oldest half rather than grow.
    if (authAuditSeen.size >= AUTH_AUDIT_MAX_KEYS) {
      const oldest = [...authAuditSeen.entries()].sort((a, b) => a[1] - b[1])
      for (const [k] of oldest.slice(0, Math.floor(oldest.length / 2))) authAuditSeen.delete(k)
    }
  }
  authAuditSeen.set(key, now)
  return true
}

/** Test seam: the map is process-global by design. */
export function __resetAuthAuditThrottle(): void {
  authAuditSeen.clear()
}

export { mcpServerEnabled }

/**
 * What a disabled deployment answers, to every caller alike.
 *
 * It names the switch because a bare "Not found" is indistinguishable from a
 * mistyped URL, and sends an operator after paths and auth schemes instead of
 * the flag. Naming it reveals nothing a caller cannot already see - the JSON-RPC
 * envelope already tells this route apart from a nonexistent one - and it is
 * returned before any token is read, so token validity stays hidden.
 *
 * Still a 404: `deploy.sh verify` and the wiki's troubleshooting table key on
 * that status. -32000 is JSON-RPC's implementation-defined server error;
 * -32601 would claim the METHOD is unknown, which it is not.
 */
export const MCP_DISABLED_MESSAGE =
  'The MCP server is disabled on this RedAmon deployment. An operator enables it with ' +
  'MCP_SERVER_ENABLED=true in .env, then recreates the webapp container ' +
  '(docker compose up -d webapp).'

function jsonRpcError(code: number, message: string, status: number): NextResponse {
  return NextResponse.json(
    { jsonrpc: '2.0', error: { code, message }, id: null },
    { status, headers: { 'Cache-Control': 'no-store' } }
  )
}

/** 401-equivalent. The reason is logged; the caller gets one stable line. */
function unauthorized(failure: McpAuthFailure, prefix?: string): NextResponse {
  console.warn(`[mcp] auth rejected: ${failure}${prefix ? ` prefix=${prefix}` : ''}`)
  return jsonRpcError(-32001, 'Unauthorized', 401)
}

/**
 * Reject a request whose Origin is present and is not our own.
 *
 * A browser always sends Origin on a cross-site fetch, so this blocks
 * browser-driven abuse and DNS rebinding. A non-browser client sends none,
 * which is why an ABSENT origin is allowed: MCP clients are not browsers.
 *
 * MCP_ALLOWED_ORIGIN is consulted first because the request-derived origin is
 * NOT reliable behind a reverse proxy. nginx forwards `Host $host`, and $host
 * DROPS THE PORT, so on a deploy using a non-default port a client sending its
 * own correct origin (https://host:8443) would be compared against
 * "host" and rejected as cross-origin. The deploy sets this explicitly; locally
 * it is empty and the request-derived check applies, which is right when
 * nothing sits in front of the app.
 */
function originAllowed(request: NextRequest): boolean {
  const origin = request.headers.get('origin')
  if (!origin) return true

  let candidate: URL
  try {
    candidate = new URL(origin)
  } catch {
    return false
  }

  const configured = (process.env.MCP_ALLOWED_ORIGIN || '').trim()
  if (configured) {
    try {
      const allowed = new URL(configured)
      // Compare the full origin (scheme + host + port), not just the host: a
      // plaintext http:// origin must not pass on an https deployment.
      return candidate.origin === allowed.origin
    } catch {
      console.error(`[mcp] MCP_ALLOWED_ORIGIN is not a valid URL: ${configured}`)
      return false
    }
  }

  try {
    return candidate.host === new URL(request.url).host
  } catch {
    return false
  }
}

export async function POST(request: NextRequest) {
  // The flag is checked before anything else, so a disabled deployment does no
  // database work and reveals nothing about whether a token is valid.
  if (!mcpServerEnabled()) {
    return jsonRpcError(-32000, MCP_DISABLED_MESSAGE, 404)
  }

  const contentType = request.headers.get('content-type') || ''
  if (!contentType.toLowerCase().includes('application/json')) {
    // A plain HTML form cannot set this, so it cannot drive the endpoint.
    return jsonRpcError(-32700, 'Content-Type must be application/json', 415)
  }
  if (!originAllowed(request)) {
    console.warn(`[mcp] rejected cross-origin request from ${request.headers.get('origin')}`)
    return jsonRpcError(-32001, 'Forbidden', 403)
  }

  // Size is checked from the DECLARED length before the body is read, because
  // this route is in PUBLIC_PATHS and App Router imposes no body limit of its
  // own: buffering first would let an unauthenticated caller OOM the control
  // plane with a multi-GB POST. A chunked request declares no length, so the
  // read below is also bounded as it streams.
  const declared = Number(request.headers.get('content-length') ?? '')
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return jsonRpcError(-32700, 'Request body too large', 413)
  }

  let raw: string
  try {
    raw = await readBounded(request, MAX_BODY_BYTES)
  } catch {
    return jsonRpcError(-32700, 'Request body too large', 413)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return jsonRpcError(-32700, 'Parse error', 400)
  }
  // Read from the already-parsed body rather than re-parsing: this only decides
  // whether to spend a database read composing the connect-time instructions,
  // so a malformed method simply means "not initialize".
  const isInitialize =
    typeof parsed === 'object' && parsed !== null &&
    (parsed as { method?: unknown }).method === 'initialize'
  if (Array.isArray(parsed)) {
    // Stateless mode answers one request per call; a batch would let one
    // authenticated call fan out past every per-call budget below.
    return jsonRpcError(-32600, 'Batch requests are not supported', 400)
  }

  let auth: Awaited<ReturnType<typeof resolveMcpUser>>
  try {
    auth = await resolveMcpUser(request)
  } catch (err) {
    // The token row or its owner's permissions could not be read: refused, never the row's scopes.
    console.error('[mcp] token resolution failed:', err)
    return jsonRpcError(-32603, 'Internal error', 500)
  }
  if (!auth.ok || !auth.token) {
    // Audited, but THROTTLED per prefix. This path is pre-auth and public, so
    // an unthrottled insert lets an anonymous flood of `Bearer rdmn_mcp_xxxx`
    // write unbounded rows into the Postgres the whole platform shares. The
    // signal a repeated failure carries survives sampling; the disk does not.
    if (shouldAuditAuthFailure(auth.prefix ?? auth.failure ?? 'unknown')) {
      void writeAudit({
        actorId: null,
        action: 'mcp.auth.denied',
        targetType: 'mcpAccessToken',
        targetId: auth.prefix ?? null,
        after: { failure: auth.failure, tokenPrefix: auth.prefix ?? null },
        source: 'mcp',
      })
    }
    return unauthorized(auth.failure ?? 'invalid', auth.prefix)
  }

  // Onboarding is composed only for `initialize`, which is where the client
  // reads it. The transport is stateless, so the server is rebuilt for every
  // request; doing this on each tool call would add a database read and a
  // tool-list build to every call for a string that is never read again. The scopes are the
  // usable ones (minted ∩ the owner's permissions), so the text never promises a lost one.
  const instructions = isInitialize
    ? await buildInstructions(auth.token.tokenId, auth.token.scopes)
    : undefined

  const server = buildMcpServer({ token: auth.token }, instructions)
  const transport = new WebStandardStreamableHTTPServerTransport({
    // Stateless: no session id, so nothing is held between requests and the
    // token is re-verified on every call.
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  })

  try {
    await server.connect(transport)
    const response = await transport.handleRequest(request, { parsedBody: parsed })
    const headers = new Headers(response.headers)
    headers.set('Cache-Control', 'no-store')
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    })
  } catch (err) {
    console.error('[mcp] request handling failed:', err)
    return jsonRpcError(-32603, 'Internal error', 500)
  } finally {
    // Stateless mode: the server and transport live for exactly this request.
    await server.close().catch(() => undefined)
  }
}

/** Stateless mode has no stream to resume and no session to delete. */
export async function GET() {
  return jsonRpcError(-32601, 'Method not allowed', 405)
}

export async function DELETE() {
  return jsonRpcError(-32601, 'Method not allowed', 405)
}
