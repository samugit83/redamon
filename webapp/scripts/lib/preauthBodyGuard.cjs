'use strict'
// D9: refuse a large request body from a caller with no credential BEFORE Next.js reads it.
//
// For every request that is not a GET or HEAD, Next.js copies the body for the middleware,
// up to proxyClientMaxBodySize (60 MB, next.config.ts), and waits for the whole body before
// acting on the middleware's answer, a 401 included. So anyone who reached the webapp could
// make its one Node.js process hold 60 to 120 MB per connection, without any credential, until
// it was OOM-killed. This guard wraps the request listener Next.js hands to
// http.createServer and looks only at the headers: a body over 1 MiB goes through only with
// a credential the webapp would accept, checked here the way the webapp checks it. Anything
// smaller passes untouched: the largest body an uncredentialed caller legitimately sends is
// the inbound MCP server's (64 KiB).
//
// The credentials: the login cookie (an HS256 JWT signed with AUTH_SECRET, with `sub` and
// `role`, as lib/auth.ts verifies it), the X-Internal-Key of a RedAmon service
// (INTERNAL_API_KEY or SCANNER_API_KEY), and a plugin call token in a Bearer header (an HS256
// JWT signed with PLUGIN_CALL_TOKEN_SECRET for the gateway audience, lib/plugins/callToken.ts).
// Only the signature and the time claims are checked: the route checks the rest.

const nodeHttp = require('node:http')
const nodeHttps = require('node:https')
const { createHmac, timingSafeEqual } = require('node:crypto')

const UNAUTHENTICATED_MAX_BODY_BYTES = 1024 * 1024
const AUTH_COOKIE_NAME = 'redamon-auth'
const CALL_TOKEN_AUDIENCE = 'redamon-plugin-gateway'
const CALL_TOKEN_SECRET_MIN_CHARS = 32
const MAX_TOKEN_CHARS = 8192
const GUARDED = Symbol.for('redamon.preauthBodyGuard')

let guardedServers = 0

function jsonPart(part) {
  try {
    const value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'))
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null
  } catch {
    return null
  }
}

/** The payload of an HS256 JWT signed with `secret` and inside its time claims, else null. */
function verifyHs256(token, secret, nowSeconds) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_CHARS || !secret) return null
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [header, payload, signature] = parts
  if (jsonPart(header)?.alg !== 'HS256') return null
  const expected = createHmac('sha256', secret).update(`${header}.${payload}`).digest()
  const given = Buffer.from(signature, 'base64url')
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null
  const claims = jsonPart(payload)
  if (!claims) return null
  if (claims.exp !== undefined && !(typeof claims.exp === 'number' && claims.exp > nowSeconds)) return null
  if (claims.nbf !== undefined && !(typeof claims.nbf === 'number' && claims.nbf <= nowSeconds)) return null
  return claims
}

function sameSecret(given, expected) {
  const a = Buffer.from(given, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}

function cookieValue(header, name) {
  if (typeof header !== 'string') return null
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0 || part.slice(0, eq).trim() !== name) continue
    const raw = part.slice(eq + 1).trim()
    try {
      return decodeURIComponent(raw)
    } catch {
      return raw
    }
  }
  return null
}

function bearerToken(header) {
  const m = /^Bearer ([A-Za-z0-9._~+/=-]+)$/.exec(typeof header === 'string' ? header.trim() : '')
  return m ? m[1] : null
}

// Unset, or left at the compose default: never a credential (lib/auth.ts, lib/session.ts).
const configured = (v) => typeof v === 'string' && v !== '' && v !== 'changeme'

/** Which credential the request carries ('session', 'internal-key', 'plugin-call-token'), or null. */
function credentialOf(headers, env, nowSeconds) {
  if (configured(env.AUTH_SECRET)) {
    const claims = verifyHs256(cookieValue(headers.cookie, AUTH_COOKIE_NAME), env.AUTH_SECRET, nowSeconds)
    if (claims && claims.sub && claims.role) return 'session'
  }
  const key = headers['x-internal-key']
  if (typeof key === 'string' && key !== '') {
    for (const name of ['INTERNAL_API_KEY', 'SCANNER_API_KEY']) {
      if (configured(env[name]) && sameSecret(key, env[name])) return 'internal-key'
    }
  }
  const callSecret = (env.PLUGIN_CALL_TOKEN_SECRET || '').trim()
  if (configured(callSecret) && callSecret.length >= CALL_TOKEN_SECRET_MIN_CHARS) {
    const claims = verifyHs256(bearerToken(headers.authorization), callSecret, nowSeconds)
    const aud = claims && (Array.isArray(claims.aud) ? claims.aud : [claims.aud])
    if (aud && aud.includes(CALL_TOKEN_AUDIENCE)) return 'plugin-call-token'
  }
  return null
}

// One line a minute at most, so a flood of refusals cannot fill the container log (D3).
function refusalLogger(log = console.warn, intervalMs = 60_000) {
  let count = 0
  let last = 0
  return (reason) => {
    count += 1
    const now = Date.now()
    if (now - last < intervalMs) return
    log(`[preauth-guard] refused ${count} request body(ies) over ${UNAUTHENTICATED_MAX_BODY_BYTES} bytes without a credential (last: ${reason})`)
    count = 0
    last = now
  }
}

function refuse(res, onRefuse) {
  onRefuse('declared length')
  // The body is never read: Connection: close ends the request here.
  res.shouldKeepAlive = false
  res.writeHead(413, { 'Content-Type': 'application/json', Connection: 'close' })
  res.end(JSON.stringify({ error: 'Request body too large', code: 'body_too_large_unauthenticated' }))
}

// A chunked body has no declared length: count what flows to whoever reads it, and drop the
// connection once it passes the limit. Counting at emit leaves the stream's mode untouched,
// so Next.js reads the body exactly as it would without the guard.
function capStreamedBody(req, limit, onRefuse) {
  let seen = 0
  const emit = req.emit
  req.emit = function (event, ...args) {
    if (event === 'data') {
      const chunk = args[0]
      seen += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.length
      if (seen > limit) {
        req.emit = emit
        onRefuse('streamed length')
        req.destroy()
        return false
      }
    }
    return emit.call(this, event, ...args)
  }
}

/** Whether the request may reach Next.js; a refused one has been answered or dropped. */
function admit(req, res, { limit, env, nowSeconds, onRefuse }) {
  if (req.method === 'GET' || req.method === 'HEAD') return true
  const streamed = req.headers['transfer-encoding'] !== undefined
  const length = req.headers['content-length']
  // Node's parser has already refused a malformed length, or one beside Transfer-Encoding.
  if (!streamed && (length === undefined || Number(length) <= limit)) return true
  if (credentialOf(req.headers, env, nowSeconds)) return true
  if (!streamed) {
    refuse(res, onRefuse)
    return false
  }
  capStreamedBody(req, limit, onRefuse)
  return true
}

function guardListener(listener, opts = {}) {
  if (listener[GUARDED]) return listener
  const limit = opts.maxBytes ?? UNAUTHENTICATED_MAX_BODY_BYTES
  const env = opts.env ?? process.env
  const clock = opts.now ?? Date.now
  const onRefuse = opts.onRefuse ?? refusalLogger()
  function guarded(req, res) {
    if (!admit(req, res, { limit, env, nowSeconds: Math.floor(clock() / 1000), onRefuse })) return
    return listener.call(this, req, res)
  }
  guarded[GUARDED] = true
  return guarded
}

/**
 * Wrap the request listener of every server created from now on through
 * `http.createServer` / `https.createServer` (the way Next.js's start-server creates its own).
 */
function installPreauthBodyGuard(opts = {}) {
  const modules = opts.modules ?? [nodeHttp, nodeHttps]
  for (const mod of modules) {
    const original = mod.createServer
    if (original[GUARDED]) continue
    const createServer = function (...args) {
      const at = args.findIndex((a) => typeof a === 'function')
      if (at >= 0) {
        args[at] = guardListener(args[at], opts)
        guardedServers += 1
      }
      return original.apply(this, args)
    }
    createServer[GUARDED] = true
    mod.createServer = createServer
  }
}

function guardedServerCount() {
  return guardedServers
}

module.exports = {
  UNAUTHENTICATED_MAX_BODY_BYTES,
  AUTH_COOKIE_NAME,
  CALL_TOKEN_AUDIENCE,
  verifyHs256,
  credentialOf,
  guardListener,
  installPreauthBodyGuard,
  guardedServerCount,
  refusalLogger,
}
