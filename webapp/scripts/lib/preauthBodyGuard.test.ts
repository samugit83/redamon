/**
 * D9 — the pre-authentication body guard (scripts/lib/preauthBodyGuard.cjs), on a real HTTP
 * server: a body over 1 MiB from a caller with no credential is refused from its headers,
 * before anything reads it; every credential the webapp accepts still sends large bodies.
 * Also pins the two things the guard depends on: Next.js creates its server through
 * http.createServer, and the image starts the server through scripts/serve.cjs.
 *
 * Run: npx vitest run --no-file-parallelism scripts/lib/preauthBodyGuard.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'vitest'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { SignJWT } from 'jose'

const require = createRequire(import.meta.url)
const guard = require('./preauthBodyGuard.cjs') as {
  UNAUTHENTICATED_MAX_BODY_BYTES: number
  verifyHs256: (t: unknown, s: string, now: number) => Record<string, unknown> | null
  credentialOf: (h: Record<string, unknown>, env: Record<string, string>, now: number) => string | null
  guardListener: (l: http.RequestListener, o?: object) => http.RequestListener
  installPreauthBodyGuard: (o?: object) => void
  guardedServerCount: () => number
}

const LIMIT = guard.UNAUTHENTICATED_MAX_BODY_BYTES
const MiB = 1024 * 1024
const AUTH_SECRET = 'a'.repeat(64)
const CALL_SECRET = 'p'.repeat(48)
const ENV = {
  AUTH_SECRET,
  INTERNAL_API_KEY: 'internal-key-'.padEnd(40, 'i'),
  SCANNER_API_KEY: 'scanner-key-'.padEnd(40, 's'),
  PLUGIN_CALL_TOKEN_SECRET: CALL_SECRET,
}
const WEBAPP = path.resolve(__dirname, '../..')
const now = () => Math.floor(Date.now() / 1000)

async function jwt(claims: Record<string, unknown>, secret: string, exp: number | string = '1h'): Promise<string> {
  return new SignJWT(claims).setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime(exp)
    .sign(new TextEncoder().encode(secret))
}
const sessionCookie = async (secret = AUTH_SECRET, exp: number | string = '1h') =>
  `theme=dark; redamon-auth=${await jwt({ sub: 'u1', role: 'user', sv: 0 }, secret, exp)}`
const callToken = (claims: Record<string, unknown> = { aud: 'redamon-plugin-gateway', sub: 'u1' }, secret = CALL_SECRET) =>
  jwt(claims, secret)

// ---------------------------------------------------------------- the server under test
// The inner listener stands in for Next.js: it reads the whole body (as Next's middleware
// clone does) and answers how many bytes it got.
let server: http.Server
let port = 0
let innerCalls = 0
let refusals: string[] = []

beforeAll(async () => {
  const inner: http.RequestListener = (req, res) => {
    innerCalls += 1
    let n = 0
    req.on('data', (c: Buffer) => { n += c.length })
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ received: n }))
    })
    req.on('error', () => {})
  }
  server = http.createServer(guard.guardListener(inner, { env: ENV, onRefuse: (r: string) => refusals.push(r) }))
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  port = (server.address() as AddressInfo).port
})
afterAll(() => new Promise<void>((r) => server.close(() => r())))
beforeEach(() => { innerCalls = 0; refusals = [] })

interface Reply { status?: number; body?: string; error?: string; received?: number }

/** Send a request; `size` bytes of body (or none), optionally chunked or left unfinished. */
function send(opts: { method?: string; headers?: Record<string, string>; size?: number; chunked?: boolean; hold?: boolean }): Promise<Reply> {
  const { method = 'POST', headers = {}, size, chunked = false, hold = false } = opts
  return new Promise((resolve) => {
    const h: Record<string, string | number> = { ...headers }
    if (size !== undefined && !chunked) h['content-length'] = size
    const req = http.request({ host: '127.0.0.1', port, method, path: '/api/anything', headers: h, agent: false }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (c) => { body += c })
      res.on('end', () => {
        if (hold) req.destroy()
        let received: number | undefined
        try { received = JSON.parse(body).received } catch { /* a refusal */ }
        resolve({ status: res.statusCode, body, received })
      })
    })
    req.on('error', (e) => resolve({ error: (e as NodeJS.ErrnoException).code || e.message }))
    if (size === undefined) { req.end(); return }
    const chunk = Buffer.alloc(64 * 1024, 0x61)
    let left = hold ? Math.min(size, chunk.length) : size
    const pump = () => {
      while (left > 0) {
        const n = Math.min(left, chunk.length)
        left -= n
        if (!req.write(chunk.subarray(0, n))) { req.once('drain', pump); return }
      }
      if (!hold) req.end()
    }
    pump()
  })
}

// ---------------------------------------------------------------- tokens and credentials
describe('verifyHs256', () => {
  test('accepts a token jose signed, refuses every alteration', async () => {
    const t = await jwt({ sub: 'u1', role: 'user' }, AUTH_SECRET)
    expect(guard.verifyHs256(t, AUTH_SECRET, now())?.sub).toBe('u1')
    expect(guard.verifyHs256(t, 'b'.repeat(64), now())).toBeNull()
    const [h, p, s] = t.split('.')
    const forged = Buffer.from(JSON.stringify({ sub: 'root', role: 'admin' })).toString('base64url')
    expect(guard.verifyHs256(`${h}.${forged}.${s}`, AUTH_SECRET, now())).toBeNull()
    expect(guard.verifyHs256(`${h}.${p}.${s.slice(0, -2)}AA`, AUTH_SECRET, now())).toBeNull()
  })

  test('refuses alg none, an expired token, a token not yet valid, junk and huge input', async () => {
    const none = `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from('{"sub":"u1","role":"user"}').toString('base64url')}.`
    expect(guard.verifyHs256(none, AUTH_SECRET, now())).toBeNull()
    const expired = await jwt({ sub: 'u1', role: 'user' }, AUTH_SECRET, now() - 10)
    expect(guard.verifyHs256(expired, AUTH_SECRET, now())).toBeNull()
    const future = await new SignJWT({ sub: 'u1' }).setProtectedHeader({ alg: 'HS256' }).setNotBefore(now() + 600)
      .sign(new TextEncoder().encode(AUTH_SECRET))
    expect(guard.verifyHs256(future, AUTH_SECRET, now())).toBeNull()
    for (const junk of [undefined, null, '', 'a.b', 'a.b.c.d', '....', 'x'.repeat(9000)]) {
      expect(guard.verifyHs256(junk, AUTH_SECRET, now())).toBeNull()
    }
  })
})

describe('credentialOf', () => {
  test('a valid login cookie, among other cookies', async () => {
    expect(guard.credentialOf({ cookie: await sessionCookie() }, ENV, now())).toBe('session')
  })

  test('a login cookie that is expired, signed elsewhere, or lacks sub/role is none', async () => {
    expect(guard.credentialOf({ cookie: await sessionCookie(AUTH_SECRET, now() - 5) }, ENV, now())).toBeNull()
    expect(guard.credentialOf({ cookie: await sessionCookie('z'.repeat(64)) }, ENV, now())).toBeNull()
    const noRole = `redamon-auth=${await jwt({ sub: 'u1' }, AUTH_SECRET)}`
    expect(guard.credentialOf({ cookie: noRole }, ENV, now())).toBeNull()
  })

  test('no login cookie counts while AUTH_SECRET is unset or the compose default', async () => {
    const cookie = `redamon-auth=${await jwt({ sub: 'u1', role: 'user' }, 'changeme')}`
    expect(guard.credentialOf({ cookie }, { ...ENV, AUTH_SECRET: 'changeme' }, now())).toBeNull()
    expect(guard.credentialOf({ cookie: await sessionCookie() }, { ...ENV, AUTH_SECRET: '' }, now())).toBeNull()
  })

  test('the internal and the scanner key; a wrong, empty or default key is none', () => {
    expect(guard.credentialOf({ 'x-internal-key': ENV.INTERNAL_API_KEY }, ENV, now())).toBe('internal-key')
    expect(guard.credentialOf({ 'x-internal-key': ENV.SCANNER_API_KEY }, ENV, now())).toBe('internal-key')
    expect(guard.credentialOf({ 'x-internal-key': ENV.INTERNAL_API_KEY + 'x' }, ENV, now())).toBeNull()
    expect(guard.credentialOf({ 'x-internal-key': '' }, ENV, now())).toBeNull()
    expect(guard.credentialOf({ 'x-internal-key': 'changeme' }, { ...ENV, INTERNAL_API_KEY: 'changeme' }, now())).toBeNull()
    expect(guard.credentialOf({ 'x-internal-key': 'anything' }, { ...ENV, INTERNAL_API_KEY: '', SCANNER_API_KEY: '' }, now())).toBeNull()
  })

  test('a plugin call token for the gateway audience; any other bearer is none', async () => {
    expect(guard.credentialOf({ authorization: `Bearer ${await callToken()}` }, ENV, now())).toBe('plugin-call-token')
    expect(guard.credentialOf({ authorization: `Bearer ${await callToken({ aud: ['x', 'redamon-plugin-gateway'] })}` }, ENV, now()))
      .toBe('plugin-call-token')
    expect(guard.credentialOf({ authorization: `Bearer ${await callToken({ sub: 'u1' })}` }, ENV, now())).toBeNull()
    // A login token in a bearer header, or a call token signed with AUTH_SECRET.
    expect(guard.credentialOf({ authorization: `Bearer ${await jwt({ sub: 'u1', role: 'user' }, AUTH_SECRET)}` }, ENV, now())).toBeNull()
    expect(guard.credentialOf({ authorization: `Bearer ${await callToken(undefined, AUTH_SECRET)}` }, ENV, now())).toBeNull()
    // A call-token secret too short to be configured accepts nothing.
    const short = 's'.repeat(20)
    expect(guard.credentialOf({ authorization: `Bearer ${await callToken(undefined, short)}` }, { ...ENV, PLUGIN_CALL_TOKEN_SECRET: short }, now()))
      .toBeNull()
  })

  test('no headers at all is none', () => {
    expect(guard.credentialOf({}, ENV, now())).toBeNull()
  })
})

// ---------------------------------------------------------------- on the wire
describe('requests without a credential', () => {
  test('GET and HEAD always pass', async () => {
    expect((await send({ method: 'GET' })).status).toBe(200)
    expect((await send({ method: 'HEAD' })).status).toBe(200)
  })

  test('a small body passes untouched, up to the limit itself', async () => {
    expect(await send({ size: 1000 })).toMatchObject({ status: 200, received: 1000 })
    expect(await send({ size: LIMIT })).toMatchObject({ status: 200, received: LIMIT })
    expect(await send({ method: 'PUT', size: 10 })).toMatchObject({ status: 200, received: 10 })
  })

  test('a POST with no body passes', async () => {
    expect(await send({})).toMatchObject({ status: 200 })
  })

  test('one byte over the limit is refused with 413, and never reaches Next.js', async () => {
    const r = await send({ size: LIMIT + 1 })
    expect(r.status).toBe(413)
    expect(JSON.parse(r.body!).code).toBe('body_too_large_unauthenticated')
    expect(innerCalls).toBe(0)
    expect(refusals).toEqual(['declared length'])
  })

  test('the D9 attack: a 60 MB body is refused from its headers, before the body is sent', async () => {
    // Only the first 64 KiB is ever written; the answer comes anyway.
    const r = await send({ size: 60 * MiB, hold: true })
    expect(r.status).toBe(413)
    expect(innerCalls).toBe(0)
  })

  test('fifty such requests at once: all refused, none reaches Next.js', async () => {
    const replies = await Promise.all(Array.from({ length: 50 }, () => send({ size: 60 * MiB, hold: true })))
    expect(replies.every((r) => r.status === 413)).toBe(true)
    expect(innerCalls).toBe(0)
  })

  test('every method that carries a body is guarded', async () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      expect((await send({ method, size: 2 * MiB, hold: true })).status).toBe(413)
    }
    expect(innerCalls).toBe(0)
  })

  test('a small chunked body passes whole', async () => {
    expect(await send({ size: 10_000, chunked: true })).toMatchObject({ status: 200, received: 10_000 })
  })

  test('a chunked body is cut off once it passes the limit', async () => {
    const r = await send({ size: 3 * MiB, chunked: true })
    expect(r.status).not.toBe(200)
    expect(refusals).toEqual(['streamed length'])
  })

  test('a forged or expired login cookie does not open the limit', async () => {
    expect((await send({ size: 2 * MiB, hold: true, headers: { cookie: await sessionCookie('z'.repeat(64)) } })).status).toBe(413)
    expect((await send({ size: 2 * MiB, hold: true, headers: { cookie: await sessionCookie(AUTH_SECRET, now() - 5) } })).status).toBe(413)
    expect((await send({ size: 2 * MiB, hold: true, headers: { 'x-internal-key': 'guess' } })).status).toBe(413)
    expect(innerCalls).toBe(0)
  })
})

describe('requests with a credential keep the large uploads working', () => {
  test('a signed-in browser sends 5 MB', async () => {
    expect(await send({ size: 5 * MiB, headers: { cookie: await sessionCookie() } })).toMatchObject({ status: 200, received: 5 * MiB })
  })

  test('a RedAmon service sends 5 MB with the internal or the scanner key', async () => {
    expect(await send({ size: 5 * MiB, headers: { 'x-internal-key': ENV.INTERNAL_API_KEY } })).toMatchObject({ status: 200, received: 5 * MiB })
    expect(await send({ size: 5 * MiB, headers: { 'x-internal-key': ENV.SCANNER_API_KEY } })).toMatchObject({ status: 200, received: 5 * MiB })
  })

  test('a plugin sends its 8 MB gateway maximum with its call token', async () => {
    const r = await send({ size: 8 * MiB, headers: { authorization: `Bearer ${await callToken()}` } })
    expect(r).toMatchObject({ status: 200, received: 8 * MiB })
  })

  test('a signed-in chunked upload passes whole', async () => {
    expect(await send({ size: 3 * MiB, chunked: true, headers: { cookie: await sessionCookie() } }))
      .toMatchObject({ status: 200, received: 3 * MiB })
    expect(refusals).toEqual([])
  })
})

// ---------------------------------------------------------------- installing it
describe('installPreauthBodyGuard', () => {
  test('wraps the listener of every server created through createServer, once', async () => {
    const created: unknown[][] = []
    const mod = { createServer: (...args: unknown[]) => { created.push(args); return args } }
    const before = guard.guardedServerCount()
    guard.installPreauthBodyGuard({ modules: [mod], env: ENV })
    guard.installPreauthBodyGuard({ modules: [mod], env: ENV })
    const listener = () => {}
    mod.createServer(listener)
    mod.createServer({ keepAlive: true }, listener)
    expect(created[0][0]).not.toBe(listener)
    expect(created[1][0]).toEqual({ keepAlive: true })
    expect(typeof created[1][1]).toBe('function')
    expect(created[1][1]).not.toBe(listener)
    expect(guard.guardedServerCount()).toBe(before + 2)
  })

  test('a real server created after install refuses an uncredentialed 2 MB body', async () => {
    const mod = { createServer: http.createServer.bind(http) }
    guard.installPreauthBodyGuard({ modules: [mod], env: ENV, onRefuse: () => {} })
    let reached = false
    const s = mod.createServer((_req: http.IncomingMessage, res: http.ServerResponse) => { reached = true; res.end('ok') }) as http.Server
    await new Promise<void>((r) => s.listen(0, '127.0.0.1', r))
    const p = (s.address() as AddressInfo).port
    const status = await new Promise<number | undefined>((resolve) => {
      const req = http.request({ host: '127.0.0.1', port: p, method: 'POST', headers: { 'content-length': 2 * MiB }, agent: false },
        (res) => { res.resume(); resolve(res.statusCode); req.destroy() })
      req.on('error', () => resolve(undefined))
      req.write(Buffer.alloc(1024))
    })
    await new Promise<void>((r) => s.close(() => r()))
    expect(status).toBe(413)
    expect(reached).toBe(false)
  })
})

// ---------------------------------------------------------------- what the guard relies on
describe('the guard is wired where Next.js creates its server', () => {
  test('Next.js start-server creates its server through http.createServer(requestListener)', () => {
    const src = readFileSync(path.join(WEBAPP, 'node_modules/next/dist/server/lib/start-server.js'), 'utf8')
    expect(src).toMatch(/_http\.default\.createServer\(requestListener\)/)
  })

  test('the standalone server.js is CommonJS and starts that start-server', () => {
    const pkg = JSON.parse(readFileSync(path.join(WEBAPP, 'package.json'), 'utf8'))
    expect(pkg.type).toBeUndefined()
    const utils = readFileSync(path.join(WEBAPP, 'node_modules/next/dist/build/utils.js'), 'utf8')
    expect(utils).toContain("require('next/dist/server/lib/start-server')")
  })

  test('the image starts the server through scripts/serve.cjs, which installs the guard first', () => {
    const dockerfile = readFileSync(path.join(WEBAPP, 'Dockerfile'), 'utf8')
    const entry = dockerfile.split('\n').find((l) => l.includes('> /app/entrypoint.sh'))!
    expect(entry).toContain('\\nexec node scripts/serve.cjs\\n')
    expect(entry).not.toContain('exec node server.js')
    const serve = readFileSync(path.join(WEBAPP, 'scripts/serve.cjs'), 'utf8')
    const install = serve.indexOf('installPreauthBodyGuard()')
    expect(install).toBeGreaterThan(0)
    expect(serve.indexOf("require('../server.js')")).toBeGreaterThan(install)
  })

  test('Next.js still buffers bodies above the guard limit, so the guard is what bounds them', () => {
    const config = readFileSync(path.join(WEBAPP, 'next.config.ts'), 'utf8')
    const m = /proxyClientMaxBodySize:\s*'(\d+)mb'/.exec(config)
    expect(m).not.toBeNull()
    expect(Number(m![1]) * MiB).toBeGreaterThan(LIMIT)
  })
})
