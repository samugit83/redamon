/**
 * MCP token scopes ∩ the owner's permissions (step 3.10; PE-20, feature document §5.13, §9.3).
 *
 * With RBAC_PERMISSIONS_ENABLED on:
 *   - at mint, and when an edit ADDS a scope, a scope is grantable only while its owner holds every
 *     permission it maps to (§5.13); the refusal is a 403 naming the scope and the permission, before
 *     the password is checked, and nothing is written;
 *   - on every call the usable scopes are minted ∩ allowed(the owner's current capabilities),
 *     computed once in resolveMcpToken: a call needing a scope the owner lost answers the existing
 *     scope error, the connect-time instructions describe only what is usable, and the scope comes
 *     back with the permission;
 *   - the token list tells the screen which scopes the owner cannot grant, and why.
 * With it off the minted scopes are the usable ones and nothing more is read (DV-30).
 *
 * Real routes (the token routes and the inbound MCP route), session helpers, step-up and capability
 * resolution; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', '7'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  let minted = 0
  Object.assign(db.mcpAccessToken, {
    create: async ({ data, select }: { data: Record<string, unknown>; select?: Record<string, boolean> }) => {
      const row: Record<string, unknown> = { id: `tok-${++minted}`, lastUsedAt: null, revokedAt: null, createdAt: new Date(), ...data }
      db.seedToken({ ...row, id: String(row.id), userId: String(row.userId) })
      return select ? Object.fromEntries(Object.keys(select).map((k) => [k, row[k]])) : row
    },
  })
  // No project exists: a call that passes its scope check stops at "Project not found".
  Object.assign(db.project, { findUnique: async () => null })
  h.db = db
  return { default: db, prisma: db }
})

import bcrypt from 'bcryptjs'
import type { AccountDb } from './authz/__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from './authz/flags'
import { setNowForTests } from './authz/clock'
import { clearPrincipalCacheForTests, invalidatePrincipal } from './authz/principal'
import { clearInstanceRootCacheForTests } from './authz/root'
import { clearCapabilityCachesForTests } from './authz/capabilities'
import { builtinSet } from './authz/builtinSets'
import { PERMISSIONS, PERMISSION_IDS } from './authz/permissions'
import {
  DEFAULT_MCP_SCOPES, MCP_SCOPES, __resetRateLimiter, __resetTokenUsageThrottle, hashToken, resolveMcpToken,
  type McpScope,
} from './mcpAuth'
import { GET as listTokens, POST as mintToken } from '@/app/api/users/[id]/mcp-tokens/route'
import { PATCH as editToken } from '@/app/api/users/[id]/mcp-tokens/[tokenId]/route'
import { POST as mcpServer, __resetAuthAuditThrottle } from '@/app/api/mcp-server/route'
import { __resetAdvertisedToolsCache } from './mcp/instructions'

const db = () => h.db as AccountDb
const PW = 'member-one-passphrase'
const HASH = bcrypt.hashSync(PW, 4)
const AUTOMATION = 'builtin:automation'
const T0 = Date.parse('2026-11-12T10:00:00Z')
let t = T0

/** The permissions a scope maps to (§5.13), read from the registry. */
const mapped = (scope: McpScope) => PERMISSION_IDS.filter((p) => PERMISSIONS[p].mcpScopes.includes(scope))

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x/mcp-tokens', {
    method,
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const tokenParams = (id: string, tokenId: string) => ({ params: Promise.resolve({ id, tokenId }) })

async function signIn(userId: string) {
  h.jar.auth = await createToken(userId, String(db().account(userId)!.role), 0)
}

const mint = (scopes: string[], password = PW) =>
  mintToken(req('POST', { name: 'agent', scopes, expiresInDays: 90, password }), params('member-1'))

let seq = 0
/** A token row as minting leaves it; returns the bearer that presents it. */
function seedToken(userId: string, scopes: McpScope[]): string {
  const plaintext = `rdmn_mcp_${String(++seq).padStart(48, '0')}`
  db().seedToken({
    id: `seed-${seq}`, userId, name: 'agent', tokenPrefix: plaintext.slice(0, 17), tokenHash: hashToken(plaintext),
    scopes, profile: null, expiresAt: null, lastUsedAt: null, createdAt: new Date(T0),
  })
  return plaintext
}

async function rpc(bearer: string, method: string, params: Record<string, unknown> = {}) {
  const res = await mcpServer(new NextRequest('http://redamon.test/api/mcp-server', {
    method: 'POST',
    headers: {
      'content-type': 'application/json', accept: 'application/json, text/event-stream',
      authorization: `Bearer ${bearer}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  }))
  return { status: res.status, body: await res.json() }
}

/** The text a `tools/call` answers. */
async function callTool(bearer: string, name: string, args: Record<string, unknown>): Promise<string> {
  const { body } = await rpc(bearer, 'tools/call', { name, arguments: args })
  return body.result.content[0].text as string
}

const SCOPE_ERROR = (scope: string) => `This token is missing the required scope: ${scope}`

beforeEach(() => {
  seq = 0
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin', password: HASH },
    { id: 'admin-1', role: 'admin', password: HASH },
    { id: 'member-1', name: 'Marco', password: HASH },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date(T0 - 86_400_000) })
  t = T0
  setNowForTests(() => new Date(t))
  setFlagsForTests({ identity: true, permissions: true })
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  __resetRateLimiter()
  __resetTokenUsageThrottle()
  __resetAuthAuditThrottle()
  __resetAdvertisedToolsCache()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllEnvs()
  vi.stubEnv('AUTH_SECRET', '7'.repeat(64))
  vi.restoreAllMocks()
})

describe('the scope map (§5.13)', () => {
  test('every scope maps to at least one permission, and Automation lacks the sandbox', () => {
    for (const scope of MCP_SCOPES) expect(mapped(scope), scope).not.toEqual([])
    expect(mapped('kali:exec')).toEqual(['agent:kali_exec'])
    expect(mapped('recon:read')).toEqual(['recon:read', 'graph:read'])
    expect(builtinSet(AUTOMATION)!.permissions).not.toContain('agent:kali_exec')
    expect(builtinSet(AUTOMATION)!.permissions).toContain('self:mcp_tokens')
  })
})

describe('mint: a scope is grantable only while the owner holds its permissions', () => {
  test('mint refuses a scope without the permission', async () => {
    db().seedAssignment('member-1', AUTOMATION)
    await signIn('member-1')
    // A wrong password: the refusal comes first, so a scope the person cannot hold costs no attempt.
    const res = await mint([...DEFAULT_MCP_SCOPES], 'not-the-password')
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: expect.stringMatching(/kali:exec.*agent:kali_exec/),
      code: 'forbidden',
      permission: 'agent:kali_exec',
      scope: 'kali:exec',
    })
    expect(db().tokens()).toEqual([])
  })

  test('a deny override takes the scope away from a Default member', async () => {
    db().seedOverride({ userId: 'member-1', permission: 'graph:read', effect: 'deny' })
    await signIn('member-1')
    // recon:read needs graph:read too: half a scope is never granted.
    const res = await mint(['recon:read'])
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'graph:read', scope: 'recon:read' })
    expect(db().tokens()).toEqual([])
  })

  test('Default member mints every scope as today', async () => {
    await signIn('member-1')
    const res = await mint([...MCP_SCOPES])
    expect(res.status).toBe(201)
    expect(db().tokens()).toHaveLength(1)
    expect(db().tokens()[0].scopes).toEqual([...MCP_SCOPES])
  })

  test('an admin (Full admin + Default member) and the Root mint every scope', async () => {
    for (const id of ['admin-1', 'root-1']) {
      await signIn(id)
      const res = await mintToken(req('POST', { name: 'agent', scopes: [...MCP_SCOPES], expiresInDays: 90, password: PW }), params(id))
      expect([id, res.status]).toEqual([id, 201])
    }
  })

  test('a deployment switch off is a permission off: agent:loop with Agent in the Loop off', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    await signIn('member-1')
    const res = await mint(['recon:read', 'agent:loop'])
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ permission: 'agent:loop', scope: 'agent:loop' })
  })

  test('switch off: the sets do not count, every scope mints as today', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    db().seedAssignment('member-1', AUTOMATION)
    db().seedOverride({ userId: 'member-1', permission: 'graph:read', effect: 'deny' })
    await signIn('member-1')
    expect((await mint([...MCP_SCOPES])).status).toBe(201)
  })
})

describe('edit: adding a scope asks the same; taking one away never does', () => {
  test('adding a scope the owner cannot hold is refused; one they hold is granted', async () => {
    db().seedAssignment('member-1', AUTOMATION)
    seedToken('member-1', ['recon:read'])
    await signIn('member-1')
    let res = await editToken(req('PATCH', { scopes: ['recon:read', 'kali:exec'], password: PW }), tokenParams('member-1', 'seed-1'))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'agent:kali_exec', scope: 'kali:exec' })
    expect(db().tokens()[0].scopes).toEqual(['recon:read'])

    res = await editToken(req('PATCH', { scopes: ['recon:read', 'recon:scan'], password: PW }), tokenParams('member-1', 'seed-1'))
    expect(res.status).toBe(200)
    expect(db().tokens()[0].scopes).toEqual(['recon:read', 'recon:scan'])
  })

  test('a scope the owner lost can be dropped without a password, and a kept one does not block an extension', async () => {
    // Minted while a Default member, then moved to Automation.
    seedToken('member-1', ['recon:read', 'kali:exec'])
    db().seedAssignment('member-1', AUTOMATION)
    await signIn('member-1')
    let res = await editToken(req('PATCH', { expiry: 30, password: PW }), tokenParams('member-1', 'seed-1'))
    expect(res.status).toBe(200)
    res = await editToken(req('PATCH', { scopes: ['recon:read'] }), tokenParams('member-1', 'seed-1'))
    expect(res.status).toBe(200)
    expect(db().tokens()[0].scopes).toEqual(['recon:read'])
  })
})

describe('the token list names what the owner cannot grant', () => {
  test('each ungrantable scope with the permissions it lacks; switch off: no field', async () => {
    db().seedAssignment('member-1', AUTOMATION)
    await signIn('member-1')
    let body = await (await listTokens(req('GET'), params('member-1'))).json()
    expect(body.ungrantableScopes['kali:exec']).toEqual(['agent:kali_exec'])
    expect(body.ungrantableScopes).not.toHaveProperty('recon:read')
    const held = new Set(builtinSet(AUTOMATION)!.permissions)
    for (const scope of MCP_SCOPES) {
      const missing = mapped(scope).filter((p) => !held.has(p))
      if (missing.length === 0) expect(body.ungrantableScopes, scope).not.toHaveProperty(scope)
      else expect(body.ungrantableScopes[scope], scope).toEqual(missing)
    }

    setFlagsForTests({ identity: true, permissions: false })
    clearPrincipalCacheForTests()
    body = await (await listTokens(req('GET'), params('member-1'))).json()
    expect(body).not.toHaveProperty('ungrantableScopes')
  })
})

describe('every call: minted ∩ the owner\'s current permissions, computed in resolveMcpToken', () => {
  test('a token loses a scope when its owner loses the permission, at the next call', async () => {
    const bearer = seedToken('member-1', ['recon:read', 'recon:scan'])
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read', 'recon:scan'])
    expect(await callTool(bearer, 'stop_recon', { projectId: 'P-1' })).toBe('Project not found')

    // A deny on one of the two permissions recon:scan maps to; the writer drops the cached account.
    db().seedOverride({ userId: 'member-1', permission: 'recon:partial', effect: 'deny' })
    invalidatePrincipal('member-1')
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read'])
    expect(await callTool(bearer, 'stop_recon', { projectId: 'P-1' })).toBe(SCOPE_ERROR('recon:scan'))
    expect(db().audit().filter((a) => a.action === 'mcp.stop_recon').map((a) => (a.after as { outcome: string }).outcome))
      .toEqual(['access_denied', 'scope_denied'])
    // The minted row is untouched: the cap is applied per call, never written.
    expect(db().tokens()[0].scopes).toEqual(['recon:read', 'recon:scan'])
  })

  test('another process sees the change within the authorization cache bound, and the scope comes back with the permission', async () => {
    const bearer = seedToken('member-1', ['recon:read', 'recon:scan'])
    db().seedOverride({ userId: 'member-1', permission: 'recon:scan', effect: 'deny' })
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read'])
    // The deny goes, written by another copy (no invalidation here): held within the bound, back after it.
    await db().userPermissionOverride.deleteMany({ where: { userId: 'member-1', permission: 'recon:scan' } })
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read'])
    t += 5_001
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read', 'recon:scan'])
  })

  test('a set change, an instance cap and a disabled owner cap the token too', async () => {
    const bearer = seedToken('member-1', ['recon:read', 'kali:exec', 'agent:loop'])
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read', 'kali:exec', 'agent:loop'])
    db().seedAssignment('member-1', AUTOMATION)
    invalidatePrincipal('member-1')
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read', 'agent:loop'])
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read'])
    await db().user.update({ where: { id: 'member-1' }, data: { status: 'disabled' } })
    invalidatePrincipal('member-1')
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual([])
  })

  test('the connect-time instructions describe the usable scopes, never the minted ones', async () => {
    const bearer = seedToken('member-1', ['recon:read', 'recon:scan'])
    db().seedOverride({ userId: 'member-1', permission: 'recon:scan', effect: 'deny' })
    const { status, body } = await rpc(bearer, 'initialize', {
      protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '1' },
    })
    expect(status).toBe(200)
    expect(body.result.instructions).toContain('This token holds: recon:read.')
    expect(body.result.instructions).not.toMatch(/holds: [^.]*recon:scan/)
  })

  test('the owner\'s permissions cannot be read: a coded 500 and an [rbac] line, never the minted scopes', async () => {
    const bearer = seedToken('member-1', ['recon:read'])
    vi.spyOn(db().user, 'findUnique').mockRejectedValue(new Error('db down'))
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    const { status, body } = await rpc(bearer, 'tools/list')
    expect(status).toBe(500)
    expect(body.error).toEqual({ code: -32603, message: 'Internal error' })
    expect(errors.mock.calls.some((c) => String(c[0]).startsWith('[rbac] mcp_scope_cap_failed'))).toBe(true)
  })

  test('switch off: the minted scopes exactly, and no account is read', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    const bearer = seedToken('member-1', ['recon:read', 'recon:scan', 'kali:exec'])
    db().seedAssignment('member-1', AUTOMATION)
    db().seedOverride({ userId: 'member-1', permission: 'recon:scan', effect: 'deny' })
    const users = vi.spyOn(db().user, 'findUnique')
    expect((await resolveMcpToken(bearer)).token!.scopes).toEqual(['recon:read', 'recon:scan', 'kali:exec'])
    expect(users).not.toHaveBeenCalled()
  })
})
