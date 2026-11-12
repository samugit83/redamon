/**
 * The self-service catalogs ask their permission (step 3.9; §5.3, PE-19, PE-22): an account's
 * attack and chat skills `self:attack_skills` / `self:chat_skills`, tradecraft `self:tradecraft`,
 * MCP servers (the account's list, the test call, the manifest) `self:mcp_servers`, LLM providers
 * (the list, a new one, a row, its test) and the model list `self:llm_providers`, the API usage
 * report `self:api_keys`, the onboarding pack, minting an MCP token and widening one
 * `self:mcp_tokens` (read fresh), mute-rule presets `self:presets`. Each is a capability with no
 * project. Listing one's MCP tokens, narrowing and revoking them never ask it: taking access away
 * is never refused.
 *
 * The `/api/users/[id]/**` routes ask it through requireSelfPermission after their account rule
 * (requireUserAccess, doubled here as admitting): only for the person's own data, so another
 * account reached through the directory read is not asked, an act-as asks both people, and the
 * internal key passes. Real guard, can() and registry; the session and Prisma are doubles
 * (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
  userAccess: vi.fn(),
}))
vi.mock('@/lib/session', async (orig) => {
  const id = async () => h.identity()
  return {
    ...(await orig<typeof import('@/lib/session')>()),
    getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
    getSession: async () => { const i = await id(); return i ? { userId: i.principal.id, role: i.principal.role } : null },
    getEffectiveUser: async () => { const i = await id(); return i ? { userId: (i.actingAs ?? i.principal).id } : null },
    requireSession: async () => {
      const i = await id()
      return i ? { userId: i.principal.id, role: i.principal.role } : new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 })
    },
    // The account rule is the route's own and unchanged: admitting here, so the self check decides.
    requireUserAccess: (...a: unknown[]) => h.userAccess(...a),
    requireAccountWrite: async () => null,
  }
})
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import { describeRoutePermissions, denying, principal, OWNER, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

type Mod = Record<string, unknown>
const own = { id: OWNER }
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string> = own, body?: unknown): RouteCase => ({
  route, permission, params, body, projectId: null, handler: async () => (await load())[route.split(' ')[0]] as never,
})

const attack = () => import('./attack-skills/route')
const attackOne = () => import('./attack-skills/[skillId]/route')
const chat = () => import('./chat-skills/route')
const chatOne = () => import('./chat-skills/[skillId]/route')
const trade = () => import('./tradecraft-resources/route')
const tradeOne = () => import('./tradecraft-resources/[resourceId]/route')
const mcp = () => import('./mcp/route')
const mcpOne = () => import('./mcp/[serverId]/route')
const llmOne = () => import('./llm-providers/[providerId]/route')
const llmList = () => import('./llm-providers/route')
const tokens = () => import('./mcp-tokens/route')
const tokenOne = () => import('./mcp-tokens/[tokenId]/route')
/** The token row a PATCH reads before it knows the edit widens the token. */
const TOKEN_ROW = { id: 't1', userId: OWNER, name: 'tok', scopes: ['recon:read'], profile: null, expiresAt: null, revokedAt: null, tokenPrefix: 'rdm_x', lastUsedAt: null, createdAt: new Date(0) }
const withToken = (h0: { models: Record<string, unknown> }) => { h0.models.mcpAccessToken = { findFirst: async () => ({ ...TOKEN_ROW }), findUnique: async () => ({ ...TOKEN_ROW }) } }
const usage = () => import('./settings/api-usage/route')
const presets = () => import('@/app/api/mute-rule-presets/route')
const presetOne = () => import('@/app/api/mute-rule-presets/[id]/route')

const MCP_DRAFT = { server: { id: 'srv1', name: 'srv', transport: 'http', url: 'http://mcp.invalid/mcp' } }

beforeEach(() => {
  h.userAccess.mockReset().mockResolvedValue(null)
})

describeRoutePermissions('self-service catalogs', [
  at('GET /api/users/[id]/attack-skills', attack, 'self:attack_skills'),
  at('POST /api/users/[id]/attack-skills', attack, 'self:attack_skills', own, { name: 'x', content: 'y' }),
  at('GET /api/users/[id]/attack-skills/[skillId]', attackOne, 'self:attack_skills', { ...own, skillId: 's1' }),
  at('PUT /api/users/[id]/attack-skills/[skillId]', attackOne, 'self:attack_skills', { ...own, skillId: 's1' }, { name: 'x' }),
  at('DELETE /api/users/[id]/attack-skills/[skillId]', attackOne, 'self:attack_skills', { ...own, skillId: 's1' }),
  at('POST /api/users/[id]/attack-skills/[skillId]/release', () => import('./attack-skills/[skillId]/release/route'), 'self:attack_skills', { ...own, skillId: 's1' }, {}),
  at('GET /api/users/[id]/attack-skills/available', () => import('./attack-skills/available/route'), 'self:attack_skills'),
  at('POST /api/users/[id]/attack-skills/batch', () => import('./attack-skills/batch/route'), 'self:attack_skills', own, { items: [] }),
  at('POST /api/users/[id]/attack-skills/generate-metadata', () => import('./attack-skills/generate-metadata/route'), 'self:attack_skills', own, { items: [] }),
  at('POST /api/users/[id]/attack-skills/import-community', () => import('./attack-skills/import-community/route'), 'self:attack_skills', own, { skillIds: [] }),
  at('GET /api/users/[id]/attack-skills/name-check', () => import('./attack-skills/name-check/route'), 'self:attack_skills'),
  at('POST /api/users/[id]/attack-skills/name-check', () => import('./attack-skills/name-check/route'), 'self:attack_skills', own, { names: [] }),
  at('GET /api/users/[id]/chat-skills', chat, 'self:chat_skills'),
  at('POST /api/users/[id]/chat-skills', chat, 'self:chat_skills', own, { name: 'x' }),
  at('GET /api/users/[id]/chat-skills/[skillId]', chatOne, 'self:chat_skills', { ...own, skillId: 'c1' }),
  at('PUT /api/users/[id]/chat-skills/[skillId]', chatOne, 'self:chat_skills', { ...own, skillId: 'c1' }, { name: 'x' }),
  at('DELETE /api/users/[id]/chat-skills/[skillId]', chatOne, 'self:chat_skills', { ...own, skillId: 'c1' }),
  at('POST /api/users/[id]/chat-skills/import-community', () => import('./chat-skills/import-community/route'), 'self:chat_skills', own, { skillIds: [] }),
  at('GET /api/users/[id]/tradecraft-resources', trade, 'self:tradecraft'),
  at('POST /api/users/[id]/tradecraft-resources', trade, 'self:tradecraft', own, { url: 'https://x.invalid' }),
  at('GET /api/users/[id]/tradecraft-resources/[resourceId]', tradeOne, 'self:tradecraft', { ...own, resourceId: 'r1' }),
  at('PUT /api/users/[id]/tradecraft-resources/[resourceId]', tradeOne, 'self:tradecraft', { ...own, resourceId: 'r1' }, { name: 'x' }),
  at('DELETE /api/users/[id]/tradecraft-resources/[resourceId]', tradeOne, 'self:tradecraft', { ...own, resourceId: 'r1' }),
  at('POST /api/users/[id]/tradecraft-resources/[resourceId]/refresh', () => import('./tradecraft-resources/[resourceId]/refresh/route'), 'self:tradecraft', { ...own, resourceId: 'r1' }, {}),
  at('POST /api/users/[id]/tradecraft-resources/[resourceId]/verify', () => import('./tradecraft-resources/[resourceId]/verify/route'), 'self:tradecraft', { ...own, resourceId: 'r1' }, {}),
  at('GET /api/users/[id]/mcp', mcp, 'self:mcp_servers'),
  at('POST /api/users/[id]/mcp', mcp, 'self:mcp_servers', own, MCP_DRAFT.server),
  at('PUT /api/users/[id]/mcp/[serverId]', mcpOne, 'self:mcp_servers', { ...own, serverId: 'srv1' }, MCP_DRAFT.server),
  at('DELETE /api/users/[id]/mcp/[serverId]', mcpOne, 'self:mcp_servers', { ...own, serverId: 'srv1' }),
  at('POST /api/mcp/test', () => import('@/app/api/mcp/test/route'), 'self:mcp_servers', {}, MCP_DRAFT),
  at('GET /api/mcp/manifest', () => import('@/app/api/mcp/manifest/route'), 'self:mcp_servers', {}),
  at('GET /api/users/[id]/llm-providers', llmList, 'self:llm_providers'),
  at('POST /api/users/[id]/llm-providers', llmList, 'self:llm_providers', own, { providerType: 'openai', name: 'x' }),
  { ...at('POST /api/users/[id]/mcp-tokens', tokens, 'self:mcp_tokens', own, { name: 'x', scopes: ['recon:read'] }), fresh: true },
  { ...at('PATCH /api/users/[id]/mcp-tokens/[tokenId]', tokenOne, 'self:mcp_tokens', { ...own, tokenId: 't1' }, { scopes: ['recon:read', 'recon:scan'] }), fresh: true, arrange: withToken },
  at('GET /api/users/[id]/llm-providers/[providerId]', llmOne, 'self:llm_providers', { ...own, providerId: 'p1' }),
  at('PUT /api/users/[id]/llm-providers/[providerId]', llmOne, 'self:llm_providers', { ...own, providerId: 'p1' }, { name: 'x' }),
  at('DELETE /api/users/[id]/llm-providers/[providerId]', llmOne, 'self:llm_providers', { ...own, providerId: 'p1' }),
  at('POST /api/users/[id]/llm-providers/[providerId]/test', () => import('./llm-providers/[providerId]/test/route'), 'self:llm_providers', { ...own, providerId: 'p1' }, {}),
  at('POST /api/models', () => import('@/app/api/models/route'), 'self:llm_providers', {}, { userId: OWNER }),
  at('GET /api/users/[id]/settings/api-usage', usage, 'self:api_keys'),
  at('POST /api/users/[id]/settings/api-usage', usage, 'self:api_keys', own, {}),
  at('POST /api/users/[id]/agent-onboarding', () => import('./agent-onboarding/route'), 'self:mcp_tokens', own, { scopes: ['recon:read'] }),
  at('GET /api/mute-rule-presets', presets, 'self:presets', {}),
  at('POST /api/mute-rule-presets', presets, 'self:presets', {}, { name: 'x', mode: 'blocklist', rules: [] }),
  at('GET /api/mute-rule-presets/[id]', presetOne, 'self:presets', { id: 'mp1' }),
  at('PATCH /api/mute-rule-presets/[id]', presetOne, 'self:presets', { id: 'mp1' }, { name: 'x' }),
  at('DELETE /api/mute-rule-presets/[id]', presetOne, 'self:presets', { id: 'mp1' }),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})

describe('self-service: whose data the permission is asked for (step 3.9)', () => {
  const KEY = 'internal-key-for-tests'
  const ADMIN = 'adm'
  const req = (method: string, path: string, headers: Record<string, string> = {}, body?: unknown) =>
    new NextRequest(`http://localhost:3000${path}`, {
      method,
      headers: body === undefined ? headers : { ...headers, 'content-type': 'application/json', origin: 'http://localhost:3000' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  const params = (p: Record<string, string>) => ({ params: Promise.resolve(p) }) as never
  const signedIn = (who: ReturnType<typeof principal>, actingAs: ReturnType<typeof principal> | null = null) =>
    h.identity.mockResolvedValue({ session: { userId: who.id, role: who.role }, principal: who, actingAs })
  const guardCalls = async () => vi.mocked((await import('@/lib/authz/guards')).requirePermission).mock.calls

  beforeEach(async () => {
    h.identity.mockReset()
    h.downstream.mockReset()
    vi.mocked((await import('@/lib/authz/guards')).requirePermission).mockClear()
    setFlagsForTests({ identity: true, permissions: true })
    vi.stubEnv('INTERNAL_API_KEY', KEY)
    clearCapabilityCachesForTests()
    clearInstanceRootCacheForTests()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
  })
  afterEach(() => {
    setFlagsForTests(null)
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  test("another account's catalog the directory read admitted is not asked the self permission", async () => {
    signedIn(principal(ADMIN, { role: 'admin', permissionOverrides: [{ permission: 'self:attack_skills', effect: 'deny', expiresAt: null, reason: null }] }))
    const res = await (await attack()).GET(req('GET', `/api/users/${OWNER}/attack-skills`), params({ id: OWNER }))
    expect(res.status).not.toBe(403)
    expect(await guardCalls()).toEqual([])
    // Past the check: the route reads the account's skills (refused by the Prisma double here).
    expect(h.downstream).toHaveBeenCalled()
  })

  test('acting as a passwordless account asks both people: the account acted as lacks it', async () => {
    signedIn(principal(ADMIN, { role: 'admin' }), denying(OWNER, 'self:attack_skills'))
    const res = await (await attack()).POST(req('POST', `/api/users/${OWNER}/attack-skills`, {}, { name: 'x' }), params({ id: OWNER }))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'self:attack_skills' })
    expect(h.downstream).not.toHaveBeenCalled()
  })

  test('acting as a passwordless account asks both people: the admin lacks it', async () => {
    signedIn(principal(ADMIN, { role: 'admin', permissionOverrides: [{ permission: 'self:chat_skills', effect: 'deny', expiresAt: null, reason: null }] }), principal(OWNER))
    const res = await (await chat()).POST(req('POST', `/api/users/${OWNER}/chat-skills`, {}, { name: 'x' }), params({ id: OWNER }))
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ permission: 'self:chat_skills' })
  })

  test('the internal key passes untouched: no session read, no permission asked', async () => {
    const res = await (await trade()).GET(req('GET', `/api/users/${OWNER}/tradecraft-resources`, { 'x-internal-key': KEY }), params({ id: OWNER }))
    expect(res.status).not.toBe(403)
    expect(h.identity).not.toHaveBeenCalled()
    expect(await guardCalls()).toEqual([])
  })

  test('listing, narrowing and revoking one\'s own MCP tokens never ask self:mcp_tokens: taking access away is never refused', async () => {
    signedIn(denying(OWNER, 'self:mcp_tokens'))
    withToken(h)
    const list = await (await tokens()).GET(req('GET', `/api/users/${OWNER}/mcp-tokens`), params({ id: OWNER }))
    const narrow = await (await tokenOne()).PATCH(req('PATCH', `/api/users/${OWNER}/mcp-tokens/t1`, {}, { scopes: [] }), params({ id: OWNER, tokenId: 't1' }))
    const revoke = await (await tokenOne()).DELETE(req('DELETE', `/api/users/${OWNER}/mcp-tokens/t1`), params({ id: OWNER, tokenId: 't1' }))
    for (const res of [list, narrow, revoke]) {
      expect(res.status).not.toBe(403)
      expect(JSON.stringify(await res.json())).not.toContain('self:mcp_tokens')
    }
    expect(await guardCalls()).toEqual([])
    delete h.models.mcpAccessToken
  })

  test('the account rule still answers first: its refusal is returned and no permission is asked', async () => {
    signedIn(denying(OWNER, 'self:mcp_servers'))
    h.userAccess.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403 }))
    const res = await (await mcp()).GET(req('GET', '/api/users/someone-else/mcp'), params({ id: 'someone-else' }))
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'Forbidden' })
    expect(await guardCalls()).toEqual([])
  })
})
