/**
 * The agent's provider list carries the instance providers (step 6.11, GV-15): GET
 * /api/users/[id]/llm-providers?internal=true with the master key is the one place every agent path
 * reads its keys (the agent session, the recon planners behind /llm/*, text-to-cypher, Models by
 * feature, CypherFix), so the account's entitled instance providers are added there as marked rows.
 * Nobody else ever receives them: a browser (the account itself, an admin) gets its own rows masked
 * and no instance row, and a scan container's key is refused before anything is read.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/users/[id]/llm-providers/route.instance.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const INSTANCE_KEY = 'sk-INSTANCE-CANARY-never-to-a-browser'
const OWN_KEY = 'sk-OWN-SECRET-123456'
const h = vi.hoisted(() => ({
  internal: false,
  session: null as { userId: string; role: string } | null,
}))
const findMany = vi.fn()
const agentProviderList = vi.fn(async (ownerId: string, own: unknown[]) => [
  ...own,
  { id: 'inst-1', providerType: 'instance', instanceProviderType: 'openai', apiKey: INSTANCE_KEY, userId: ownerId },
])

vi.mock('@/lib/prisma', () => ({ default: { userLlmProvider: { findMany: (...a: unknown[]) => findMany(...a) } } }))
vi.mock('@/lib/instanceProviders/entitlement', () => ({ agentProviderList: (...a: [string, unknown[]]) => agentProviderList(...a) }))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/authz/adminPermission', () => ({ sessionHolds: async (s: { role: string }) => s.role === 'admin' }))
vi.mock('@/lib/session', () => ({
  getSession: async () => h.session,
  isInternalRequest: () => h.internal,
  isScannerRequest: () => false,
  actsAsAccount: async () => false,
  requireAccountWrite: async () => null,
}))

import { GET } from './route'

const OWN = { id: 'own-1', userId: 'owner', providerType: 'openai', name: 'Mine', apiKey: OWN_KEY, awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', defaultHeaders: {} }
const params = { params: Promise.resolve({ id: 'owner' }) }
const get = (query = '?internal=true') => GET(new NextRequest(`http://x/api/users/owner/llm-providers${query}`), params)

beforeEach(() => {
  h.internal = false
  h.session = null
  findMany.mockReset().mockResolvedValue([OWN])
  agentProviderList.mockClear()
})

describe('the agent list (master key, ?internal=true)', () => {
  test('carries the own rows and the instance rows of the account, with their keys', async () => {
    h.internal = true
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.map((r: { id: string }) => r.id)).toEqual(['own-1', 'inst-1'])
    expect(JSON.stringify(body)).toContain(INSTANCE_KEY)
    expect(agentProviderList).toHaveBeenCalledWith('owner', [OWN])
  })

  test('the internal key without ?internal=true: own rows masked, no instance row', async () => {
    h.internal = true
    const text = await (await get('')).text()
    expect(text).not.toContain(INSTANCE_KEY)
    expect(text).not.toContain(OWN_KEY)
    expect(agentProviderList).not.toHaveBeenCalled()
  })
})

describe('provider key never returned unmasked, nor an instance row, to anyone else', () => {
  test.each([
    ['the account itself', { userId: 'owner', role: 'standard' }],
    ['an admin reading the account', { userId: 'admin-1', role: 'admin' }],
  ])('%s with ?internal=true: own rows masked, no instance row', async (_name, session) => {
    h.session = session
    const res = await get()
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain(INSTANCE_KEY)
    expect(text).not.toContain('inst-1')
    expect(text).not.toContain(OWN_KEY)
    expect(agentProviderList).not.toHaveBeenCalled()
  })

  test('scan container never receives the key: its key is no session and no master key, so 401 before any read', async () => {
    const res = await get()
    expect(res.status).toBe(401)
    expect(findMany).not.toHaveBeenCalled()
    expect(agentProviderList).not.toHaveBeenCalled()
  })

  test('another member asking for the account: 403, nothing read', async () => {
    h.session = { userId: 'mallory', role: 'standard' }
    const res = await get()
    expect(res.status).toBe(403)
    expect(agentProviderList).not.toHaveBeenCalled()
  })
})
