/**
 * The account acted as, and another account's projects (review of step 3.7, finding 4), with
 * RBAC_PERMISSIONS_ENABLED on:
 *
 * - When the path names the account an admin is acting as, its data is that account's own (§4.7:
 *   what both people may do), not another account's administration: reading it (the account, its
 *   LLM providers, the requireUserAccess read rule) needs no users:read, and saving its remembered
 *   default models needs no users:edit. Its name, email and role stay the real person's to change
 *   (users:edit), and every other account still needs users:read.
 * - Reading another account through the user directory (users:read) gives its projects' names and
 *   dates; their scope (target domain, target label) only with projects:oversee (§5.1: users:read
 *   is "project counts", projects:oversee reads projects).
 *
 * With the switch off every answer is as before. Real routes, session helpers, act-as cookie and
 * capability resolution; the database is the in-memory accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string; actAs?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  const db = createAccountDb()
  h.db = db
  // The LLM providers list: none stored, so the read rule is all that decides.
  Object.assign(db, { userLlmProvider: { findMany: async () => [] } })
  return { default: db, prisma: db }
})

import type { AccountDb, AccountSeed } from '@/lib/authz/__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { GET as readUser, PUT as editUser } from './route'
import { GET as listLlmProviders } from './llm-providers/route'
import { GET as listMcpTokens } from './mcp-tokens/route'

const db = () => h.db as AccountDb

const PROJECT = {
  id: 'proj-1', name: 'Lab one', targetDomain: 'one.e2e.test', ipMode: false, targetIps: [], subdomainList: [],
  domainBatchMode: false, domainBatchHosts: [], createdAt: new Date('2026-11-01T00:00:00Z'), updatedAt: new Date('2026-11-02T00:00:00Z'),
}

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x', {
    method,
    headers: { host: 'redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

async function as(userId: string, actingAs?: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
  h.jar.actAs = actingAs ? await createActAsToken(userId, actingAs) : undefined
}

async function answer(res: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  return { status: res.status, body: await res.json().catch(() => ({})) as Record<string, unknown> }
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-imp', role: 'admin', adminProfileId: 'prof-imp' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'admin-audit', role: 'admin', adminProfileId: 'builtin:security-auditor' },
    { id: 'member-1', projects: [PROJECT] } as AccountSeed,
    { id: 'member-2', projects: [] } as AccountSeed,
  ])
  db().seedSet({ id: 'prof-imp', kind: 'admin', name: 'Support', permissions: ['users:impersonate'] })
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
})

describe('acting as an account: the path naming it is that account\'s own data', () => {
  test('an admin holding users:impersonate but not users:read reads the account it acts as, its projects whole', async () => {
    await as('admin-imp', 'member-1')
    const { status, body } = await answer(await readUser(req('GET'), params('member-1')))
    expect(status).toBe(200)
    expect(body.projects).toEqual([expect.objectContaining({ id: 'proj-1', targetDomain: 'one.e2e.test', targetLabel: expect.any(String) })])
  })

  test('its LLM providers and the read rule (requireUserAccess read) answer it too', async () => {
    await as('admin-imp', 'member-1')
    expect((await listLlmProviders(req('GET'), params('member-1'))).status).toBe(200)
    expect((await listMcpTokens(req('GET'), params('member-1'))).status).toBe(200)
  })

  test('every other account still needs users:read', async () => {
    await as('admin-imp', 'member-1')
    for (const res of [
      await readUser(req('GET'), params('member-2')),
      await listLlmProviders(req('GET'), params('member-2')),
      await listMcpTokens(req('GET'), params('member-2')),
    ]) {
      expect(res.status).toBe(403)
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:read' })
    }
  })

  test('without the act-as cookie the same admin reads nothing of the account', async () => {
    await as('admin-imp')
    expect((await readUser(req('GET'), params('member-1'))).status).toBe(403)
    expect((await listMcpTokens(req('GET'), params('member-1'))).status).toBe(403)
  })

  test('saving the remembered default models of the account acted as needs no users:edit', async () => {
    await as('admin-imp', 'member-1')
    const res = await editUser(req('PUT', { defaultAgentModel: 'openai/gpt-x', defaultAiPipelineModel: 'openai/gpt-y' }), params('member-1'))
    expect(res.status).toBe(200)
    expect(db().account('member-1')).toMatchObject({ defaultAgentModel: 'openai/gpt-x', defaultAiPipelineModel: 'openai/gpt-y' })
  })

  test('its name, email and role stay the real person\'s: users:edit', async () => {
    await as('admin-imp', 'member-1')
    for (const body of [{ name: 'Renamed' }, { email: 'new@e2e.local' }, { role: 'admin' }, { defaultAgentModel: 'openai/gpt-x', name: 'Renamed' }]) {
      const res = await editUser(req('PUT', body), params('member-1'))
      expect(res.status).toBe(403)
      expect(await res.json()).toMatchObject({ code: 'forbidden', permission: 'users:edit' })
    }
    expect(db().account('member-1')).toMatchObject({ name: 'member-1', email: 'member-1@e2e.local', role: 'standard' })
  })

  test('another account\'s defaults still need users:edit', async () => {
    await as('admin-imp', 'member-1')
    expect((await editUser(req('PUT', { defaultAgentModel: 'openai/gpt-x' }), params('member-2'))).status).toBe(403)
  })
})

describe("another account's projects: their scope only with projects:oversee", () => {
  test('users:read alone (User manager): names and dates, no target', async () => {
    await as('admin-um')
    const { status, body } = await answer(await readUser(req('GET'), params('member-1')))
    expect(status).toBe(200)
    expect(body.projects).toEqual([{
      id: 'proj-1', name: 'Lab one', createdAt: PROJECT.createdAt.toISOString(), updatedAt: PROJECT.updatedAt.toISOString(),
    }])
  })

  test('users:read with projects:oversee (Security auditor): the scope too', async () => {
    await as('admin-audit')
    const { body } = await answer(await readUser(req('GET'), params('member-1')))
    expect(body.projects).toEqual([expect.objectContaining({ targetDomain: 'one.e2e.test', targetLabel: expect.any(String) })])
  })

  test('the account itself reads its own scope', async () => {
    await as('member-1')
    const { body } = await answer(await readUser(req('GET'), params('member-1')))
    expect(body.projects).toEqual([expect.objectContaining({ targetDomain: 'one.e2e.test' })])
  })
})

describe('switch off: as before', () => {
  beforeEach(() => setFlagsForTests({ identity: true, permissions: false }))

  test.each(['admin-um', 'admin-imp'])("%s reads another account and its projects' scope", async (admin) => {
    await as(admin)
    const { status, body } = await answer(await readUser(req('GET'), params('member-1')))
    expect(status).toBe(200)
    expect(body.projects).toEqual([expect.objectContaining({ targetDomain: 'one.e2e.test', targetLabel: expect.any(String) })])
  })

  test('an admin acting as a member edits its name, as before', async () => {
    await as('admin-imp', 'member-1')
    expect((await editUser(req('PUT', { name: 'Renamed' }), params('member-1'))).status).toBe(200)
  })

  test('a member reads no other account', async () => {
    await as('member-2')
    expect((await readUser(req('GET'), params('member-1'))).status).toBe(403)
  })
})
