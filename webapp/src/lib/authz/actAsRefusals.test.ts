/**
 * Never while acting as someone (step 3.14, IM-08; feature document §4.7): with
 * RBAC_PERMISSIONS_ENABLED on, an admin acting as an account cannot change its password or reset
 * its credentials, change its sign-in email, delete it, mint an MCP token in its name, or write its
 * agent skills on any path (single create, edit, delete, batch, release, saving a plugin proposal).
 * Each attempt answers 403 `not_while_acting_as` naming the account ("not available while acting as
 * Marco") and writes an `act_as.refused` row, before anything is written. The admin's administration
 * of other accounts, the account's own writes and every write with the switch off are unchanged.
 *
 * Real routes, session helpers, tokens and capability resolution; the database is the in-memory
 * accountDb.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', '9'.repeat(64))

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
  // The rows the self-service routes read before they decide (a provider, the MCP servers, a project,
  // the GitHub token); every write past a refusal would fail loudly here.
  Object.assign(db, {
    userLlmProvider: {
      findFirst: async () => ({ id: 'prov-1', userId: 'member-1', providerType: 'openai_compatible', name: 'p', baseUrl: 'https://llm.e2e.test/v1', apiKey: 'sk-fake-key' }),
      update: async () => { throw new Error('provider written') },
      create: async () => { throw new Error('provider written') },
    },
    userSettings: {
      findUnique: async () => ({
        githubAccessToken: 'ghp_fake_e2e_token',
        mcpServers: [{ id: 'srv-1', name: 's', transport: 'http', url: 'https://mcp.e2e.test/mcp', enabled: false }],
      }),
      upsert: async () => { throw new Error('settings written') },
      update: async () => { throw new Error('settings written') },
    },
    userChatSkill: {
      create: async () => { throw new Error('chat skill written') },
      count: async () => 0,
      findFirst: async () => ({ id: 'cs-1', userId: 'member-1' }),
      update: async () => { throw new Error('chat skill written') },
      delete: async () => { throw new Error('chat skill written') },
    },
    project: { ...db.project, findUnique: async ({ where }: { where: { id: string } }) => (where.id === 'P-member-1' ? { id: 'P-member-1', userId: 'member-1' } : null) },
  })
  h.db = db
  return { default: db, prisma: db }
})
const agentCalls = vi.hoisted(() => ({ n: 0 }))
vi.mock('@/app/api/agent/agentProxy', async (orig) => ({
  ...(await orig<typeof import('@/app/api/agent/agentProxy')>()),
  callAgent: async () => { agentCalls.n++; throw new Error('the agent was called') },
}))

import bcrypt from 'bcryptjs'
import type { AccountDb } from './__testing__/accountDb'
import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import { getSession } from '@/lib/session'
import { ACTING_AS_ACTIONS, refuseWhileActingAs } from './actAsRefusals'
import { UserSkillError } from '@/lib/userSkills'
import {
  createUserSkill, createUserSkillsBatch, deleteUserSkill, releaseUserSkill, updateUserSkill,
} from '@/lib/userSkillWrites'
import { adoptUserSkillVersion } from '@/lib/plugins/userSkillAdoption'
import { PUT as editUser, DELETE as deleteUser } from '@/app/api/users/[id]/route'
import { POST as createChatSkill } from '@/app/api/users/[id]/chat-skills/route'
import { PUT as editChatSkill, DELETE as deleteChatSkill } from '@/app/api/users/[id]/chat-skills/[skillId]/route'
import { POST as importChatSkills } from '@/app/api/users/[id]/chat-skills/import-community/route'
import { POST as importAgentSkills } from '@/app/api/users/[id]/attack-skills/import-community/route'
import { POST as createProvider } from '@/app/api/users/[id]/llm-providers/route'
import { PUT as editProvider } from '@/app/api/users/[id]/llm-providers/[providerId]/route'
import { POST as addMcpServer } from '@/app/api/users/[id]/mcp/route'
import { PUT as editMcpServer } from '@/app/api/users/[id]/mcp/[serverId]/route'
import { POST as importUrl } from '@/app/api/agent/workspace/import-url/route'
import { POST as resolveUrl } from '@/app/api/agent/workspace/import-url/resolve/route'
import { PUT as setPassword } from '@/app/api/users/[id]/password/route'
import { POST as resetCredentials } from '@/app/api/users/[id]/reset-credentials/route'
import { POST as mintToken } from '@/app/api/users/[id]/mcp-tokens/route'

const db = () => h.db as AccountDb
const ADMIN_PW = 'admin-one-passphrase'
const ADMIN_HASH = bcrypt.hashSync(ADMIN_PW, 4)

function req(method: string, body?: unknown): NextRequest {
  return new NextRequest('http://redamon.test/api/users/x', {
    method,
    headers: { host: 'redamon.test', origin: 'http://redamon.test', 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

/** Signed in as `userId`, acting as `actingAs` through a cookie that names its start row in the log. */
async function as(userId: string, actingAs?: string) {
  h.jar.auth = await createToken(userId, String(db().account(userId)!.role), 0)
  if (!actingAs) {
    h.jar.actAs = undefined
    return
  }
  const jti = `start-${userId}-${actingAs}-${db().actAs().length + 1}`
  db().seedActAs({ id: jti, adminId: userId, targetUserId: actingAs, event: 'start', createdAt: new Date(), durationMinutes: 60 })
  h.jar.actAs = await createActAsToken(userId, actingAs, 3600, { asv: 0, jti })
}

const refusals = () => db().audit().filter((r) => r.action === 'act_as.refused')

async function expectRefused(res: Response, action: string) {
  expect(res.status).toBe(403)
  expect(await res.json()).toEqual({
    error: expect.stringMatching(/^Not available while acting as Marco: .+ stays with them\./),
    code: 'not_while_acting_as',
    action,
  })
  expect(refusals().at(-1)).toMatchObject({
    action: 'act_as.refused', actorId: 'admin-1', onBehalfOfUserId: 'member-1', targetType: 'user', targetId: 'member-1',
    after: { action },
  })
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-1', role: 'admin', name: 'Laura', password: ADMIN_HASH },
    // A passwordless managed account: run only through act-as, which step 1.6 lets write its data.
    { id: 'member-1', name: 'Marco', password: '' },
    { id: 'member-2', name: 'Nina' },
  ])
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('the helper', () => {
  test('refuses only while acting, and only on the account acted as when one is named', async () => {
    await as('admin-1', 'member-1')
    const session = (await getSession())!
    expect(await refuseWhileActingAs({ session, targetUserId: 'member-2' }, 'change_email')).toBeNull()
    expect((await refuseWhileActingAs({ session }, 'change_shares'))?.status).toBe(403)
    expect((await refuseWhileActingAs({ session, targetUserId: 'member-1' }, 'transfer_projects'))?.status).toBe(403)
    await as('admin-1')
    expect(await refuseWhileActingAs({ session: (await getSession())! }, 'change_shares')).toBeNull()
    expect(refusals()).toHaveLength(2)
  })

  test('switch off: never refuses, writes nothing', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-1', 'member-1')
    for (const action of ACTING_AS_ACTIONS) {
      expect(await refuseWhileActingAs({ session: (await getSession())! }, action)).toBeNull()
    }
    expect(refusals()).toEqual([])
  })
})

describe('each never-list action is refused and audited', () => {
  test('changing the password of the account acted as', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await setPassword(req('PUT', { newPassword: 'a-long-new-passphrase-42', reason: 'x' }), params('member-1')), 'change_password')
    expect(db().account('member-1')!.password).toBe('')
  })

  test('resetting its credentials', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await resetCredentials(req('POST', { mode: 'link', reason: 'x' }), params('member-1')), 'change_password')
    expect(db().invites()).toEqual([])
  })

  test('changing its sign-in email; its name stays the admin\'s users:edit to change', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await editUser(req('PUT', { email: 'new@e2e.local' }), params('member-1')), 'change_email')
    expect(db().account('member-1')!.email).toBe('member-1@e2e.local')
    expect((await editUser(req('PUT', { name: 'Marco R.' }), params('member-1'))).status).toBe(200)
  })

  test('deleting its account', async () => {
    await as('admin-1', 'member-1')
    await expectRefused(await deleteUser(req('DELETE'), params('member-1')), 'delete_account')
    expect(db().account('member-1')).toBeDefined()
  })

  test('minting an MCP token in its name: refused, as it always was (real-only)', async () => {
    await as('admin-1', 'member-1')
    const res = await mintToken(req('POST', { name: 't', scopes: ['read'] }), params('member-1'))
    expect(res.status).toBe(403)
    expect(db().tokens()).toEqual([])
  })

  test('another account stays the admin\'s to administer while acting', async () => {
    await as('admin-1', 'member-1')
    // An email change takes the admin's own password (step 2.11).
    expect((await editUser(req('PUT', { email: 'nina@e2e.local', stepUpPassword: ADMIN_PW }), params('member-2'))).status).toBe(200)
    expect(refusals()).toEqual([])
  })

  test('switch off: the admin\'s administration as before', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-1', 'member-1')
    expect((await editUser(req('PUT', { email: 'marco@e2e.local', stepUpPassword: ADMIN_PW }), params('member-1'))).status).toBe(200)
    expect(refusals()).toEqual([])
  })
})

describe('writing the agent skills of the account acted as, on every path (the userSkillWrites chokepoint)', () => {
  const ADMIN = { actorId: 'admin-1', onBehalfOf: 'member-1', source: 'ui' as const }
  const writes: Array<[string, () => Promise<unknown>]> = [
    ['single create', () => createUserSkill({ userId: 'member-1', name: 'x', description: null, content: 'x' }, ADMIN)],
    ['batch upload', () => createUserSkillsBatch({ userId: 'member-1', items: [{ name: 'x', content: 'x' }] }, ADMIN)],
    ['edit', () => updateUserSkill({ userId: 'member-1', skillId: 's1', name: 'y' }, ADMIN)],
    ['delete', () => deleteUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)],
    ['release', () => releaseUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)],
    ["saving a plugin's proposal", () => adoptUserSkillVersion({
      changeSetId: 'cs-1', ownerId: 'member-1', actor: ADMIN, name: 'x', description: null, projectId: null,
      enableNew: false, disableSource: false, acknowledgedRiskLines: undefined,
    } as unknown as Parameters<typeof adoptUserSkillVersion>[0])],
  ]

  test.each(writes)('%s: 403 not_while_acting_as, audited, before any transaction', async (_name, write) => {
    await as('admin-1', 'member-1')
    const tx = vi.spyOn(db(), '$transaction')
    const err = await write().catch((e: unknown) => e) as UserSkillError
    expect(err).toBeInstanceOf(UserSkillError)
    expect(err).toMatchObject({ status: 403, code: 'not_while_acting_as', extra: { action: 'write_agent_skills' } })
    expect(err.message).toMatch(/^Not available while acting as Marco: writing their agent skills stays with them\./)
    expect(tx).not.toHaveBeenCalled()
    expect(refusals().at(-1)).toMatchObject({ onBehalfOfUserId: 'member-1', after: { action: 'write_agent_skills' } })
  })

  test('the account\'s own write and the switch off read no session and refuse nothing', async () => {
    await as('admin-1', 'member-1')
    const own = { actorId: 'member-1', source: 'ui' as const }
    const tx = vi.spyOn(db(), '$transaction').mockRejectedValue(new Error('reached the write'))
    await expect(deleteUserSkill({ userId: 'member-1', skillId: 's1' }, own)).rejects.toThrow('reached the write')
    setFlagsForTests({ identity: true, permissions: false })
    await expect(deleteUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)).rejects.toThrow('reached the write')
    expect(tx).toHaveBeenCalledTimes(2)
    expect(refusals()).toEqual([])
  })

  test('an admin not acting (a plugin approval of someone else\'s proposal) is not refused here', async () => {
    await as('admin-1')
    vi.spyOn(db(), '$transaction').mockRejectedValue(new Error('reached the write'))
    await expect(deleteUserSkill({ userId: 'member-1', skillId: 's1' }, ADMIN)).rejects.toThrow('reached the write')
  })
})

describe('the self-service catalogs of the account acted as (a passwordless managed account, which 1.6 lets the admin write)', () => {
  const p2 = <T extends Record<string, string>>(id: string, other: T) => ({ params: Promise.resolve({ id, ...other }) })
  const cases: Array<[string, () => Promise<Response>, string]> = [
    ['create a chat skill', () => createChatSkill(req('POST', { name: 'x', content: 'x' }), params('member-1')), 'write_chat_skills'],
    ['edit a chat skill', () => editChatSkill(req('PUT', { name: 'y' }), p2('member-1', { skillId: 'cs-1' })), 'write_chat_skills'],
    ['delete a chat skill', () => deleteChatSkill(req('DELETE'), p2('member-1', { skillId: 'cs-1' })), 'write_chat_skills'],
    ['import the community chat skills', () => importChatSkills(req('POST', {}), params('member-1')), 'write_chat_skills'],
    ['import the community agent skills', () => importAgentSkills(req('POST', {}), params('member-1')), 'write_agent_skills'],
    ['add an LLM provider', () => createProvider(req('POST', { providerType: 'openai_compatible', name: 'p', baseUrl: 'https://evil.e2e.test/v1', apiKey: 'sk-x' }), params('member-1')), 'change_llm_endpoint'],
    ["change an LLM provider's endpoint", () => editProvider(req('PUT', { baseUrl: 'https://evil.e2e.test/v1', apiKey: 'sk-new' }), p2('member-1', { providerId: 'prov-1' })), 'change_llm_endpoint'],
    ["change an LLM provider's key", () => editProvider(req('PUT', { apiKey: 'sk-new' }), p2('member-1', { providerId: 'prov-1' })), 'change_llm_endpoint'],
    ['add an outbound MCP server', () => addMcpServer(req('POST', { name: 'm', transport: 'http', url: 'https://evil.e2e.test/mcp' }), params('member-1')), 'add_mcp_server'],
    ["re-point an MCP server", () => editMcpServer(req('PUT', { name: 's', transport: 'http', url: 'https://evil.e2e.test/mcp', enabled: false }), p2('member-1', { serverId: 'srv-1' })), 'change_mcp_endpoint'],
  ]

  test.each(cases)('%s: 403 not_while_acting_as, audited, nothing written', async (_name, call, action) => {
    await as('admin-1', 'member-1')
    await expectRefused(await call(), action)
  })

  test("a provider's name change stays allowed: it reaches the write", async () => {
    await as('admin-1', 'member-1')
    const res = await editProvider(req('PUT', { name: 'renamed', apiKey: '••••••••' }), p2('member-1', { providerId: 'prov-1' }))
    expect(res.status).toBe(500)
    expect(refusals()).toEqual([])
  })

  test('switch off: the same writes are not refused for acting (they reach the write)', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    await as('admin-1', 'member-1')
    expect((await createChatSkill(req('POST', { name: 'x', content: 'x' }), params('member-1'))).status).toBe(500)
    expect(refusals()).toEqual([])
  })
})

describe("using the GitHub token of the account acted as (workspace import)", () => {
  const link = { projectId: 'P-member-1', url: 'https://github.com/e2e-org/private-repo' }

  test.each([['import', importUrl], ['link check', resolveUrl]] as const)('%s of a GitHub link: 403 instead of importing without the token', async (_name, route) => {
    await as('admin-1', 'member-1')
    await expectRefused(await route(req('POST', link)), 'use_github_token')
    expect(agentCalls.n).toBe(0)
  })

  test('a link that is not GitHub, and the switch off, go on without a token (to the agent)', async () => {
    await as('admin-1', 'member-1')
    await importUrl(req('POST', { ...link, url: 'https://example.e2e.test/archive.zip' })).catch(() => null)
    setFlagsForTests({ identity: true, permissions: false })
    await importUrl(req('POST', link)).catch(() => null)
    expect(agentCalls.n).toBe(2)
    expect(refusals()).toEqual([])
  })
})
