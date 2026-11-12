/**
 * A §5.2 platform tool is its permission's, whoever holds it (review of step 3.7, finding 5). With
 * RBAC_PERMISSIONS_ENABLED on a member may hold one through an override (3.4's resolution, 3.11's
 * `overrideAllowed`: "a §5.2 platform tool on a member only", D-20), and every platform gate asks
 * the permission, not the account type: the plugin lifecycle (`requirePluginAdmin`,
 * platform:plugins) and the agent's MCP reload (platform:agent_mcp) let such a member in, and
 * refuse an admin whose profile lacks the permission. With the switch off overrides count for
 * nothing and both stay the administrator account's, with today's answers.
 *
 * Real session helpers, tokens and capability resolution; the database is the in-memory
 * accountDb; the agent is a fetch double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'ik-test-master-0001')
vi.stubEnv('AGENT_API_URL', 'http://agent.test:8080')

const h = vi.hoisted(() => ({ db: null as unknown, jar: {} as { auth?: string } }))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
vi.mock('@/lib/prisma', async () => {
  const { createAccountDb } = await import('@/lib/authz/__testing__/accountDb')
  h.db = createAccountDb()
  return { default: h.db, prisma: h.db }
})

import type { AccountDb } from './__testing__/accountDb'
import { createToken } from '@/lib/auth'
import { setFlagsForTests } from './flags'
import { clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { clearCapabilityCachesForTests } from './capabilities'
import { requirePluginAdmin } from '@/lib/plugins/lifecycleRoutes'
import { viewerIsAdmin } from '@/lib/plugins/pageModel'
import { POST as reloadMcp } from '@/app/api/mcp/reload/route'

const db = () => h.db as AccountDb
const fetchMock = vi.fn()

async function as(userId: string) {
  const row = db().account(userId)!
  h.jar.auth = await createToken(userId, String(row.role), Number(row.sessionVersion ?? 0))
}

/** Whether each gate let the person in: the plugin lifecycle, the plugins page model, the MCP reload. */
async function gates(userId: string) {
  await as(userId)
  fetchMock.mockClear()
  const plugin = await requirePluginAdmin()
  const reload = await reloadMcp()
  return {
    plugins: !(plugin instanceof NextResponse),
    pluginsPage: await viewerIsAdmin(userId),
    reload: reload.status === 200 && fetchMock.mock.calls.length === 1,
    reloadAnswer: reload.status === 200 ? null : { status: reload.status, body: await reload.json() },
  }
}

beforeEach(() => {
  db().reset()
  db().seedUsers([
    { id: 'root-1', role: 'admin' },
    { id: 'admin-um', role: 'admin', adminProfileId: 'builtin:user-manager' },
    { id: 'admin-po', role: 'admin', adminProfileId: 'builtin:platform-operator' },
    { id: 'member-plugins' },
    { id: 'member-mcp' },
    { id: 'member-1' },
  ])
  db().seedOverride({ userId: 'member-plugins', permission: 'platform:plugins', effect: 'grant', reason: 'runs the plugins' })
  db().seedOverride({ userId: 'member-mcp', permission: 'platform:agent_mcp', effect: 'grant', reason: 'runs the MCP servers' })
  db().seedInstance({ rootUserId: 'root-1', rootAssignedBy: 'host', rootConfirmedAt: new Date('2026-11-12T08:00:00Z') })
  setFlagsForTests({ identity: true, permissions: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  h.jar = {}
  fetchMock.mockReset()
  fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllGlobals()
})

describe('permissions switch on: the permission decides, whatever the account type', () => {
  test('a member holding platform:plugins through an override manages plugins, and reloads nothing', async () => {
    expect(await gates('member-plugins')).toMatchObject({ plugins: true, pluginsPage: true, reload: false })
  })

  test('a member holding platform:agent_mcp through an override reloads the agent\'s MCP servers, and manages no plugin', async () => {
    expect(await gates('member-mcp')).toMatchObject({ plugins: false, pluginsPage: false, reload: true, reloadAnswer: null })
  })

  test('a member without an override passes neither; the reload refusal names its permission', async () => {
    const g = await gates('member-1')
    expect(g).toMatchObject({ plugins: false, pluginsPage: false, reload: false })
    expect(g.reloadAnswer).toMatchObject({ status: 403, body: { code: 'forbidden', permission: 'platform:agent_mcp' } })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('an admin whose profile lacks both (User manager) passes neither; a Platform operator passes both', async () => {
    expect(await gates('admin-um')).toMatchObject({ plugins: false, pluginsPage: false, reload: false })
    expect(await gates('admin-po')).toMatchObject({ plugins: true, pluginsPage: true, reload: true })
  })
})

describe('permissions switch off: the administrator account, as before', () => {
  beforeEach(() => setFlagsForTests({ identity: true, permissions: false }))

  test.each(['member-plugins', 'member-mcp', 'member-1'])('%s passes neither; the reload answers today\'s 403', async (member) => {
    const g = await gates(member)
    expect(g).toMatchObject({ plugins: false, pluginsPage: false, reload: false })
    expect(g.reloadAnswer).toEqual({ status: 403, body: { error: 'Forbidden' } })
  })

  test.each(['admin-um', 'admin-po'])('%s passes both', async (admin) => {
    expect(await gates(admin)).toMatchObject({ plugins: true, pluginsPage: true, reload: true })
  })
})
