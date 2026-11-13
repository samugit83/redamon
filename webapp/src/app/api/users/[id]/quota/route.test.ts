/**
 * GET /api/users/[id]/quota (step 6.8; GV-09..GV-13): one account's quota (the real resolution), where
 * each value comes from with set names, and the use the webapp counts (owned projects, MCP tokens that
 * still work). The account or a users:read holder (requireUserAccess, doubled); an unknown account 404;
 * with RBAC_GOVERNANCE_ENABLED off 404 before the session or the database is read.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/users/[id]/quota/route.test.ts"
 * @vitest-environment node
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  access: vi.fn(),
  users: new Set(['mem-c']),
  touched: vi.fn(),
}))

vi.mock('@/lib/session', () => ({ requireUserAccess: (...a: unknown[]) => h.access(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: async ({ where }: { where: { id: string } }) => { h.touched('user'); return h.users.has(where.id) ? { id: where.id } : null } },
    project: { count: async () => { h.touched('project'); return 1 } },
    mcpAccessToken: { count: async () => { h.touched('token'); return 2 } },
    permissionSet: { findMany: async () => [{ id: 'cset-1', name: 'Lab team' }] },
  },
}))
vi.mock('@/lib/sharedInstanceSettings', () => ({
  instanceSettingsInForce: async () => {
    h.touched('instance')
    return { quotas: { defaults: { maxProjects: 1, maxMcpTokens: 5 }, perSet: { 'cset-1': { maxProjects: 3 }, 'builtin:default-member': { maxConcurrentScans: 2 } }, perUser: { 'mem-c': { maxConcurrentAgentRuns: 1 } } } }
  },
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: async (id: string) => ({ id, role: 'standard', status: 'active', legacyGrants: [], permissionSets: ['cset-1'], permissionOverrides: [] }),
}))
vi.mock('@/lib/authz/capabilities', () => ({
  resolveCapabilities: async () => ({
    accountType: 'member',
    sets: [{ id: 'cset-1', name: 'Lab team', kind: 'member', via: 'assigned' }, { id: 'builtin:default-member', name: 'Default member', kind: 'member', via: 'assigned' }],
  }),
}))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'

const call = (id: string) => GET(new NextRequest(`http://localhost:3000/api/users/${id}/quota`), { params: Promise.resolve({ id }) })

beforeEach(() => {
  h.access.mockReset()
  h.access.mockResolvedValue(null)
  h.touched.mockClear()
  setFlagsForTests({ identity: true, permissions: true, governance: true })
})
afterEach(() => setFlagsForTests(null))

describe('GET /api/users/[id]/quota', () => {
  test('the quota, where each value comes from (sets by name), and the use counted here', async () => {
    const res = await call('mem-c')
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.enforced).toBe(true)
    expect(body.quota).toMatchObject({ maxProjects: 3, maxConcurrentScans: 2, maxConcurrentAgentRuns: 1, maxMcpTokens: 5, llmDailyCalls: null })
    expect(body.sources.maxProjects).toEqual({ kind: 'set', setId: 'cset-1', setName: 'Lab team' })
    expect(body.sources.maxConcurrentScans).toEqual({ kind: 'set', setId: 'builtin:default-member', setName: 'Default member' })
    expect(body.sources.maxConcurrentAgentRuns).toEqual({ kind: 'user' })
    expect(body.sources.maxMcpTokens).toEqual({ kind: 'default' })
    expect(body.use).toEqual({ maxProjects: 1, maxMcpTokens: 2 })
    expect(h.access).toHaveBeenCalledWith(expect.anything(), 'mem-c', { mode: 'read' })
  })

  test("another account without users:read: the guard's 403, nothing read", async () => {
    h.access.mockResolvedValue(NextResponse.json({ error: 'Forbidden', code: 'forbidden', permission: 'users:read' }, { status: 403 }))
    const res = await call('mem-c')
    expect(res.status).toBe(403)
    expect(h.touched).not.toHaveBeenCalled()
  })

  test('an unknown account is 404', async () => {
    expect((await call('ghost')).status).toBe(404)
  })

  test('switch off: 404 before the session or the database is read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    expect((await call('mem-c')).status).toBe(404)
    expect(h.access).not.toHaveBeenCalled()
    expect(h.touched).not.toHaveBeenCalled()
  })
})
