/**
 * The decision check follows the project's toggles (step 5.4; SH-34, IM-09): an approval or a
 * dangerous-tool confirmation needs Exploitation & shells, a Fireteam member confirmation needs Use
 * AI agent and Exploitation, an answer to the agent's question Use AI agent, a CodeFix push Manage
 * (and Use AI agent for `codefix:run`), each asked again when the person answers.
 *
 * projectAccess() is stubbed with the write answers step 5.6 will give (today `effectiveToggles`
 * holds the run toggles off, route.test.ts proves that); can(), meetsLevel, the registry, the
 * resolution and the route are the real ones. Run with route.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const KEY = 'internal-key-for-test'
vi.stubEnv('INTERNAL_API_KEY', KEY)
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

const h = vi.hoisted(() => ({
  access: null as Record<string, unknown> | null,
  audit: [] as Array<Record<string, unknown>>,
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => ({
        id: where.id, email: `${where.id}@e2e.local`, name: where.id, role: where.id.startsWith('admin') ? 'admin' : 'standard',
        password: 'hash', createdAt: new Date(0), legacyGrants: [], status: 'active', sessionVersion: 0,
        mustChangePassword: false, adminProfileId: null, lastLoginAt: null, permissionSets: [], permissionOverrides: [],
      }),
    },
    instanceSettings: { findUnique: async () => ({ rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }) },
    permissionSet: { findMany: async () => [] },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { h.audit.push(data); return { id: 'row' } } },
  },
}))
vi.mock('@/lib/authz/projectAccess', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: vi.fn(async () => h.access),
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { projectAccess } from '@/lib/authz/projectAccess'

const OFF = { runScans: false, useAgent: false, exploit: false, manage: false }
function writeShare(toggles: Partial<typeof OFF> = {}) {
  return { project: { id: 'P-alice', userId: 'alice' }, level: 'write', toggles: { rawData: true, ...OFF, ...toggles }, via: 'share' }
}

async function ask(kind: string, over: Record<string, unknown> = {}) {
  const res = await POST(new NextRequest('http://localhost:3000/api/internal/agent/authorize-decision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-internal-key': KEY },
    body: JSON.stringify({ kind, userId: 'bob', projectId: 'P-alice', sessionId: 'sess-b', ...over }),
  }))
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  h.access = null
  h.audit = []
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  vi.mocked(projectAccess).mockClear()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('approvals by toggle', () => {
  test('approval refused when the exploit toggle is off, allowed with it', async () => {
    h.access = writeShare({ useAgent: true })
    expect(await ask('approval')).toMatchObject({ status: 403, body: { permission: 'agent:approve_phase', reason: 'project_level' } })
    h.access = writeShare({ useAgent: true, exploit: true })
    expect(await ask('approval')).toEqual({ status: 200, body: { allowed: true } })
    expect(vi.mocked(projectAccess).mock.calls.every(([s, p, o]) => s.userId === 'bob' && p === 'P-alice' && o?.fresh === true)).toBe(true)
  })

  test('a dangerous-tool confirmation follows Exploitation as well', async () => {
    h.access = writeShare()
    expect((await ask('tool_confirmation')).body.permission).toBe('agent:approve_dangerous')
    h.access = writeShare({ exploit: true })
    expect((await ask('tool_confirmation')).status).toBe(200)
  })

  test('a Fireteam member confirmation needs Use AI agent and Exploitation', async () => {
    h.access = writeShare({ exploit: true })
    expect((await ask('fireteam_member_confirmation')).body).toMatchObject({ permission: 'agent:fireteam', reason: 'project_level' })
    h.access = writeShare({ useAgent: true })
    expect((await ask('fireteam_member_confirmation')).body).toMatchObject({ permission: 'agent:approve_dangerous', reason: 'project_level' })
    h.access = writeShare({ useAgent: true, exploit: true })
    expect((await ask('fireteam_member_confirmation')).status).toBe(200)
  })

  test('an answer to the agent\'s question needs Use AI agent only', async () => {
    h.access = writeShare({ exploit: true, manage: true })
    expect((await ask('question')).body).toMatchObject({ permission: 'agent:chat', reason: 'project_level' })
    h.access = writeShare({ useAgent: true })
    expect((await ask('question')).status).toBe(200)
  })

  test('a CodeFix push needs Manage on top of codefix:run (phase file 5.2)', async () => {
    h.access = writeShare({ useAgent: true })
    expect((await ask('codefix_push')).body).toMatchObject({ permission: 'codefix:run', reason: 'project_level' })
    h.access = writeShare({ manage: true })
    expect((await ask('codefix_push')).body).toMatchObject({ permission: 'codefix:run', reason: 'project_level' })
    h.access = writeShare({ useAgent: true, manage: true })
    expect((await ask('codefix_push')).status).toBe(200)
  })
})

describe('re-checked when made', () => {
  test('refused after a revoke on an open socket: allowed, the share goes, refused and audited', async () => {
    h.access = writeShare({ useAgent: true, exploit: true })
    expect((await ask('approval')).status).toBe(200)
    h.access = null
    expect(await ask('approval')).toMatchObject({ status: 403, body: { code: 'forbidden', permission: 'agent:approve_phase', reason: 'project_not_visible' } })
    expect(h.audit).toEqual([expect.objectContaining({
      actorId: 'bob', actorEmail: 'bob@e2e.local', projectId: 'P-alice', action: 'agent.decision_refused',
      targetId: 'sess-b', after: { kind: 'approval', reason: 'project_not_visible' },
    })])
  })

  test('the toggle switched off mid-session refuses the next answer', async () => {
    h.access = writeShare({ useAgent: true, exploit: true })
    expect((await ask('tool_confirmation')).status).toBe(200)
    h.access = writeShare({ useAgent: true })
    expect((await ask('tool_confirmation')).body.reason).toBe('project_level')
  })

  test('the owner\'s answer never depends on a toggle', async () => {
    h.access = { project: { id: 'P-alice', userId: 'alice' }, level: 'owner', toggles: { rawData: true }, via: 'owner' }
    for (const kind of ['approval', 'tool_confirmation', 'fireteam_member_confirmation', 'question', 'codefix_push']) {
      expect((await ask(kind, { userId: 'alice' })).status, kind).toBe(200)
    }
    expect(h.audit).toEqual([])
  })
})

describe('decisions the project settings take without asking anyone (step 5.4 review)', () => {
  test('a Fireteam wave start needs Use AI agent, nothing else', async () => {
    h.access = writeShare({ exploit: true, manage: true })
    expect((await ask('fireteam_deploy')).body).toMatchObject({ permission: 'agent:fireteam', reason: 'project_level' })
    h.access = writeShare({ useAgent: true })
    expect((await ask('fireteam_deploy')).status).toBe(200)
  })
})
