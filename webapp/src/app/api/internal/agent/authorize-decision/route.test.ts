/**
 * POST /api/internal/agent/authorize-decision (step 5.4; SH-34, SH-41 mid-session part, IM-09):
 * before the agent accepts an answer to one of its prompts, or CodeFix pushes with the owner's
 * token, it asks whether the person may still take that decision now. The kind names the
 * permissions (and level); can() decides them fresh for the ticket's person, under act-as for both
 * people; a disabled or deleted account is refused; a refusal writes `agent.decision_refused`.
 *
 * Prisma is a double (accounts, projects, shares, the instance row, the audit table); the
 * registry, the built-in sets, the resolution, projectAccess(), can() and lib/audit.ts are the real
 * ones. The write toggles are held off until step 5.6 (`effectiveToggles`), so a write share's
 * toggled decisions are proved with projectAccess stubbed in route.toggles.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'

const KEY = 'internal-key-for-test'
vi.stubEnv('INTERNAL_API_KEY', KEY)
vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

type Row = Record<string, unknown>
const db = vi.hoisted(() => ({
  users: new Map<string, Record<string, unknown>>(),
  projects: new Map<string, { id: string; userId: string }>(),
  shares: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
  failUsers: false,
  audit: [] as Array<Record<string, unknown>>,
}))
const userFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  if (db.failUsers) throw Object.assign(new Error('db down'), { code: 'P1001' })
  const row = db.users.get(where.id)
  return row ? { ...row } : null
})
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: async () => (db.instance ? { ...db.instance } : null) },
    permissionSet: { findMany: async () => [] },
    project: { findUnique: async ({ where }: { where: { id: string } }) => db.projects.get(where.id) ?? null },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
        const share = db.shares.get(`${where.projectId_userId.projectId}:${where.projectId_userId.userId}`)
        return share ? { ...share } : null
      },
    },
    projectBreakGlass: { findFirst: async () => null },
    auditLog: { create: async ({ data }: { data: Record<string, unknown> }) => { db.audit.push(data); return { id: 'row' } } },
  },
}))

import { POST } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'

const PATH = '/api/internal/agent/authorize-decision'

function account(id: string, over: Row = {}): Row {
  return {
    id, email: `${id}@e2e.local`, name: id, role: 'standard', password: 'hash', createdAt: new Date(0), legacyGrants: [],
    status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
    permissionSets: [], permissionOverrides: [], ...over,
  }
}
const deny = (permission: string) => ({ permission, effect: 'deny', expiresAt: null, reason: null })

function req(body: unknown, headers: Record<string, string> = { 'x-internal-key': KEY }, method = 'POST'): NextRequest {
  return new NextRequest(`http://localhost:3000${PATH}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

const check = (over: Row = {}) => ({ kind: 'approval', userId: 'alice', projectId: 'P-alice', sessionId: 'sess-1', ...over })

async function ask(over: Row = {}) {
  const res = await POST(req(check(over)))
  return { status: res.status, body: await res.json() }
}

beforeEach(() => {
  db.users.clear()
  db.users.set('alice', account('alice'))
  db.users.set('bob', account('bob'))
  db.users.set('admin-1', account('admin-1', { role: 'admin' }))
  db.users.set('admin-2', account('admin-2', { role: 'admin' }))
  db.projects.clear()
  db.projects.set('P-alice', { id: 'P-alice', userId: 'alice' })
  db.shares.clear()
  db.instance = { rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }
  db.failUsers = false
  db.audit = []
  userFindUnique.mockClear()
  setFlagsForTests({ identity: true, permissions: true })
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearSharingPolicyCacheForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('internal key only', () => {
  test('no key, a wrong key or the scanner key: 401, nothing read or written', async () => {
    vi.stubEnv('SCANNER_API_KEY', 'scanner-key-for-test')
    for (const headers of [{}, { 'x-internal-key': 'nope' }, { 'x-internal-key': 'scanner-key-for-test' }] as Record<string, string>[]) {
      expect((await POST(req(check(), headers))).status).toBe(401)
    }
    expect((await POST(req(check(), { cookie: 'redamon-auth=whatever' }))).status).toBe(401)
    expect(userFindUnique).not.toHaveBeenCalled()
    expect(db.audit).toEqual([])
    vi.stubEnv('SCANNER_API_KEY', '')
  })

  test('the middleware lets the agent through with INTERNAL_KEY_ALLOWLIST_ENFORCE=true, POST on this path only', async () => {
    vi.stubEnv('INTERNAL_KEY_ALLOWLIST_ENFORCE', 'true')
    vi.resetModules()
    const { middleware, internalKeyRouteAllowed } = await import('@/middleware')
    expect(internalKeyRouteAllowed('POST', PATH)).toBe(true)
    const passed = await middleware(req(check()))
    expect(passed.headers.get('x-middleware-next')).toBe('1')
    expect(internalKeyRouteAllowed('GET', PATH)).toBe(false)
    expect(internalKeyRouteAllowed('POST', `${PATH}/x`)).toBe(false)
    expect(internalKeyRouteAllowed('POST', '/api/internal/agent/authorize-decisions')).toBe(false)
    vi.stubEnv('INTERNAL_KEY_ALLOWLIST_ENFORCE', '')
  })
})

describe('the body', () => {
  test('a malformed check is a 400 and decides nothing', async () => {
    const bad: unknown[] = [
      null, [], 'x', {},
      check({ kind: 'admin' }), check({ kind: 'toString' }), check({ kind: undefined }),
      check({ userId: '' }), check({ projectId: 7 }), check({ sessionId: undefined }), check({ userId: 'u'.repeat(201) }),
      check({ actorId: 3 }), check({ actorId: '' }),
    ]
    for (const body of bad) {
      const res = await POST(req(body as object))
      expect([res.status, await res.json()]).toEqual([400, { error: 'Not an agent decision check', code: 'invalid_decision_check' }])
    }
    const res = await POST(req('{not json'))
    expect(res.status).toBe(400)
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test("a refusal's log line carries no CR/LF from the session id (the agent's client value)", async () => {
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:approve_phase')] }))
    expect((await ask({ sessionId: 'sess-1\r\n[rbac] agent decision allowed' })).status).toBe(403)
    const line = vi.mocked(console.warn).mock.calls.map(c => String(c[0])).find(l => l.startsWith('[rbac] agent decision refused'))
    expect(line).toBe('[rbac] agent decision refused kind=approval permission=agent:approve_phase reason=capability session=sess-1??[rbac] agent decision allowed')
  })

  test('the agent cannot ask for less: a permission or level in the body is ignored, the kind decides', async () => {
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:approve_phase')] }))
    const { status, body } = await ask({ permission: 'agent:chat', permissions: ['agent:chat'], level: 'R' })
    expect([status, body.permission, body.reason]).toEqual([403, 'agent:approve_phase', 'capability'])
  })
})

describe('the decision, now (identity + permissions on)', () => {
  test('the owner may take every kind of decision on their project; nothing is audited here', async () => {
    for (const kind of ['approval', 'tool_confirmation', 'fireteam_member_confirmation', 'question', 'codefix_push']) {
      expect(await ask({ kind }), kind).toEqual({ status: 200, body: { allowed: true } })
    }
    expect(db.audit).toEqual([])
  })

  test('each kind asks its own permissions: a deny on one refuses that kind and names it', async () => {
    const cases: Array<[string, string]> = [
      ['approval', 'agent:approve_phase'],
      ['tool_confirmation', 'agent:approve_dangerous'],
      ['fireteam_member_confirmation', 'agent:fireteam'],
      ['fireteam_member_confirmation', 'agent:approve_dangerous'],
      ['question', 'agent:chat'],
      ['codefix_push', 'codefix:run'],
    ]
    for (const [kind, permission] of cases) {
      db.users.set('alice', account('alice', { permissionOverrides: [deny(permission)] }))
      clearPrincipalCacheForTests()
      const { status, body } = await ask({ kind })
      expect([kind, status, body]).toEqual([kind, 403, {
        error: 'This decision is not allowed for this person on this project any more',
        code: 'forbidden', permission, reason: 'capability',
      }])
    }
  })

  test('a permission taken away after the socket opened refuses the next answer (read fresh, never cached)', async () => {
    expect((await ask()).status).toBe(200)
    // The ticket's cap still says yes; the account changes in the database only.
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:approve_phase')] }))
    const { status, body } = await ask()
    expect([status, body.reason]).toEqual([403, 'capability'])
    for (const [arg] of userFindUnique.mock.calls) expect(arg.where.id).toBe('alice')
  })

  test('an account disabled mid-session is refused, a deleted one too', async () => {
    db.users.set('alice', account('alice', { status: 'disabled' }))
    expect((await ask()).body).toMatchObject({ code: 'forbidden', permission: 'agent:approve_phase', reason: 'account_inactive' })
    db.users.delete('alice')
    expect((await ask()).body).toMatchObject({ code: 'forbidden', permission: 'agent:approve_phase', reason: 'deleted' })
  })

  test('a project the person cannot see (not shared, or gone) is refused as not visible', async () => {
    expect((await ask({ userId: 'bob' })).body).toMatchObject({ reason: 'project_not_visible', permission: 'agent:approve_phase' })
    expect((await ask({ projectId: 'P-gone' })).body).toMatchObject({ reason: 'project_not_visible' })
  })

  test('a Recon operator holds no approval into exploitation (the P3-05 person, now at decision time)', async () => {
    db.users.set('alice', account('alice', { permissionSets: [{ setId: 'builtin:recon-operator' }] }))
    expect((await ask()).body).toMatchObject({ reason: 'capability', permission: 'agent:approve_phase' })
    expect((await ask({ kind: 'question' })).status).toBe(200)
  })

  test('a failed read answers a coded 500, never allowed', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    db.failUsers = true
    const res = await POST(req(check()))
    expect(res.status).toBe(500)
    expect(await res.json()).not.toHaveProperty('allowed')
  })
})

describe('the refusal is audited', () => {
  test('audit names the collaborator: a read share answering an approval', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    db.instance = { ...db.instance, sharingPolicy: { enabled: true } }
    db.shares.set('P-alice:bob', { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
    const { status, body } = await ask({ userId: 'bob' })
    expect([status, body.reason]).toEqual([403, 'project_level'])
    expect(db.audit).toEqual([{
      actorId: 'bob', actorEmail: 'bob@e2e.local', projectId: 'P-alice', permission: 'agent:approve_phase',
      action: 'agent.decision_refused', targetType: 'agent_session', targetId: 'sess-1',
      after: { kind: 'approval', reason: 'project_level' }, source: 'ui',
    }])
  })

  test('admin under act-as recorded as the admin, the account acted as on behalf of', async () => {
    db.users.set('alice', account('alice', { permissionSets: [{ setId: 'builtin:recon-operator' }] }))
    const { status, body } = await ask({ actorId: 'admin-1' })
    expect([status, body.reason]).toEqual([403, 'capability'])
    expect(db.audit).toHaveLength(1)
    expect(db.audit[0]).toMatchObject({
      actorId: 'admin-1', onBehalfOfUserId: 'alice', actorEmail: 'admin-1@e2e.local',
      action: 'agent.decision_refused', permission: 'agent:approve_phase',
    })
  })

  test('a share revoked mid-session: refused and audited', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    db.instance = { ...db.instance, sharingPolicy: { enabled: true } }
    db.shares.set('P-alice:bob', { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
    expect((await ask({ userId: 'bob', kind: 'question' })).body.reason).toBe('project_level')
    db.shares.delete('P-alice:bob')
    expect((await ask({ userId: 'bob', kind: 'question' })).body.reason).toBe('project_not_visible')
    expect(db.audit.map((r) => (r.after as Row).reason)).toEqual(['project_level', 'project_not_visible'])
  })
})

describe('under act-as: what both people hold, fresh', () => {
  test('an admin acting as a Default member may approve on the member\'s project', async () => {
    expect(await ask({ actorId: 'admin-1' })).toEqual({ status: 200, body: { allowed: true } })
  })

  test('an admin denied the permission does not borrow it from the account acted as', async () => {
    db.users.set('admin-1', account('admin-1', { role: 'admin', permissionOverrides: [deny('agent:approve_dangerous')] }))
    expect((await ask({ actorId: 'admin-1', kind: 'tool_confirmation' })).body).toMatchObject({ reason: 'capability' })
  })

  test('an act-as the rule no longer allows (the target is an admin) is refused, not an error', async () => {
    db.projects.set('P-admin2', { id: 'P-admin2', userId: 'admin-2' })
    const { status, body } = await ask({ userId: 'admin-2', projectId: 'P-admin2', actorId: 'admin-1' })
    expect([status, body.reason]).toEqual([403, 'act_as_refused'])
  })

  test('the admin disabled or deleted since the socket opened is refused', async () => {
    db.users.set('admin-1', account('admin-1', { role: 'admin', status: 'disabled' }))
    expect((await ask({ actorId: 'admin-1' })).body.reason).toBe('account_inactive')
    db.users.delete('admin-1')
    expect((await ask({ actorId: 'admin-1' })).body.reason).toBe('deleted')
  })

  test('actorId equal to userId is no act-as', async () => {
    expect(await ask({ actorId: 'alice' })).toEqual({ status: 200, body: { allowed: true } })
    db.users.set('alice', account('alice', { permissionSets: [{ setId: 'builtin:recon-operator' }] }))
    await ask({ actorId: 'alice' })
    expect(db.audit[0]).not.toHaveProperty('onBehalfOfUserId')
  })
})

describe('the switches', () => {
  test('identity off: the status is not counted (as a session does), the rest is today\'s owner check', async () => {
    setFlagsForTests({ identity: false, permissions: false })
    db.users.set('alice', account('alice', { status: 'disabled' }))
    expect(await ask()).toEqual({ status: 200, body: { allowed: true } })
    expect((await ask({ userId: 'bob' })).body.reason).toBe('project_not_visible')
  })

  test('permissions off: every account holds the agent permissions on its own project (PE-27)', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    db.users.set('alice', account('alice', { permissionSets: [{ setId: 'builtin:recon-operator' }] }))
    for (const kind of ['approval', 'tool_confirmation', 'fireteam_member_confirmation', 'question', 'codefix_push']) {
      expect((await ask({ kind })).status, kind).toBe(200)
    }
  })

  test('write sharing in force: a write share is refused every toggled decision until 5.6 turns the toggles on', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    db.instance = { ...db.instance, sharingPolicy: { enabled: true, maxLevel: 'write' } }
    db.shares.set('P-alice:bob', {
      access: 'write', rawData: true, expiresAt: null, user: { status: 'active' }, runScans: true, useAgent: true, exploit: true, manage: true,
    })
    for (const kind of ['approval', 'tool_confirmation', 'fireteam_member_confirmation', 'question', 'codefix_push']) {
      expect([kind, (await ask({ kind, userId: 'bob' })).body.reason]).toEqual([kind, 'project_level'])
    }
  })
})

describe('a decision nobody is asked about: the Fireteam wave start (step 5.4 review, OQ-R6)', () => {
  test('fireteam_deploy asks agent:fireteam alone, fresh', async () => {
    expect(await ask({ kind: 'fireteam_deploy' })).toEqual({ status: 200, body: { allowed: true } })
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:fireteam')] }))
    clearPrincipalCacheForTests()
    const { status, body } = await ask({ kind: 'fireteam_deploy' })
    expect([status, body.permission, body.reason]).toEqual([403, 'agent:fireteam', 'capability'])
    expect(db.audit).toEqual([expect.objectContaining({
      action: 'agent.decision_refused', permission: 'agent:fireteam', after: { kind: 'fireteam_deploy', reason: 'capability' },
    })])
  })

  test('a member\'s dangerous calls are decided one by one, not at the wave start', async () => {
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:approve_dangerous')] }))
    expect((await ask({ kind: 'fireteam_deploy' })).status).toBe(200)
  })
})

describe('a tool confirmation answering a Fireteam member\'s escalation (step 5.4 review, finding 3)', () => {
  test('the mode adds agent:fireteam: approving it redeploys the member', async () => {
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:fireteam')] }))
    expect((await ask({ kind: 'tool_confirmation' })).status).toBe(200)
    const { status, body } = await ask({ kind: 'tool_confirmation', mode: 'fireteam_escalation' })
    expect([status, body.permission, body.reason]).toEqual([403, 'agent:fireteam', 'capability'])
    expect(db.audit).toEqual([expect.objectContaining({
      action: 'agent.decision_refused', permission: 'agent:fireteam',
      after: { kind: 'tool_confirmation', mode: 'fireteam_escalation', reason: 'capability' },
    })])
  })

  test('approve_dangerous is still asked in that mode, and the owner holds both', async () => {
    expect(await ask({ kind: 'tool_confirmation', mode: 'fireteam_escalation' })).toEqual({ status: 200, body: { allowed: true } })
    db.users.set('alice', account('alice', { permissionOverrides: [deny('agent:approve_dangerous')] }))
    clearPrincipalCacheForTests()
    expect((await ask({ kind: 'tool_confirmation', mode: 'fireteam_escalation' })).body.permission).toBe('agent:approve_dangerous')
  })

  test('a mode the kind does not have is a 400, never a narrower check', async () => {
    for (const over of [
      { kind: 'tool_confirmation', mode: 'plan' }, { kind: 'tool_confirmation', mode: 'toString' },
      { kind: 'approval', mode: 'fireteam_escalation' }, { kind: 'tool_confirmation', mode: 7 },
      { kind: 'tool_confirmation', mode: null },
    ]) {
      const res = await POST(req(check(over)))
      expect([JSON.stringify(over), res.status]).toEqual([JSON.stringify(over), 400])
    }
  })
})
