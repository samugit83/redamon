/**
 * The webapp gateway of the per-user Kali sandboxes (group 1, B.10, S13; T5, I9): which project
 * folders a person's sandbox mounts, who may have one, and the calls to the orchestrator and the
 * agent.
 *
 * The mount list is the person's own projects plus the projects shared with them whose effective
 * toggles (the owner's consent applied) hold Use AI agent or Exploitation & shells; under act-as only
 * what act-as access allows (the member's own projects). It is read fresh on every call and never
 * cached: a stop that lands between the webapp's read and the orchestrator's start is caught by the
 * re-check after a fresh start (R2-F7).
 *
 * Real authz (visibleProjects, projectAccess, the principal, capabilities, the sharing policy); Prisma
 * is the in-memory list double plus the rows projectAccess and loadPrincipal read; the orchestrator,
 * the agent and the audit writer are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/sandbox/gateway.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'

type Row = Record<string, unknown>
interface Call { method: string; path: string; body: unknown; opts: unknown; args: number }
type Handler = (body: unknown) => [number, unknown] | Promise<[number, unknown]>

const h = vi.hoisted(() => ({
  db: null as unknown,
  calls: [] as Call[],
  script: new Map<string, Handler>(),
  down: false,
  agentCalls: [] as Array<{ path: string; init: RequestInit }>,
  agentDown: false,
  writeAudit: vi.fn(async (_entry: Record<string, unknown>) => undefined),
  settingsUpdate: vi.fn(async (_args: unknown) => ({ count: 1 })),
  userReads: vi.fn(),
}))

vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: async (...a: unknown[]) => {
    const [url, init = {}, opts] = a as [string, RequestInit | undefined, unknown]
    const u = new URL(String(url))
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    h.calls.push({ method, path: u.pathname, body, opts, args: a.length })
    if (h.down) {
      throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }) })
    }
    const handler = h.script.get(`${method} ${u.pathname}`)
    const [status, data] = handler ? await handler(body) : [404, { detail: 'Not Found' }]
    return new Response(status === 204 ? null : JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } })
  },
}))
vi.mock('@/lib/agentFetch', async (orig) => {
  const real = await orig<typeof import('@/lib/agentFetch')>()
  return {
    ...real,
    agentFetch: async (path: string, init: RequestInit = {}) => {
      h.agentCalls.push({ path, init })
      if (h.agentDown) {
        throw new real.AgentUnreachableError(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }))
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 })
    },
  }
})
vi.mock('@/lib/audit', () => ({ writeAudit: (entry: Record<string, unknown>) => h.writeAudit(entry) }))
vi.mock('@/lib/prisma', () => ({
  default: new Proxy({}, { get: (_t, k) => (h.db as Record<string, unknown>)[k as string] }),
}))

import {
  assertSandboxUser, ensureSandbox, ensureStatus, leaseSandbox, listSandboxes, agentSandboxList, reconcileSandbox,
  releaseSandboxLease, resetSandboxGatewayForTests, sandboxMode, sandboxProjectsFor, sandboxStatus, stopAllSandboxes,
  stopProjectSandboxes, stopSandbox, touchSandbox,
} from './gateway'
import { SandboxError, PROJECT_ID_PATTERN, USER_ID_PATTERN, INSTANCE_PATTERN, RESERVED_USER_IDS } from './orchestratorClient'
import { dropSandboxClient, pushSandboxTunnel } from './agentCalls'
import { ORCHESTRATOR_ENSURE_TIMEOUT_S } from './contract'
import { emptyProjectListState, projectListPrisma, type ProjectListState } from '@/lib/authz/__testing__/projectListDb'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'

const TOKEN = 'per-instance-bearer-0123456789abcdef'
const TUNNEL = 'per-instance-tunnel-fedcba9876543210'
const INSTANCE = 'a1b2c3'
const PORTS = {
  network_recon: 8000, nuclei: 8002, metasploit: 8003, nmap: 8004, playwright: 8005,
  sessions: 8013, hydra: 8014, tunnel: 8015, terminal: 8016, ngrok_api: 4040,
}
const RAM = {
  admitted: false, limitType: 'ram', resource: 'kali_sandbox', current: 1, ceiling: 2,
  settingName: null, detail: 'not enough memory: 0.5 GB free, a sandbox needs 1.0 GB',
}
const WRITE_SHARING: Partial<RbacFlags> = { identity: true, permissions: true, sharing: true, sharingWrite: true }
const HOUR = 3_600_000

let state: ProjectListState

function account(id: string, over: Row = {}): Row {
  return {
    id, email: `${id}@example.test`, name: id, role: 'standard', password: 'hash', createdAt: new Date(0),
    legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, permissionSets: [], permissionOverrides: [], ...over,
  }
}
const project = (id: string, userId: string): Row => ({ id, userId, createdAt: new Date(0) })
function share(projectId: string, userId: string, over: Row = {}): Row {
  return {
    projectId, userId, access: 'write', rawData: false, expiresAt: null,
    runScans: false, useAgent: false, exploit: false, manage: false, ...over,
  }
}
const consent = (projectId: string): Row => ({ projectId, ownerCredentialConsentAt: new Date(0), ownerCredentialConsentById: 'carol' })
const user = (id: string) => state.users.find((u) => u.id === id)!
const setUser = (id: string, over: Row) => Object.assign(user(id), over)
const revoke = (projectId: string, userId: string) => {
  state.shares = state.shares.filter((s) => !(s.projectId === projectId && s.userId === userId))
}

function buildDb() {
  const list = projectListPrisma(state)
  return {
    ...list,
    project: {
      ...list.project,
      findUnique: async ({ where }: { where: { id: string } }) => {
        const row = state.projects.find((p) => p.id === where.id)
        return row ? { id: row.id, userId: row.userId } : null
      },
    },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
        const { projectId, userId } = where.projectId_userId
        const row = state.shares.find((s) => s.projectId === projectId && s.userId === userId)
        if (!row) return null
        const u = state.users.find((x) => x.id === userId)
        return { ...row, user: u ? { status: u.status } : null }
      },
    },
    projectBreakGlass: { findFirst: async () => null },
    projectAccessPolicy: {
      ...list.projectAccessPolicy,
      findUnique: async ({ where }: { where: { projectId: string } }) =>
        (state.consents ?? []).find((c) => c.projectId === where.projectId) ?? null,
    },
    user: {
      ...list.user,
      findUnique: async ({ where }: { where: { id: string } }) => {
        h.userReads(where.id)
        const row = state.users.find((u) => u.id === where.id)
        return row ? { ...row } : null
      },
    },
    instanceSettings: {
      findUnique: async () => ({
        id: 'instance', sharingPolicy: state.policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null,
      }),
    },
    permissionSet: { findMany: async () => [] },
    userSettings: { updateMany: (args: unknown) => h.settingsUpdate(args) },
  }
}

function running(body: Row, over: Row = {}): Row {
  return {
    mode: 'per_user', user_id: body.user_id, view: body.view, instance: INSTANCE,
    host: `redamon-kali-0123456789abcdef-${INSTANCE}`, token: TOKEN, tunnel_token: TUNNEL, ports: PORTS,
    reverse_port: 4444, projects: body.projects, state: 'running', fresh: false, stop_at: 1e10,
    stop_reason: null, warn: false, ...over,
  }
}
const on = (key: string, handler: Handler) => h.script.set(key, handler)
const callsTo = (method: string, p: string) => h.calls.filter((c) => c.method === method && c.path === p)
const ensures = () => callsTo('POST', '/sandboxes/ensure').map((c) => c.body as Row)
const audits = (action: string) => h.writeAudit.mock.calls.map((c) => c[0]).filter((e) => e.action === action)

async function refusal(p: Promise<unknown>): Promise<SandboxError> {
  try {
    await p
  } catch (err) {
    if (err instanceof SandboxError) return err
    throw err
  }
  throw new Error('expected a SandboxError, got an answer')
}

beforeEach(() => {
  state = emptyProjectListState()
  state.users = [
    account('alice'), account('bob'), account('carol'),
    account('analyst', { permissionSets: [{ setId: 'builtin:read-only-analyst' }] }),
  ]
  state.projects = [
    project('PA', 'alice'), project('PA2', 'alice'), project('PB', 'bob'),
    project('PC', 'carol'), project('PD', 'carol'), project('PE', 'carol'), project('PF', 'carol'),
    project('PG', 'carol'), project('PH', 'carol'),
  ]
  state.shares = [
    share('PC', 'bob', { useAgent: true }),
    share('PD', 'bob', { exploit: true }),
    share('PE', 'bob', { access: 'read', rawData: true }),
    share('PF', 'bob', { useAgent: true }),
    share('PG', 'bob', { useAgent: true, expiresAt: new Date(Date.now() - HOUR) }),
    share('PH', 'bob', { manage: true, runScans: true }),
  ]
  state.consents = [consent('PC'), consent('PD'), consent('PG'), consent('PH')]
  state.policy = { enabled: true, maxLevel: 'write' }
  h.db = buildDb()
  h.calls.length = 0
  h.script.clear()
  h.down = false
  h.agentCalls.length = 0
  h.agentDown = false
  h.writeAudit.mockClear()
  h.settingsUpdate.mockClear()
  h.userReads.mockClear()
  on('GET /sandboxes/mode', () => [200, { mode: 'per_user' }])
  on('POST /sandboxes/ensure', (b) => [200, running(b as Row)])
  setFlagsForTests(WRITE_SHARING)
  clearSharingPolicyCacheForTests()
  clearPrincipalCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  resetSandboxGatewayForTests()
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('the mount list (sandboxProjectsFor): from the authorization library only', () => {
  test('own projects plus shares whose effective toggles hold Use AI agent or Exploitation & shells', async () => {
    expect(await sandboxProjectsFor('bob')).toEqual(['PB', 'PC', 'PD'])
  })

  test('a read share, a share without the owner\'s consent, an expired share and a share with only Run scans / Manage are left out', async () => {
    const list = await sandboxProjectsFor('bob')
    for (const id of ['PE', 'PF', 'PG', 'PH']) expect([id, list.includes(id)]).toEqual([id, false])
  })

  test('sharing off, or Root\'s policy off: own projects only', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    expect(await sandboxProjectsFor('bob')).toEqual(['PB'])
    setFlagsForTests(WRITE_SHARING)
    state.policy = {}
    clearSharingPolicyCacheForTests()
    expect(await sandboxProjectsFor('bob')).toEqual(['PB'])
  })

  test('write sharing not in force: every share reads as Read, so own projects only', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect(await sandboxProjectsFor('bob')).toEqual(['PB'])
    setFlagsForTests(WRITE_SHARING)
    state.policy = { enabled: true, maxLevel: 'read' }
    clearSharingPolicyCacheForTests()
    expect(await sandboxProjectsFor('bob')).toEqual(['PB'])
  })

  test("another person's projects never: each person gets their own list", async () => {
    expect(await sandboxProjectsFor('alice')).toEqual(['PA', 'PA2'])
    expect(await sandboxProjectsFor('carol')).toEqual(['PC', 'PD', 'PE', 'PF', 'PG', 'PH'])
    expect(await sandboxProjectsFor('nobody')).toEqual([])
  })

  test('act-as: the member\'s own projects, no project shared with the member, never the admin\'s', async () => {
    state.users.push(account('admin-1', { role: 'admin' }))
    state.projects.push(project('PX', 'admin-1'))
    expect(await sandboxProjectsFor('bob', { actingAs: true })).toEqual(['PB'])
  })

  test('read fresh each time: a withdrawn consent and a revoked share count at once, with no cache to clear', async () => {
    expect(await sandboxProjectsFor('bob')).toEqual(['PB', 'PC', 'PD'])
    state.consents = state.consents!.filter((c) => c.projectId !== 'PC')
    revoke('PD', 'bob')
    expect(await sandboxProjectsFor('bob')).toEqual(['PB'])
  })

  test('a stored project id outside the contract\'s pattern is never sent', async () => {
    state.projects.push(project('bad.id', 'bob'), project('.staging', 'bob'))
    expect(await sandboxProjectsFor('bob')).toEqual(['PB', 'PC', 'PD'])
  })

  test('an invalid user id is refused before any read', async () => {
    for (const id of ['', '../alice', 'a/b', 'ensure', 'x'.repeat(65), 'bob\n']) {
      expect((await refusal(sandboxProjectsFor(id))).code).toBe('invalid_user_id')
    }
    expect(h.userReads).not.toHaveBeenCalled()
  })
})

describe('the person (assertSandboxUser): an active account holding one of the three permissions, read fresh', () => {
  test('a member with the agent permissions passes', async () => {
    await expect(assertSandboxUser('bob')).resolves.toBeUndefined()
  })

  test('a disabled, an invited and a missing account are refused', async () => {
    setUser('alice', { status: 'disabled' })
    setUser('carol', { status: 'invited' })
    for (const id of ['alice', 'carol', 'nobody']) {
      const err = await refusal(assertSandboxUser(id))
      expect([id, err.status, err.code]).toEqual([id, 403, 'sandbox_user_refused'])
    }
  })

  test('an account without agent:chat, agent:kali_exec or platform:kali_terminal is refused', async () => {
    expect((await refusal(assertSandboxUser('analyst'))).code).toBe('sandbox_user_refused')
  })

  test('any one of the three is enough', async () => {
    for (const permission of ['agent:chat', 'agent:kali_exec', 'platform:kali_terminal']) {
      setUser('analyst', { permissionOverrides: [{ permission, effect: 'grant', expiresAt: null, reason: 'test grant' }] })
      clearPrincipalCacheForTests()
      await expect(assertSandboxUser('analyst')).resolves.toBeUndefined()
    }
  })

  test('the account is read fresh: a disable counts at the next call, whatever this process holds', async () => {
    await assertSandboxUser('bob')
    setUser('bob', { status: 'disabled' })
    expect((await refusal(assertSandboxUser('bob'))).code).toBe('sandbox_user_refused')
  })
})

describe('ensureSandbox', () => {
  test('sends the person, the view, the fresh mount list and the project hint, with the long timeout when it waits', async () => {
    on('POST /sandboxes/ensure', (b) => [200, { ...running(b as Row), extra: 'never forwarded' }])
    const answer = await ensureSandbox('bob', { needProject: 'PC' })
    const [call] = callsTo('POST', '/sandboxes/ensure')
    expect(call.body).toEqual({ user_id: 'bob', view: 'own', projects: ['PB', 'PC', 'PD'], need_project: 'PC', wait: true, touch: false })
    expect(call.opts).toEqual({ timeoutMs: ORCHESTRATOR_ENSURE_TIMEOUT_S * 1000 })
    expect(answer).toEqual(running({ user_id: 'bob', view: 'own', projects: ['PB', 'PC', 'PD'] }))
    expect(ensureStatus(answer)).toBe(200)
  })

  test('a call that does not wait keeps the default timeout, and its 202 is answered as a 202', async () => {
    on('POST /sandboxes/ensure', () => [202, { mode: 'per_user', state: 'starting', instance: INSTANCE, fresh: false }])
    const answer = await ensureSandbox('bob', { wait: false })
    const [call] = callsTo('POST', '/sandboxes/ensure')
    expect(call.body).toMatchObject({ wait: false, touch: false, need_project: null })
    expect(call.opts).toBeUndefined()
    expect(answer).toEqual({ mode: 'per_user', state: 'starting', instance: INSTANCE, fresh: false })
    expect(ensureStatus(answer)).toBe(202)
  })

  test('act-as asks for the act_as view with the member\'s act-as list; a project shared with the member is refused there', async () => {
    await ensureSandbox('bob', { actingAs: true, needProject: 'PB' })
    expect(ensures()[0]).toMatchObject({ user_id: 'bob', view: 'act_as', projects: ['PB'] })
    const err = await refusal(ensureSandbox('bob', { actingAs: true, needProject: 'PC' }))
    expect([err.status, err.code]).toEqual([403, 'sandbox_project_refused'])
    expect(ensures()).toHaveLength(1)
  })

  test('the agent\'s project id is a hint, never a grant: outside the list is refused and never sent', async () => {
    for (const needProject of ['PA', 'PE', 'PF', 'missing']) {
      const err = await refusal(ensureSandbox('bob', { needProject }))
      expect([needProject, err.status, err.code]).toEqual([needProject, 403, 'sandbox_project_refused'])
    }
    expect(ensures()).toEqual([])
  })

  test('a refused person gets 403 sandbox_user_refused and nothing reaches the orchestrator\'s ensure', async () => {
    setUser('bob', { status: 'disabled' })
    const err = await refusal(ensureSandbox('bob'))
    expect([err.status, err.code]).toEqual([403, 'sandbox_user_refused'])
    expect(ensures()).toEqual([])
  })

  test('in per-user mode a refusal is a 403, never answered as shared', async () => {
    on('POST /sandboxes/ensure', () => [200, { mode: 'shared' }])
    setUser('bob', { status: 'disabled' })
    expect((await refusal(ensureSandbox('bob'))).code).toBe('sandbox_user_refused')
    expect((await refusal(ensureSandbox('carol', { needProject: 'PA' }))).code).toBe('sandbox_project_refused')
    expect((await refusal(ensureSandbox('analyst'))).code).toBe('sandbox_user_refused')
    expect(ensures()).toEqual([])
  })

  test('a fresh start on the own view turns the person\'s tunnels off and writes sandbox.started, once', async () => {
    on('POST /sandboxes/ensure', (b) => [200, running(b as Row, { fresh: true })])
    await ensureSandbox('bob')
    expect(h.settingsUpdate).toHaveBeenCalledTimes(1)
    expect(h.settingsUpdate).toHaveBeenCalledWith({ where: { userId: 'bob', tunnelsEnabled: true }, data: { tunnelsEnabled: false } })
    const [row] = audits('sandbox.started')
    expect(row).toMatchObject({
      actorId: 'bob', action: 'sandbox.started', targetType: 'user', targetId: 'bob',
      after: { view: 'own', instance: INSTANCE, projectsHash: 'f3ed1ec8bb40f7b4' },
    })
    expect(audits('sandbox.started')).toHaveLength(1)
  })

  test('the 202 of a fresh start does the same (the warm-up is often the call that starts it)', async () => {
    on('POST /sandboxes/ensure', () => [202, { mode: 'per_user', state: 'starting', instance: INSTANCE, fresh: true }])
    await ensureSandbox('bob', { wait: false })
    expect(h.settingsUpdate).toHaveBeenCalledTimes(1)
    expect(audits('sandbox.started')).toHaveLength(1)
  })

  test('the audit row holds no token and no project list', async () => {
    on('POST /sandboxes/ensure', (b) => [200, running(b as Row, { fresh: true })])
    await ensureSandbox('bob', { needProject: 'PC' })
    const text = JSON.stringify(h.writeAudit.mock.calls)
    for (const secret of [TOKEN, TUNNEL, 'PC', 'PD', '"PB"']) expect([secret, text.includes(secret)]).toEqual([secret, false])
  })

  test('a fresh act_as start is audited on behalf of the member, with the actor when given, and leaves the tunnels alone', async () => {
    on('POST /sandboxes/ensure', (b) => [200, running(b as Row, { fresh: true })])
    await ensureSandbox('bob', { actingAs: true })
    expect(h.settingsUpdate).not.toHaveBeenCalled()
    expect(audits('sandbox.started')[0]).toMatchObject({ actorId: null, onBehalfOfUserId: 'bob', after: { view: 'act_as', projectsHash: 'f9085bf3a4e33576' } })
    await ensureSandbox('bob', { actingAs: true, actor: { actorId: 'admin-1', onBehalfOfUserId: 'bob', actorEmail: 'admin-1@example.test' } })
    expect(audits('sandbox.started')[1]).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'bob', actorEmail: 'admin-1@example.test' })
  })

  test('an answer that is not fresh writes nothing', async () => {
    await ensureSandbox('bob')
    expect(h.settingsUpdate).not.toHaveBeenCalled()
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('a shared answer from the orchestrator answers shared and writes nothing', async () => {
    on('POST /sandboxes/ensure', () => [200, { mode: 'shared' }])
    expect(await ensureSandbox('bob')).toEqual({ mode: 'shared' })
    expect(h.writeAudit).not.toHaveBeenCalled()
    expect(h.settingsUpdate).not.toHaveBeenCalled()
  })

  test('a memory refusal is a 409 carrying the governor payload, wrapped or not', async () => {
    for (const body of [{ detail: { ...RAM, code: 'sandbox_ram' } }, { ...RAM, code: 'sandbox_ram' }]) {
      on('POST /sandboxes/ensure', () => [409, body])
      const err = await refusal(ensureSandbox('bob'))
      expect([err.status, err.code, err.limit]).toEqual([409, 'sandbox_ram', RAM])
    }
  })

  test('the contract\'s error codes keep their status; anything else is a 503 orchestrator_unavailable', async () => {
    const cases: Array<[number, unknown, number, string]> = [
      [400, { detail: { code: 'invalid_project_id' } }, 400, 'invalid_project_id'],
      [503, { detail: { code: 'sandbox_image_missing' } }, 503, 'sandbox_image_missing'],
      [503, { code: 'sandbox_start_failed' }, 503, 'sandbox_start_failed'],
      [504, { detail: { code: 'sandbox_start_timeout' } }, 504, 'sandbox_start_timeout'],
      [500, { detail: 'Traceback with a token in it' }, 503, 'orchestrator_unavailable'],
      [401, { detail: 'Unauthorized' }, 503, 'orchestrator_unavailable'],
      [409, { detail: 'busy' }, 503, 'orchestrator_unavailable'],
      [404, { detail: 'Not Found' }, 503, 'orchestrator_unavailable'],
    ]
    for (const [status, body, want, code] of cases) {
      on('POST /sandboxes/ensure', () => [status, body])
      const err = await refusal(ensureSandbox('bob'))
      expect([status, err.status, err.code]).toEqual([status, want, code])
      expect(err.message).not.toContain('token')
    }
  })

  test('a malformed answer is a 503 orchestrator_unavailable, never handed on', async () => {
    for (const bad of [
      { mode: 'per_user', state: 'running', instance: INSTANCE, fresh: false },
      { mode: 'per_user', state: 'starting', instance: '../x', fresh: true },
      { mode: 'per_user', state: 'running', instance: INSTANCE, token: TOKEN, fresh: 'yes' },
      { mode: 'whatever' },
      ['not', 'an', 'object'],
    ]) {
      on('POST /sandboxes/ensure', () => [200, bad])
      const err = await refusal(ensureSandbox('bob'))
      expect([err.status, err.code]).toEqual([503, 'orchestrator_unavailable'])
    }
  })

  test('invalid ids are 400s and reach nothing', async () => {
    expect((await refusal(ensureSandbox('../bob'))).code).toBe('invalid_user_id')
    expect((await refusal(ensureSandbox('stop-all'))).code).toBe('invalid_user_id')
    for (const needProject of ['..', '.staging', 'a/b', 'CON', 'x'.repeat(65)]) {
      expect((await refusal(ensureSandbox('bob', { needProject }))).code).toBe('invalid_project_id')
    }
    expect(h.calls).toEqual([])
    expect(h.userReads).not.toHaveBeenCalled()
  })
})

describe('shared mode answers before the person checks, as today; per-user mode refuses', () => {
  const sharedMode = () => on('GET /sandboxes/mode', () => [200, { mode: 'shared' }])

  test('shared mode + a person without agent:chat, agent:kali_exec or platform:kali_terminal: shared, nothing read', async () => {
    sharedMode()
    setUser('carol', { permissionSets: [{ setId: 'builtin:automation' }] })
    expect(await ensureSandbox('analyst')).toEqual({ mode: 'shared' })
    expect(await ensureSandbox('carol', { needProject: 'PC' })).toEqual({ mode: 'shared' })
    expect(h.userReads).not.toHaveBeenCalled()
    expect(ensures()).toEqual([])
  })

  test('shared mode + a project outside the list (a read share, another tenant\'s, act-as on a share): shared', async () => {
    sharedMode()
    for (const [needProject, actingAs] of [['PE', false], ['PA', false], ['PC', true]] as Array<[string, boolean]>) {
      expect([needProject, await ensureSandbox('bob', { needProject, actingAs })]).toEqual([needProject, { mode: 'shared' }])
    }
  })

  test('per-user mode + the same: 403 with the contract\'s codes, the orchestrator\'s ensure never asked', async () => {
    setUser('carol', { permissionSets: [{ setId: 'builtin:automation' }] })
    expect((await refusal(ensureSandbox('analyst'))).code).toBe('sandbox_user_refused')
    expect((await refusal(ensureSandbox('carol', { needProject: 'PC' }))).code).toBe('sandbox_user_refused')
    for (const [needProject, actingAs] of [['PE', false], ['PA', false], ['PC', true]] as Array<[string, boolean]>) {
      const err = await refusal(ensureSandbox('bob', { needProject, actingAs }))
      expect([needProject, err.status, err.code]).toEqual([needProject, 403, 'sandbox_project_refused'])
    }
    expect(ensures()).toEqual([])
  })

  test('an outage: 503 orchestrator_unavailable, never an invented mode', async () => {
    h.down = true
    for (const userId of ['analyst', 'bob']) {
      const err = await refusal(ensureSandbox(userId, { needProject: 'PA' }))
      expect([userId, err.status, err.code]).toEqual([userId, 503, 'orchestrator_unavailable'])
    }
  })

  test('the mode is asked fresh in every call: a switch between two calls counts at once', async () => {
    sharedMode()
    expect(await ensureSandbox('analyst')).toEqual({ mode: 'shared' })
    on('GET /sandboxes/mode', () => [200, { mode: 'per_user' }])
    expect((await refusal(ensureSandbox('analyst'))).code).toBe('sandbox_user_refused')
    expect(callsTo('GET', '/sandboxes/mode')).toHaveLength(2)
  })

  test('invalid ids are still 400s before the mode is asked', async () => {
    sharedMode()
    expect((await refusal(ensureSandbox('../bob'))).code).toBe('invalid_user_id')
    expect((await refusal(ensureSandbox('bob', { needProject: '..' }))).code).toBe('invalid_project_id')
    expect(h.calls).toEqual([])
  })
})

describe('the orchestrator down: the webapp never invents a mode (the agent decides from its own last answer)', () => {
  const seen = async (mode: 'shared' | 'per_user') => {
    on('GET /sandboxes/mode', () => [200, { mode }])
    expect(await sandboxMode({ fresh: true })).toBe(mode)
  }
  const unavailable = async (p: Promise<unknown>) => {
    const err = await refusal(p)
    expect([err.status, err.code, err.limit]).toEqual([503, 'orchestrator_unavailable', null])
  }

  test('no mode seen since the webapp started + an outage: 503 orchestrator_unavailable, never shared', async () => {
    h.down = true
    await unavailable(ensureSandbox('bob'))
  })

  test('per-user mode seen + an outage: 503', async () => {
    await seen('per_user')
    h.down = true
    await unavailable(ensureSandbox('bob'))
  })

  test('shared mode seen + an outage: 503 too, the agent keeps shared from its own memory', async () => {
    await seen('shared')
    h.down = true
    await unavailable(ensureSandbox('bob'))
    on('POST /sandboxes/ensure', () => [200, { mode: 'shared' }])
    h.down = false
    await ensureSandbox('bob')
    h.down = true
    await unavailable(ensureSandbox('bob'))
  })

  test('a refused account or a project outside the list + an outage: 503 too, whatever mode was seen (the mode comes first)', async () => {
    setUser('carol', { status: 'disabled' })
    h.down = true
    for (const mode of [null, 'shared', 'per_user'] as const) {
      if (mode) {
        h.down = false
        await seen(mode)
        h.down = true
      }
      await unavailable(ensureSandbox('carol'))
      await unavailable(ensureSandbox('bob', { needProject: 'PA' }))
    }
    expect(ensures()).toEqual([])
  })

  test('a server error, a refused orchestrator key, a missing mode route or any coded error from the mode route is not an answer: 503, never shared', async () => {
    // The mode route answers only 200 {mode} (B.9): a contract code there is another route's answer
    // (e.g. GET /sandboxes/{user_id} registered first, which refuses "mode" as a user id).
    for (const [status, body] of [
      [500, { detail: 'Internal Server Error' }], [401, { detail: 'Unauthorized' }], [404, { detail: 'Not Found' }],
      [403, { detail: { code: 'sandbox_user_refused' } }], [409, { detail: { ...RAM, code: 'sandbox_ram' } }],
      [503, { detail: { code: 'sandbox_start_failed' } }], [400, { detail: { code: 'invalid_user_id' } }],
      [404, { detail: { code: 'unknown_instance' } }],
    ] as Array<[number, unknown]>) {
      on('GET /sandboxes/mode', () => [status, body])
      await unavailable(ensureSandbox('bob'))
      await unavailable(ensureSandbox('bob', { needProject: 'PA' }))
    }
    expect(ensures()).toEqual([])
  })

  test('an outage inside the re-check after a fresh start is 503 too', async () => {
    on('POST /sandboxes/ensure', (b) => {
      setUser('bob', { status: 'disabled' })
      h.down = true
      return [200, running(b as Row, { fresh: true })]
    })
    await unavailable(ensureSandbox('bob'))
  })

  test('the internal route answers the agent 503 orchestrator_unavailable, with no detail and no mode', async () => {
    vi.stubEnv('INTERNAL_API_KEY', 'k'.repeat(40))
    const { POST } = await import('@/app/api/internal/agent/sandbox/ensure/route')
    const { NextRequest } = await import('next/server')
    const ask = async (body: unknown) => {
      const res = await POST(new NextRequest('http://localhost/api/internal/agent/sandbox/ensure', {
        method: 'POST', headers: { 'x-internal-key': 'k'.repeat(40), 'content-type': 'application/json' }, body: JSON.stringify(body),
      }))
      return [res.status, await res.json()] as const
    }
    h.down = true
    expect(await ask({ userId: 'bob' })).toEqual([503, { error: expect.any(String), code: 'orchestrator_unavailable' }])
    expect(await ask({ userId: 'bob', projectId: 'PA' })).toEqual([503, { error: expect.any(String), code: 'orchestrator_unavailable' }])
    h.down = false
    expect(await ask({ userId: 'bob', projectId: 'PA' })).toEqual([403, { error: expect.any(String), code: 'sandbox_project_refused' }])
    on('GET /sandboxes/mode', () => [200, { mode: 'shared' }])
    expect(await ask({ userId: 'bob', projectId: 'PA' })).toEqual([200, { mode: 'shared' }])
    vi.unstubAllEnvs()
  })

  test('a mode guessed from a missing route is shown to people but never becomes the mode last named', async () => {
    await seen('per_user')
    h.script.delete('GET /sandboxes/mode')
    expect(await sandboxMode({ fresh: true })).toBe('shared')
    const asked = callsTo('GET', '/sandboxes/mode').length
    await touchSandbox('bob')
    // The warm-up still runs (per-user mode is the last named), and its ensure answers 503 for the missing route.
    expect(callsTo('GET', '/sandboxes/mode').length).toBe(asked + 1)
  })
})

describe('a stop overtaken by an ensure in flight (R2-F7): the access is re-read after a fresh start', () => {
  test('no mount list is kept between calls: a revoke between two calls changes the next body', async () => {
    await ensureSandbox('bob')
    revoke('PC', 'bob')
    await ensureSandbox('bob')
    expect(ensures().map((b) => b.projects)).toEqual([['PB', 'PC', 'PD'], ['PB', 'PD']])
  })

  test('a share revoked while the start was in flight: the stale instance is reconciled away and the start retried on the fresh list', async () => {
    on('POST /sandboxes/bob/reconcile', () => [200, { stopped: 1 }])
    let first = true
    on('POST /sandboxes/ensure', (b) => {
      if (first) revoke('PC', 'bob')
      first = false
      return [200, running(b as Row, { fresh: true })]
    })
    const answer = await ensureSandbox('bob')
    expect(callsTo('POST', '/sandboxes/bob/reconcile').map((c) => c.body)).toEqual([{ projects: ['PB', 'PD'], act_as_projects: ['PB'] }])
    expect(ensures().map((b) => b.projects)).toEqual([['PB', 'PC', 'PD'], ['PB', 'PD']])
    expect(answer).toMatchObject({ projects: ['PB', 'PD'] })
    expect(audits('sandbox.stopped')[0]).toMatchObject({ targetId: 'bob', after: { reason: 'access_lost', stopped: 1 } })
  })

  test('the project the call needs was the one revoked: reconciled, then refused, not retried', async () => {
    on('POST /sandboxes/bob/reconcile', () => [200, { stopped: 1 }])
    on('POST /sandboxes/ensure', (b) => {
      revoke('PC', 'bob')
      return [200, running(b as Row, { fresh: true })]
    })
    const err = await refusal(ensureSandbox('bob', { needProject: 'PC' }))
    expect([err.status, err.code]).toEqual([403, 'sandbox_project_refused'])
    expect(ensures()).toHaveLength(1)
    expect(callsTo('POST', '/sandboxes/bob/reconcile')).toHaveLength(1)
  })

  test('the account disabled while the start was in flight: the person\'s sandboxes are stopped and the call refused', async () => {
    on('POST /sandboxes/bob/stop', () => [200, { stopped: 1 }])
    on('POST /sandboxes/ensure', (b) => {
      setUser('bob', { status: 'disabled' })
      return [200, running(b as Row, { fresh: true })]
    })
    const err = await refusal(ensureSandbox('bob'))
    expect([err.status, err.code]).toEqual([403, 'sandbox_user_refused'])
    expect(callsTo('POST', '/sandboxes/bob/stop').map((c) => c.body)).toEqual([{ reason: 'account_disabled' }])
    expect(h.agentCalls.map((c) => c.path)).toEqual(['/sandboxes/bob/drop'])
  })

  test('the account deleted while the start was in flight: stopped as deleted', async () => {
    on('POST /sandboxes/bob/stop', () => [200, { stopped: 1 }])
    on('POST /sandboxes/ensure', (b) => {
      state.users = state.users.filter((u) => u.id !== 'bob')
      return [200, running(b as Row, { fresh: true })]
    })
    await refusal(ensureSandbox('bob'))
    expect(callsTo('POST', '/sandboxes/bob/stop').map((c) => c.body)).toEqual([{ reason: 'account_deleted' }])
  })

  test('bounded: access that keeps changing under every start fails with sandbox_start_failed after the retry', async () => {
    on('POST /sandboxes/bob/reconcile', () => [200, { stopped: 1 }])
    const order = ['PC', 'PD']
    on('POST /sandboxes/ensure', (b) => {
      const next = order.shift()
      if (next) revoke(next, 'bob')
      return [200, running(b as Row, { fresh: true })]
    })
    const err = await refusal(ensureSandbox('bob'))
    expect([err.status, err.code]).toEqual([503, 'sandbox_start_failed'])
    expect(ensures()).toHaveLength(2)
  })

  test('a call that reuses a running instance (not fresh) is not re-checked: the orchestrator already stopped every instance outside the list', async () => {
    await ensureSandbox('bob')
    expect(h.userReads).toHaveBeenCalledTimes(1)
  })
})

describe('touchSandbox (the warm-up): never throws, never waits, quiet until per-user mode is known', () => {
  test('mode not seen yet: nothing is read and nothing is called', async () => {
    await touchSandbox('bob')
    expect(h.calls).toEqual([])
    expect(h.userReads).not.toHaveBeenCalled()
  })

  test('shared mode seen: nothing is started', async () => {
    on('GET /sandboxes/mode', () => [200, { mode: 'shared' }])
    await sandboxMode()
    h.calls.length = 0
    await touchSandbox('bob')
    expect(h.calls).toEqual([])
  })

  test('per-user mode seen: an ensure that does not wait, marked touch, with the default timeout', async () => {
    await sandboxMode()
    on('POST /sandboxes/ensure', () => [202, { mode: 'per_user', state: 'starting', instance: INSTANCE, fresh: true }])
    await touchSandbox('bob', { actingAs: true })
    const [call] = callsTo('POST', '/sandboxes/ensure')
    expect(call.body).toEqual({ user_id: 'bob', view: 'act_as', projects: ['PB'], need_project: null, wait: false, touch: true })
    expect(call.opts).toBeUndefined()
  })

  test('a mode seen in an ensure answer counts too', async () => {
    await ensureSandbox('bob')
    await touchSandbox('carol')
    expect(ensures().map((b) => b.user_id)).toEqual(['bob', 'carol'])
  })

  test('a refusal, an orchestrator error and an unreachable orchestrator are swallowed and logged without a token', async () => {
    await sandboxMode()
    setUser('bob', { status: 'disabled' })
    await expect(touchSandbox('bob')).resolves.toBeUndefined()
    setUser('bob', { status: 'active' })
    on('POST /sandboxes/ensure', () => [409, { detail: { ...RAM, code: 'sandbox_ram' } }])
    await expect(touchSandbox('bob')).resolves.toBeUndefined()
    h.down = true
    await expect(touchSandbox('bob')).resolves.toBeUndefined()
    await expect(touchSandbox('../bad')).resolves.toBeUndefined()
    const logged = JSON.stringify(vi.mocked(console.warn).mock.calls)
    expect(logged).toContain('sandbox_user_refused')
    expect(logged).not.toContain(TOKEN)
  })
})

describe('stops: orchestrator, then the agent\'s client, then one audit row', () => {
  const ADMIN = { actorId: 'admin-1', onBehalfOfUserId: null, actorEmail: 'admin-1@example.test' }

  test('stopSandbox stops both views, drops the agent\'s clients and audits the count with the actor', async () => {
    on('POST /sandboxes/bob/stop', () => [200, { stopped: 2 }])
    expect(await stopSandbox('bob', 'operator', ADMIN)).toBe(2)
    expect(callsTo('POST', '/sandboxes/bob/stop').map((c) => c.body)).toEqual([{ reason: 'operator' }])
    expect(callsTo('POST', '/sandboxes/bob/stop')[0].args).toBe(2)
    expect(h.agentCalls.map((c) => [c.path, c.init.method])).toEqual([['/sandboxes/bob/drop', 'POST']])
    expect(audits('sandbox.stopped')).toEqual([expect.objectContaining({
      ...ADMIN, targetType: 'user', targetId: 'bob', after: { reason: 'operator', stopped: 2 },
    })])
  })

  test('nothing stopped: no drop and no row', async () => {
    on('POST /sandboxes/bob/stop', () => [200, { stopped: 0 }])
    expect(await stopSandbox('bob', 'access_lost', null)).toBe(0)
    expect(h.agentCalls).toEqual([])
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('an agent that cannot be reached does not undo the stop', async () => {
    on('POST /sandboxes/bob/stop', () => [200, { stopped: 1 }])
    h.agentDown = true
    expect(await stopSandbox('bob', 'account_disabled', null)).toBe(1)
    expect(audits('sandbox.stopped')).toHaveLength(1)
  })

  test('an unknown reason or user id reaches nothing', async () => {
    expect((await refusal(stopSandbox('bob', 'because' as never, null))).code).toBe('invalid_reason')
    expect((await refusal(stopSandbox('../bob', 'operator', null))).code).toBe('invalid_user_id')
    expect(h.calls).toEqual([])
  })

  test('stopAllSandboxes stops every sandbox and drops each person\'s clients', async () => {
    on('GET /sandboxes', () => [200, { mode: 'per_user', sandboxes: [
      { user_id: 'bob', view: 'own', instance: INSTANCE, host: 'h', token: TOKEN, state: 'running' },
      { user_id: 'bob', view: 'act_as', instance: 'b2c3d4', host: 'h', token: TOKEN, state: 'running' },
      { user_id: 'carol', view: 'own', instance: 'c3d4e5', host: 'h', token: TOKEN, state: 'running' },
    ] }])
    on('POST /sandboxes/stop-all', () => [200, { stopped: 3 }])
    expect(await stopAllSandboxes('emergency', ADMIN)).toBe(3)
    expect(callsTo('POST', '/sandboxes/stop-all').map((c) => c.body)).toEqual([{ reason: 'emergency' }])
    expect(h.agentCalls.map((c) => c.path).sort()).toEqual(['/sandboxes/bob/drop', '/sandboxes/carol/drop'])
    expect(audits('sandbox.stopped')[0]).toMatchObject({ ...ADMIN, targetType: 'instance', after: { reason: 'emergency', stopped: 3 } })
  })

  test('stopProjectSandboxes calls stop-project and returns the outcome; it never throws', async () => {
    on('POST /sandboxes/stop-project', () => [200, { stopped: 1 }])
    expect(await stopProjectSandboxes('PC', 'project_deleted', ADMIN)).toEqual({ ok: true, stopped: 1 })
    expect(callsTo('POST', '/sandboxes/stop-project').map((c) => c.body)).toEqual([{ project_id: 'PC', reason: 'project_deleted' }])
    expect(audits('sandbox.stopped')[0]).toMatchObject({ targetType: 'project', targetId: 'PC', projectId: 'PC', after: { reason: 'project_deleted', stopped: 1 } })
    h.down = true
    expect(await stopProjectSandboxes('PC', 'project_deleted', ADMIN)).toEqual({ ok: false, code: 'orchestrator_unreachable' })
    h.down = false
    on('POST /sandboxes/stop-project', () => [500, { detail: 'boom' }])
    expect(await stopProjectSandboxes('PC', 'project_deleted', ADMIN)).toEqual({ ok: false, code: 'orchestrator_error' })
    expect(await stopProjectSandboxes('../PC', 'project_deleted', ADMIN)).toEqual({ ok: false, code: 'invalid_project_id' })
  })

  test('an orchestrator without the sandbox routes has nothing to stop', async () => {
    expect(await stopSandbox('bob', 'operator', null)).toBe(0)
    expect(await stopAllSandboxes('emergency', null)).toBe(0)
    expect(await stopProjectSandboxes('PC', 'project_deleted', null)).toEqual({ ok: true, stopped: 0 })
  })
})

describe('reconcileSandbox: both lists, best effort, for each person', () => {
  test('sends the own and act-as lists, audits what stopped, goes on past a failure', async () => {
    on('POST /sandboxes/bob/reconcile', () => [200, { stopped: 1 }])
    on('POST /sandboxes/alice/reconcile', () => [500, { detail: 'boom' }])
    on('POST /sandboxes/carol/reconcile', () => [200, { stopped: 0 }])
    expect(await reconcileSandbox(['bob', 'alice', '../bad', 'carol'])).toBe(1)
    expect(callsTo('POST', '/sandboxes/bob/reconcile')[0].body).toEqual({ projects: ['PB', 'PC', 'PD'], act_as_projects: ['PB'] })
    expect(callsTo('POST', '/sandboxes/alice/reconcile')[0].body).toEqual({ projects: ['PA', 'PA2'], act_as_projects: ['PA', 'PA2'] })
    expect(callsTo('POST', '/sandboxes/carol/reconcile')).toHaveLength(1)
    expect(audits('sandbox.stopped')).toEqual([expect.objectContaining({ targetId: 'bob', after: { reason: 'access_lost', stopped: 1 } })])
  })

  test('never throws, even with the orchestrator down', async () => {
    h.down = true
    expect(await reconcileSandbox(['bob'])).toBe(0)
  })
})

describe('reads: status, mode, lists, leases', () => {
  test('sandboxStatus keeps the contract\'s fields only (no token)', async () => {
    on('GET /sandboxes/bob', () => [200, { mode: 'per_user', instances: [{
      instance: INSTANCE, view: 'own', state: 'running', projects_hash: 'f3ed1ec8bb40f7b4', created_at: 1, last_used: 2,
      lease_kinds: ['run'], stop_at: 3, stop_reason: null, warn: false, reverse_port: 4444, token: TOKEN, host: 'h',
    }] }])
    const status = await sandboxStatus('bob')
    expect(status).toEqual({ mode: 'per_user', instances: [{
      instance: INSTANCE, view: 'own', state: 'running', projects_hash: 'f3ed1ec8bb40f7b4', created_at: 1, last_used: 2,
      lease_kinds: ['run'], stop_at: 3, stop_reason: null, warn: false, reverse_port: 4444,
    }] })
  })

  test('sandboxMode is cached 30 s; fresh reads again; a missing route is shared', async () => {
    expect(await sandboxMode()).toBe('per_user')
    expect(await sandboxMode()).toBe('per_user')
    expect(callsTo('GET', '/sandboxes/mode')).toHaveLength(1)
    on('GET /sandboxes/mode', () => [200, { mode: 'shared' }])
    expect(await sandboxMode({ fresh: true })).toBe('shared')
    h.script.delete('GET /sandboxes/mode')
    expect(await sandboxMode({ fresh: true })).toBe('shared')
  })

  test('listSandboxes (the Operations view) never carries a token or a host', async () => {
    on('GET /sandboxes', () => [200, { mode: 'per_user', sandboxes: [
      { user_id: 'bob', view: 'own', instance: INSTANCE, host: 'redamon-kali-x', token: TOKEN, state: 'running' },
    ] }])
    on('GET /sandboxes/bob', () => [200, { mode: 'per_user', instances: [{
      instance: INSTANCE, view: 'own', state: 'running', projects_hash: 'f3ed1ec8bb40f7b4', created_at: 1, last_used: 2,
      lease_kinds: [], stop_at: 3, stop_reason: null, warn: false, reverse_port: 4444,
    }] }])
    const list = await listSandboxes()
    expect(list).toEqual({ mode: 'per_user', sandboxes: [{
      user_id: 'bob', view: 'own', instance: INSTANCE, state: 'running', projects_hash: 'f3ed1ec8bb40f7b4',
      created_at: 1, last_used: 2, stop_at: 3,
    }] })
    expect(JSON.stringify(list)).not.toContain(TOKEN)
    expect(JSON.stringify(list)).not.toContain('redamon-kali-x')
  })

  test('the agent\'s list keeps the hosts and tokens it needs, and only the contract\'s fields', async () => {
    on('GET /sandboxes', () => [200, { mode: 'per_user', sandboxes: [
      { user_id: 'bob', view: 'own', instance: INSTANCE, host: 'redamon-kali-x', token: TOKEN, state: 'running', extra: 1 },
    ] }])
    expect(await agentSandboxList()).toEqual({ mode: 'per_user', sandboxes: [
      { user_id: 'bob', view: 'own', instance: INSTANCE, host: 'redamon-kali-x', token: TOKEN, state: 'running' },
    ] })
  })

  test('an orchestrator without the routes: people see no sandbox; the agent\'s list is 503, never a guessed mode', async () => {
    expect(await sandboxStatus('bob')).toEqual({ mode: 'shared', instances: [] })
    expect(await listSandboxes()).toEqual({ mode: 'shared', sandboxes: [] })
    const err = await refusal(agentSandboxList())
    expect([err.status, err.code]).toEqual([503, 'orchestrator_unavailable'])
    await touchSandbox('bob')
    expect(ensures()).toEqual([])
  })

  test('a lease re-checks the person, then takes or renews it at the orchestrator', async () => {
    const LEASE = '0b9d7a52-5d0f-4b6f-9a39-6a1d2a0a7f10'
    on('POST /sandboxes/bob/leases', () => [200, { expires_at: 10, state: 'running', stop_at: 20, warn: false }])
    expect(await leaseSandbox('bob', { instance: INSTANCE, leaseId: LEASE, kind: 'run' }))
      .toEqual({ expires_at: 10, state: 'running', stop_at: 20, warn: false })
    expect(callsTo('POST', '/sandboxes/bob/leases')[0].body).toEqual({ instance: INSTANCE, lease_id: LEASE, kind: 'run' })
    on('POST /sandboxes/bob/leases', () => [409, { detail: { code: 'sandbox_not_running' } }])
    expect((await refusal(leaseSandbox('bob', { instance: INSTANCE, leaseId: LEASE, kind: 'run' }))).code).toBe('sandbox_not_running')
    setUser('bob', { status: 'disabled' })
    h.calls.length = 0
    expect((await refusal(leaseSandbox('bob', { instance: INSTANCE, leaseId: LEASE, kind: 'hold' }))).code).toBe('sandbox_user_refused')
    expect(h.calls).toEqual([])
  })

  test('a release goes to the orchestrator without a re-check (releasing is always allowed)', async () => {
    const LEASE = '0b9d7a52-5d0f-4b6f-9a39-6a1d2a0a7f10'
    on(`DELETE /sandboxes/bob/leases/${LEASE}`, () => [204, null])
    setUser('bob', { status: 'disabled' })
    await expect(releaseSandboxLease('bob', LEASE)).resolves.toBeUndefined()
    expect(callsTo('DELETE', `/sandboxes/bob/leases/${LEASE}`)).toHaveLength(1)
  })
})

describe('agentCalls: the agent\'s drop and tunnel routes, with the master key', () => {
  test('drop and tunnel reach the agent routes of the contract', async () => {
    expect(await dropSandboxClient('bob')).toEqual({ ok: true, status: 200 })
    const config = { ngrokAuthtoken: 'ngrok-secret-value', chiselServerUrl: null, chiselAuth: null }
    expect(await pushSandboxTunnel('bob', config)).toEqual({ ok: true, status: 200 })
    expect(h.agentCalls.map((c) => [c.path, c.init.method])).toEqual([['/sandboxes/bob/drop', 'POST'], ['/sandboxes/bob/tunnel', 'POST']])
    expect(JSON.parse(String(h.agentCalls[1].init.body))).toEqual(config)
  })

  test('an invalid user id reaches nothing; an agent down is an answer, not a throw, and the config is never logged', async () => {
    expect(await dropSandboxClient('../bob')).toEqual({ ok: false, status: 0, code: 'invalid_user_id' })
    expect(h.agentCalls).toEqual([])
    h.agentDown = true
    const res = await pushSandboxTunnel('bob', { ngrokAuthtoken: 'ngrok-secret-value', chiselServerUrl: null, chiselAuth: null })
    expect(res).toEqual({ ok: false, status: 0, code: 'agent_unreachable' })
    const logged = JSON.stringify([vi.mocked(console.warn).mock.calls, vi.mocked(console.error).mock.calls])
    expect(logged).not.toContain('ngrok-secret-value')
  })
})

describe('the id patterns are the contract\'s (recon_orchestrator/sandbox_contract.py)', () => {
  const py = readFileSync(path.resolve(__dirname, '../../../../recon_orchestrator/sandbox_contract.py'), 'utf8')
  const pyConst = (name: string) => {
    const m = py.match(new RegExp(`^${name} = r"([^"]+)"$`, 'm'))
    if (!m) throw new Error(`${name} not found in the Python contract`)
    return m[1]
  }

  test('USER_ID_RE, PROJECT_ID_RE and INSTANCE_RE match byte for byte', () => {
    expect(USER_ID_PATTERN.source).toBe(pyConst('USER_ID_RE'))
    expect(PROJECT_ID_PATTERN.source).toBe(pyConst('PROJECT_ID_RE'))
    expect(INSTANCE_PATTERN.source).toBe(pyConst('INSTANCE_RE'))
    for (const re of [USER_ID_PATTERN, PROJECT_ID_PATTERN, INSTANCE_PATTERN]) expect(re.flags).toBe('')
  })

  test('RESERVED_USER_IDS match', () => {
    const m = py.match(/^RESERVED_USER_IDS = \(([^)]*)\)$/m)
    expect(m).not.toBeNull()
    expect([...RESERVED_USER_IDS]).toEqual([...m![1].matchAll(/"([^"]+)"/g)].map((x) => x[1]))
  })
})
