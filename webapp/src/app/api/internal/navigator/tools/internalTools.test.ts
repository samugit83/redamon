/**
 * The AI Navigator tool callbacks (plan §7.7, §10.2 rows 5, 6, 9, 10, 11, 12, 13, 26, 29): the master key, a
 * live run's credential, every id from the run entry (never the body), and the fresh checks: the
 * person and the acting admin, every permission with the act-as intersection, the level, the owner's
 * policy, Root's switch, the tenant unchanged and the login still alive. A refusal is audited.
 *
 * can(), projectAccess, the principals and the tool handler are doubles; the routes, the registry,
 * the credential and the decision logic are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  principals: new Map<string, { id: string; status: string; sessionVersion: number; role: string }>(),
  access: null as null | { project: { id: string; userId: string }; level: string; toggles: { rawData: boolean }; via: string },
  denied: new Set<string>(),
  canCalls: [] as Array<{ who: string; permission: string; actingAs: string | null; projectId: string }>,
  enabled: true,
  allowed: true,
  audits: [] as Array<Record<string, unknown>>,
  handled: [] as Array<{ projectId: string; tenantId: string; scopes: string[]; actingAs: boolean }>,
  actAsInForce: true,
  deviceRefusal: null as string | null,
  accessOpts: [] as unknown[],
  accessSubjects: [] as string[],
  execCalls: [] as Array<{ userId: string; projectId: string; cypher: string }>,
  execResult: { records: [] } as { records: unknown[] },
}))

vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: async () => ({ roeSensitiveDataHandling: 'no_access' }) } } }))
vi.mock('@/lib/authz/principal', () => ({ loadPrincipal: async (id: string) => h.principals.get(id) ?? null }))
vi.mock('@/lib/authz/flags', async (orig) => ({ ...(await orig<typeof import('@/lib/authz/flags')>()), rbacFlags: () => ({ identity: true }) }))
vi.mock('@/lib/authz/can', () => ({
  ActAsNotAllowedError: class extends Error {},
  can: async (who: { id: string }, permission: string, opts: { projectId: string; actingAs?: { id: string } }) => {
    h.canCalls.push({ who: who.id, permission, actingAs: opts.actingAs?.id ?? null, projectId: opts.projectId })
    return h.denied.has(permission)
      ? { allowed: false, status: 403, reason: 'capability', permission }
      : { allowed: true, permission, capabilities: new Set(), access: h.access }
  },
}))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async (s: { userId?: string; id?: string }, _p: string, opts: unknown) => {
    h.accessSubjects.push(s.userId ?? s.id ?? '')
    h.accessOpts.push(opts)
    return h.access
  },
}))
vi.mock('@/lib/navigator/switch', () => ({ navigatorEnabled: async () => h.enabled }))
vi.mock('@/lib/authz/navigatorPolicy', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/navigatorPolicy')>()),
  navigatorAllowedFor: async () => h.allowed,
}))
vi.mock('@/lib/authz/deviceSessions', () => ({ deviceSessionRefusal: async () => h.deviceRefusal }))
vi.mock('@/lib/authz/actAs', () => ({ actAsBindingInForce: async () => h.actAsInForce }))
vi.mock('@/lib/activationLock', () => ({ activationBusy: async () => false }))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => { h.audits.push(e) } }))
vi.mock('@/lib/mcp/graphClient', async (orig) => ({
  ...(await orig<typeof import('@/lib/mcp/graphClient')>()),
  execCypher: async (userId: string, projectId: string, cypher: string) => {
    h.execCalls.push({ userId, projectId, cypher })
    return h.execResult
  },
}))
vi.mock('@/lib/mcp/tools', async (orig) => ({
  ...(await orig<typeof import('@/lib/mcp/tools')>()),
  graphSummary: async (ctx: { token: { scopes: string[]; actingAs?: boolean } }, projectId: string) => {
    h.handled.push({ projectId, tenantId: '', scopes: ctx.token.scopes, actingAs: ctx.token.actingAs === true })
    return { counts: { Subdomain: 3 }, note: 'AKIAIOSFODNN7EXAMPLE' }
  },
}))

import { GET as manifest } from './route'
import { POST as callTool } from './[name]/route'
import { navigatorRuns, clearNavigatorRunsForTests, setStopNotifierForTests } from '@/lib/navigator/runRegistry'

const KEY = 'a-strong-master-key-for-tests'
const P = 'cproject000000000000000001'

function start(over: { actorId?: string | null; personId?: string; sessionVersion?: number; device?: string | null; startId?: string | null } = {}) {
  const personId = over.personId ?? 'alice'
  const r = navigatorRuns().reserve({ personId, projectId: P })
  if (!r.ok) throw new Error('reserve')
  const token = navigatorRuns().complete(r.runId, {
    threadId: 'cthread000000000000000001', tenantId: 'owner', actorId: over.actorId ?? null,
    login: { userId: over.actorId ?? personId, sessionVersion: over.sessionVersion ?? 0, deviceSessionId: over.device ?? null,
      actAsStartId: over.startId ?? null },
  })!
  return { token, runId: r.runId }
}

function req(path: string, token: string | null, body?: unknown, key = KEY) {
  return new NextRequest(`http://webapp:3000${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'x-internal-key': key, ...(token ? { 'x-redamon-navigator': token } : {}), 'content-type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
}
const call = (token: string | null, name: string, body: unknown = { args: {} }, key = KEY) =>
  callTool(req(`/api/internal/navigator/tools/${name}`, token, body, key), { params: Promise.resolve({ name }) })

beforeEach(() => {
  vi.stubEnv('INTERNAL_API_KEY', KEY)
  clearNavigatorRunsForTests()
  setStopNotifierForTests(() => {})
  h.principals = new Map([
    ['alice', { id: 'alice', status: 'active', sessionVersion: 0, role: 'standard' }],
    ['admin', { id: 'admin', status: 'active', sessionVersion: 0, role: 'admin' }],
  ])
  h.access = { project: { id: P, userId: 'owner' }, level: 'read', toggles: { rawData: false }, via: 'share' }
  h.denied = new Set()
  h.canCalls = []
  h.enabled = true
  h.allowed = true
  h.audits = []
  h.handled = []
  h.actAsInForce = true
  h.deviceRefusal = null
  h.accessOpts = []
  h.accessSubjects = []
  h.execCalls = []
  h.execResult = { records: [] }
})

describe('who may call', () => {
  test('no key, the scanner key or a wrong key: 401', async () => {
    const { token } = start()
    vi.stubEnv('SCANNER_API_KEY', 'scanner-key')
    for (const key of ['', 'scanner-key', 'wrong']) expect((await call(token, 'graph_summary', { args: {} }, key)).status).toBe(401)
  })

  test('a missing, malformed, unknown or ended credential: the same 404', async () => {
    const { token, runId } = start()
    const answers = []
    for (const t of [null, 'short', 'A'.repeat(43)]) {
      const res = await call(t, 'graph_summary')
      answers.push([res.status, await res.json()])
    }
    navigatorRuns().end(runId)
    const ended = await call(token, 'graph_summary')
    answers.push([ended.status, await ended.json()])
    expect(new Set(answers.map((a) => JSON.stringify(a))).size).toBe(1)
    expect(answers[0][0]).toBe(404)
  })
})

describe('the call', () => {
  test('ids come from the run: a project or person in the body is ignored', async () => {
    const { token } = start()
    const res = await call(token, 'graph_summary', { args: {}, projectId: 'cprojectOTHER000000000001', userId: 'mallory' })
    expect(res.status).toBe(200)
    expect(h.handled).toEqual([{ projectId: P, tenantId: '', scopes: ['recon:read'], actingAs: false }])
    expect(h.canCalls.every((c) => c.projectId === P && c.who === 'alice')).toBe(true)
  })

  test('each of the tool\'s permissions is checked, fresh', async () => {
    const { token } = start()
    await call(token, 'graph_summary')
    expect(h.canCalls.map((c) => c.permission)).toEqual(['navigator:use', 'graph:read'])
  })

  test('the result is masked unless the RoE allows full access', async () => {
    const { token } = start()
    const body = await (await call(token, 'graph_summary')).json()
    expect(JSON.stringify(body)).not.toContain('AKIAIOSFODNN7EXAMPLE')
    expect(body).toMatchObject({ ok: true, result: { counts: { Subdomain: 3 } } })
  })

  test('a permission lost mid-run refuses the next call and is audited', async () => {
    const { token } = start()
    h.denied.add('graph:read')
    const res = await call(token, 'graph_summary')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ ok: false, code: 'tool_refused' })
    expect(h.audits).toEqual([expect.objectContaining({ action: 'navigator.refused', actorId: 'alice', projectId: P,
      after: { tool: 'graph_summary', permission: 'graph:read', code: 'capability' } })])
    expect(h.handled).toEqual([])
  })

  test('a Read share without Raw data is refused the workspace and told why', async () => {
    const { token } = start()
    const res = await call(token, 'workspace_read', { args: { path: 'notes.md' } })
    expect(res.status).toBe(403)
    expect((await res.json()).message).toMatch(/Raw data & files/)
  })

  test.each([
    ['the switch turned off', () => { h.enabled = false }, 'navigator_disabled'],
    ['the owner turned the policy off', () => { h.allowed = false }, 'owner_disallowed'],
    ['the project changed owner', () => { h.access = { ...h.access!, project: { id: P, userId: 'new-owner' } } }, 'tool_refused'],
    ['the access ended', () => { h.access = null }, 'tool_refused'],
    ['the account was disabled', () => { h.principals.get('alice')!.status = 'disabled' }, 'tool_refused'],
    ['signed out everywhere (session version moved)', () => { h.principals.get('alice')!.sessionVersion = 1 }, 'tool_refused'],
  ])('%s: refused', async (_name, change, code) => {
    const { token } = start()
    change()
    const res = await call(token, 'graph_summary')
    expect(await res.json()).toMatchObject({ ok: false, code })
    expect(h.handled).toEqual([])
  })

  test('raw Cypher on a Read share without Raw data is refused, says why, and never runs', async () => {
    const { token } = start()
    const res = await call(token, 'run_cypher', { args: { cypher: 'MATCH (s:Subdomain) RETURN s.name LIMIT 5' } })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ ok: false, code: 'tool_refused', message: expect.stringMatching(/Raw data & files/) })
    expect(h.execCalls).toEqual([])
  })

  test('the query runs on the owner\'s tenant and the run\'s project; the person is the caller the limits count', async () => {
    h.access = { project: { id: P, userId: 'owner' }, level: 'read', toggles: { rawData: true }, via: 'share' }
    const { token } = start()
    const res = await call(token, 'run_cypher', {
      args: { cypher: 'MATCH (s:Subdomain) RETURN s.name LIMIT 5' }, projectId: 'cprojectOTHER000000000001', userId: 'mallory',
    })
    expect(res.status).toBe(200)
    expect(h.execCalls).toEqual([{ userId: 'owner', projectId: P, cypher: 'MATCH (s:Subdomain) RETURN s.name LIMIT 5' }])
    // The run's checks and mcpProjectAccess both ask for the person, never the owner, and the MCP
    // context's token is the person's, so every rate bucket counts the person.
    expect(h.accessSubjects.length).toBeGreaterThanOrEqual(2)
    expect(new Set(h.accessSubjects)).toEqual(new Set(['alice']))
    expect(h.canCalls.every((c) => c.who === 'alice')).toBe(true)
  })

  test('a row of another tenant in the result is discarded, never answered', async () => {
    h.access = { project: { id: P, userId: 'owner' }, level: 'owner', toggles: { rawData: true }, via: 'owner' }
    h.execResult = { records: [
      { s: { _kind: 'node', labels: ['Subdomain'], properties: { name: 'a.example.test', user_id: 'owner', project_id: P } } },
      { loot: { name: 'b.example.test', user_id: 'someone-else', project_id: 'cprojectOTHER000000000001' } },
    ] }
    const { token } = start()
    const res = await call(token, 'run_cypher', { args: { cypher: 'MATCH (s:Subdomain) RETURN s LIMIT 5' } })
    const text = await res.text()
    expect(JSON.parse(text)).toMatchObject({ ok: false, code: 'tenant_violation' })
    expect(text).not.toContain('b.example.test')
    expect(text).not.toContain('a.example.test')
  })

  test('a revoked device session refuses', async () => {
    const { token } = start({ device: 'sid-1' })
    h.deviceRefusal = 'revoked'
    expect(await (await call(token, 'graph_summary')).json()).toMatchObject({ ok: false, code: 'tool_refused' })
  })

  test('under act-as: can() is asked with the intersection, projectAccess with actingAs, and the ended act-as refuses', async () => {
    const { token } = start({ actorId: 'admin', startId: 'start-1' })
    expect((await call(token, 'graph_summary')).status).toBe(200)
    expect(h.canCalls.every((c) => c.who === 'admin' && c.actingAs === 'alice')).toBe(true)
    expect(h.accessOpts.at(-1)).toMatchObject({ actingAs: true, fresh: true })
    expect(h.handled.at(-1)).toMatchObject({ actingAs: true })
    h.actAsInForce = false
    expect(await (await call(token, 'graph_summary')).json()).toMatchObject({ ok: false, code: 'tool_refused' })
  })

  test('unknown tools, bad arguments and the per-run budget', async () => {
    const { token } = start()
    expect((await call(token, 'delete_everything')).status).toBe(404)
    expect(await (await call(token, 'run_cypher', { args: { question: 'which hosts?' } })).json()).toMatchObject({ code: 'invalid_args' })
    for (let i = 0; i < 20; i += 1) await call(token, 'graph_summary')
    const res = await call(token, 'graph_summary')
    expect(res.status).toBe(429)
    expect(await res.json()).toMatchObject({ code: 'tool_budget' })
  })
})

describe('the manifest', () => {
  test('only the tools the person may use now', async () => {
    const { token } = start()
    h.denied.add('graph:cypher')
    const body = await (await manifest(req('/api/internal/navigator/tools', token))).json()
    const names = body.tools.map((t: { name: string }) => t.name)
    expect(names).toContain('graph_summary')
    expect(names).not.toContain('run_cypher')
    // A Read share without Raw data: no workspace tool.
    expect(names.filter((n: string) => n.startsWith('workspace_'))).toEqual([])
  })

  test('a refused run lists nothing', async () => {
    const { token } = start()
    h.enabled = false
    expect(await (await manifest(req('/api/internal/navigator/tools', token))).json()).toEqual({ tools: [] })
  })
})
