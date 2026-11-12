/**
 * The Mute Rules routes: who may call them, and what each refuses.
 *
 * These rules decide what the AI agent can see for a whole project, so every
 * route is held to the triage routes' standard: strict owner check (404, never
 * 403), JSON-only mutations (415), and an audit row naming the real actor.
 * Apply is additionally a graph writer, so its preconditions are pinned one by
 * one, and it must apply the SAVED rules, never whatever a request body says.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { Prisma } from '@prisma/client'
import { muteRulesFingerprint } from '@/lib/nodeFilters/presets'

const h = vi.hoisted(() => ({
  eff: vi.fn(),
  session: vi.fn(),
  projectFind: vi.fn(),
  filterFind: vi.fn(),
  filterCreate: vi.fn(),
  filterUpdateMany: vi.fn(),
  filterUpsert: vi.fn(),
  runFindFirst: vi.fn(),
  runFindMany: vi.fn(),
  runUpdateMany: vi.fn(),
  runCreate: vi.fn(),
  exemptionFindMany: vi.fn(),
  exemptionGroupBy: vi.fn(),
  exemptionDeleteMany: vi.fn(),
  versionFind: vi.fn(),
  agentFetch: vi.fn(),
  audit: vi.fn(),
  writers: vi.fn(),
  activating: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overProjectOwner()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => h.eff() }))
vi.mock('@/lib/session', () => ({ getSession: () => h.session() }))
vi.mock('@/lib/audit', () => ({ writeAudit: (e: unknown) => h.audit(e) }))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: (...a: unknown[]) => h.writers(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.activating(...a) }))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))
vi.mock('@/lib/prisma', () => {
  const nodeFilterRun = {
    findFirst: (...a: unknown[]) => h.runFindFirst(...a),
    findMany: (...a: unknown[]) => h.runFindMany(...a),
    updateMany: (...a: unknown[]) => h.runUpdateMany(...a),
    create: (...a: unknown[]) => h.runCreate(...a),
  }
  return {
    default: {
      project: { findUnique: (...a: unknown[]) => h.projectFind(...a) },
      projectNodeFilter: {
        findUnique: (...a: unknown[]) => h.filterFind(...a),
        create: (...a: unknown[]) => h.filterCreate(...a),
        updateMany: (...a: unknown[]) => h.filterUpdateMany(...a),
        upsert: (...a: unknown[]) => h.filterUpsert(...a),
      },
      nodeFilterRun,
      nodeFilterExemption: {
        findMany: (...a: unknown[]) => h.exemptionFindMany(...a),
        groupBy: (...a: unknown[]) => h.exemptionGroupBy(...a),
        deleteMany: (...a: unknown[]) => h.exemptionDeleteMany(...a),
      },
      scanVersion: { findFirst: (...a: unknown[]) => h.versionFind(...a) },
      $transaction: (fn: (tx: unknown) => unknown) => fn({ nodeFilterRun }),
    },
  }
})

import { GET as getFilters, PUT as putFilters } from './route'
import { GET as getStatus } from './status/route'
import { POST as postPreview } from './preview/route'
import { POST as postApply } from './apply/route'
import { GET as getRun } from './runs/[runId]/route'
import { POST as postDisarm } from './disarm/route'
import { DELETE as deleteExemptions } from './exemptions/route'

const OWNER = 'owner'
const P = 'p1'
const params = { params: Promise.resolve({ id: P }) }
const RULE = { id: 'k3f9a2', name: 'Informational templates', enabled: true,
               all: [{ field: 'severity', op: 'in', value: ['info'] }] }
const RULES = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [RULE] } } }
const STORED = { projectId: P, mode: 'denylist', applyToScans: false, rules: RULES, revision: 3,
                 updatedBy: OWNER, updatedAt: new Date('2026-09-23T10:00:00Z') }

function json(url: string, body: unknown, method = 'POST', contentType = 'application/json') {
  return new NextRequest(`http://x${url}`, { method, body: JSON.stringify(body), headers: { 'Content-Type': contentType } })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.eff.mockResolvedValue({ userId: OWNER })
  h.session.mockResolvedValue({ userId: 'admin-real', role: 'admin' })
  h.projectFind.mockResolvedValue({ id: P, userId: OWNER })
  h.filterFind.mockResolvedValue(STORED)
  h.filterUpdateMany.mockResolvedValue({ count: 1 })
  h.filterUpsert.mockResolvedValue({})
  h.runFindFirst.mockResolvedValue(null)
  h.runFindMany.mockResolvedValue([])
  h.runUpdateMany.mockResolvedValue({ count: 1 })
  h.runCreate.mockResolvedValue({ id: 'run1' })
  h.exemptionFindMany.mockResolvedValue([{ label: 'Vulnerability', nodeKey: 'v1' }])
  h.exemptionGroupBy.mockResolvedValue([{ label: 'Vulnerability', _count: { _all: 1 } }])
  h.exemptionDeleteMany.mockResolvedValue({ count: 2 })
  h.versionFind.mockResolvedValue({ id: 'v7', label: 'Scan 7' })
  h.writers.mockResolvedValue(null)
  h.activating.mockResolvedValue(false)
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ accepted: true }), { status: 202 }))
})

const ROUTES = [
  ['GET rules', () => getFilters(new NextRequest(`http://x/api/projects/${P}/node-filters`), params)],
  ['PUT rules', () => putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3 }, 'PUT'), params)],
  ['GET status', () => getStatus(new NextRequest('http://x/s'), params)],
  ['POST preview', () => postPreview(json('/p', { mode: 'denylist', rules: RULES }), params)],
  ['POST apply', () => postApply(json('/a', { target: 'current', versionId: 'v7', revision: 3 }), params)],
  ['GET run', () => getRun(new NextRequest('http://x/r'), { params: Promise.resolve({ id: P, runId: 'run1' }) })],
  ['POST disarm', () => postDisarm(json('/d', {}), params)],
  ['DELETE exemptions', () => deleteExemptions(new NextRequest('http://x/e', { method: 'DELETE' }), params)],
] as const

describe('ownership', () => {
  test.each(ROUTES)('%s: a non-owner gets 404 and nothing is touched', async (_name, call) => {
    h.eff.mockResolvedValue({ userId: 'mallory' })
    const res = await call()
    expect(res.status).toBe(404)
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(h.filterUpdateMany).not.toHaveBeenCalled()
    expect(h.runCreate).not.toHaveBeenCalled()
    expect(h.exemptionDeleteMany).not.toHaveBeenCalled()
  })

  test.each([
    ['PUT rules', () => putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3 }, 'PUT', 'text/plain'), params)],
    ['POST preview', () => postPreview(json('/p', { mode: 'denylist', rules: RULES }, 'POST', 'text/plain'), params)],
    ['POST apply', () => postApply(json('/a', { target: 'scans', revision: 3 }, 'POST', 'application/x-www-form-urlencoded'), params)],
    ['POST disarm', () => postDisarm(json('/d', {}, 'POST', 'multipart/form-data'), params)],
  ] as const)('%s refuses a body that is not JSON', async (_name, call) => {
    expect((await call()).status).toBe(415)
  })
})

describe('GET and PUT the rules', () => {
  test('a project with no row reads as empty, denylist, revision 0', async () => {
    h.filterFind.mockResolvedValue(null)
    const body = await (await getFilters(new NextRequest('http://x'), params)).json()
    expect(body).toMatchObject({ mode: 'denylist', applyToScans: false, revision: 0, exists: false,
                                 rules: { version: 1, kinds: {} } })
    expect(body.exemptionCounts).toEqual({ Vulnerability: 1 })
    expect(body.activeVersion).toEqual({ id: 'v7', label: 'Scan 7' })
  })

  test('a save bumps the revision, conditionally, and never touches applyToScans', async () => {
    const res = await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3 }, 'PUT'), params)
    expect(res.status).toBe(200)
    const call = h.filterUpdateMany.mock.calls[0][0]
    expect(call.where).toEqual({ projectId: P, revision: 3 })
    expect(call.data.revision).toEqual({ increment: 1 })
    expect(call.data).not.toHaveProperty('applyToScans')
  })

  test('the first save creates the row at revision 1', async () => {
    h.filterFind.mockResolvedValueOnce(null)
    const res = await putFilters(json('/n', { mode: 'allowlist', rules: RULES, revision: 0 }, 'PUT'), params)
    expect((await res.json()).revision).toBe(1)
    expect(h.filterCreate.mock.calls[0][0].data).toMatchObject({ projectId: P, mode: 'allowlist', revision: 1 })
  })

  test('a stale revision is a 409 that names the current one', async () => {
    const res = await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 2 }, 'PUT'), params)
    expect(res.status).toBe(409)
    expect((await res.json()).currentRevision).toBe(3)
    expect(h.filterUpdateMany).not.toHaveBeenCalled()
  })

  test('a save that lost a race is a 409 too', async () => {
    h.filterUpdateMany.mockResolvedValue({ count: 0 })
    const res = await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3 }, 'PUT'), params)
    expect(res.status).toBe(409)
  })

  test('Overwrite saves over a newer revision, and the audit says it was forced', async () => {
    const res = await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 1, force: true }, 'PUT'), params)
    expect(res.status).toBe(200)
    expect(h.filterUpdateMany.mock.calls[0][0].where).toEqual({ projectId: P })
    const saved = h.audit.mock.calls.find(c => c[0].action === 'node_filters.saved')![0]
    expect(saved.after).toMatchObject({ forced: true, realActorUserId: 'admin-real' })
    expect(saved.actorId).toBe(OWNER)
  })

  test('an invalid rule document is refused with every error', async () => {
    const bad = { version: 1, kinds: { 'vuln.nuclei': { enabled: true, action: 'mute', rules: [
      { ...RULE, name: '<script>' }] } } }
    const res = await putFilters(json('/n', { mode: 'denylist', rules: bad, revision: 3 }, 'PUT'), params)
    expect(res.status).toBe(400)
    expect((await res.json()).errors.length).toBeGreaterThan(0)
    expect(h.filterUpdateMany).not.toHaveBeenCalled()
  })

  test('a mode change gets its own audit row', async () => {
    await putFilters(json('/n', { mode: 'allowlist', rules: RULES, revision: 3 }, 'PUT'), params)
    const actions = h.audit.mock.calls.map(c => c[0].action)
    expect(actions).toEqual(['node_filters.saved', 'node_filters.mode_changed'])
  })
})

describe('the loaded preset', () => {
  const PRESET = { name: 'Quiet perimeter', fingerprint: '1a2b3c' }

  test('a preset load stores the record with the save, and the audit names the preset', async () => {
    const res = await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3, loadedPreset: PRESET }, 'PUT'), params)
    expect(res.status).toBe(200)
    expect(h.filterUpdateMany.mock.calls[0][0].data.loadedPreset).toEqual({
      name: 'Quiet perimeter', fingerprint: muteRulesFingerprint('denylist', RULES),
    })
    const saved = h.audit.mock.calls.map(c => c[0]).find(e => e.action === 'node_filters.saved')
    expect(saved.after.presetLoaded).toBe('Quiet perimeter')
  })

  test('forged_preset_fingerprint: the stored fingerprint is computed from the saved rules, never taken from the body', async () => {
    // Trusting the body would let a request badge rules no preset produced, and
    // any client/server difference in hashing would hide the badge for good.
    await putFilters(json('/n', { mode: 'allowlist', rules: RULES, revision: 3,
                                  loadedPreset: { name: 'Quiet perimeter', fingerprint: 'deadbeef' } }, 'PUT'), params)
    const stored = h.filterUpdateMany.mock.calls[0][0].data.loadedPreset
    expect(stored.fingerprint).toBe(muteRulesFingerprint('allowlist', RULES))
    expect(stored.fingerprint).not.toBe('deadbeef')
  })

  test('the first save of a project can carry the record too', async () => {
    h.filterFind.mockResolvedValue(null)
    await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 0, loadedPreset: PRESET }, 'PUT'), params)
    expect(h.filterCreate.mock.calls[0][0].data.loadedPreset).toEqual({
      name: 'Quiet perimeter', fingerprint: muteRulesFingerprint('denylist', RULES),
    })
  })

  test('an ordinary save leaves the record alone: the badge is decided by the fingerprint', async () => {
    await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3 }, 'PUT'), params)
    expect(h.filterUpdateMany.mock.calls[0][0].data).not.toHaveProperty('loadedPreset')
  })

  test('null clears the record', async () => {
    await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3, loadedPreset: null }, 'PUT'), params)
    expect(h.filterUpdateMany.mock.calls[0][0].data.loadedPreset).toBe(Prisma.DbNull)
  })

  test('a malformed record is a 400 and nothing is saved', async () => {
    for (const bad of ['x', { name: 'only a name' }, { name: 'A', fingerprint: 'f'.repeat(40) }]) {
      const res = await putFilters(json('/n', { mode: 'denylist', rules: RULES, revision: 3, loadedPreset: bad }, 'PUT'), params)
      expect(res.status).toBe(400)
    }
    expect(h.filterUpdateMany).not.toHaveBeenCalled()
  })

  test('GET returns the record, and a project that never loaded one reads null', async () => {
    h.filterFind.mockResolvedValue({ ...STORED, loadedPreset: PRESET })
    expect((await (await getFilters(new NextRequest('http://x/n'), params)).json()).loadedPreset).toEqual(PRESET)
    h.filterFind.mockResolvedValue(STORED)
    expect((await (await getFilters(new NextRequest('http://x/n'), params)).json()).loadedPreset).toBeNull()
  })
})

describe('status', () => {
  test('counts the rules the engine would run', async () => {
    h.filterFind.mockResolvedValue({ ...STORED, applyToScans: true })
    const body = await (await getStatus(new NextRequest('http://x'), params)).json()
    expect(body).toEqual({ armed: true, mode: 'denylist', activeRules: 1, activeKinds: 1, runningApply: false })
  })
})

describe('preview', () => {
  test('sends the draft and the exemptions to the agent, with a 25 s budget', async () => {
    h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ ok: true, kinds: {} }), { status: 200 }))
    const res = await postPreview(json('/p', { mode: 'denylist', rules: RULES, kinds: ['vuln.nuclei'] }), params)
    expect(res.status).toBe(200)
    const [path, init, opts] = h.agentFetch.mock.calls[0]
    expect(path).toBe('/graph/node-filters/preview')
    expect(JSON.parse(init.body)).toEqual({
      user_id: OWNER, project_id: P, mode: 'denylist', rules: RULES,
      exemptions: [['Vulnerability', 'v1']], kinds: ['vuln.nuclei'],
    })
    expect(opts).toEqual({ timeoutMs: 25000 })
  })

  test('an unreadable document is a 400 before the agent', async () => {
    const res = await postPreview(json('/p', { mode: 'sometimes', rules: RULES }), params)
    expect(res.status).toBe(400)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('a second preview while one runs is a 429', async () => {
    let release: (v: Response) => void = () => {}
    h.agentFetch.mockReturnValueOnce(new Promise<Response>(r => { release = r }))
    const first = postPreview(json('/p', { mode: 'denylist', rules: RULES }), params)
    await new Promise(r => setTimeout(r, 0))
    await new Promise(r => setTimeout(r, 0))
    const second = await postPreview(json('/p', { mode: 'denylist', rules: RULES }), params)
    expect(second.status).toBe(429)
    release(new Response(JSON.stringify({ ok: true }), { status: 200 }))
    expect((await first).status).toBe(200)
  })

  test('an unreachable agent is a 503', async () => {
    const { AgentUnreachableError } = await import('@/lib/agentFetch')
    h.agentFetch.mockRejectedValue(new AgentUnreachableError('agent down'))
    expect((await postPreview(json('/p', { mode: 'denylist', rules: RULES }), params)).status).toBe(503)
  })
})

describe('apply', () => {
  const apply = (body: Record<string, unknown>) => postApply(json('/a', body), params)

  test('applies the SAVED rules: the body cannot choose them', async () => {
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3,
                              rules: { version: 1, kinds: {} }, mode: 'allowlist' })
    expect(res.status).toBe(202)
    expect((await res.json()).runId).toBe('run1')
    const created = h.runCreate.mock.calls[0][0].data
    expect(created).toMatchObject({ projectId: P, mode: 'denylist', rules: RULES, revision: 3,
                                    versionId: 'v7', target: 'current', actorUserId: OWNER,
                                    realActorUserId: 'admin-real', status: 'running' })
    // The agent gets the run id and nothing else.
    expect(JSON.parse(h.agentFetch.mock.calls[0][1].body)).toEqual({ run_id: 'run1' })
    expect(h.filterUpsert).not.toHaveBeenCalled()
    expect(h.audit.mock.calls.map(c => c[0].action)).toEqual(['node_filters.applied'])
  })

  test('a stale revision is refused', async () => {
    expect((await apply({ target: 'current', versionId: 'v7', revision: 2 })).status).toBe(409)
    expect(h.runCreate).not.toHaveBeenCalled()
  })

  test('only the active version can be changed', async () => {
    const res = await apply({ target: 'current', versionId: 'v3', revision: 3 })
    expect(res.status).toBe(409)
    expect((await res.json()).error).toMatch(/active version/)
    expect(h.runCreate).not.toHaveBeenCalled()
  })

  test('refused while anything else writes the graph', async () => {
    h.writers.mockResolvedValue('a full recon scan is running')
    const res = await apply({ target: 'both', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(409)
    expect((await res.json()).error).toMatch(/full recon scan is running/)
    expect(h.runCreate).not.toHaveBeenCalled()
    expect(h.filterUpsert).not.toHaveBeenCalled()
  })

  test('refused while a version is being activated', async () => {
    h.activating.mockResolvedValue(true)
    expect((await apply({ target: 'current', versionId: 'v7', revision: 3 })).status).toBe(409)
    expect(h.runCreate).not.toHaveBeenCalled()
  })

  test('refused when a run is already live, in the same transaction', async () => {
    h.runFindMany.mockResolvedValue([{ id: 'other', heartbeatAt: new Date() }])
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(409)
    expect((await res.json()).runId).toBe('other')
    expect(h.runCreate).not.toHaveBeenCalled()
  })

  test('an activation that took its lock after the check fails the new run', async () => {
    h.activating.mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(409)
    expect(h.runUpdateMany.mock.calls.at(-1)![0].data).toMatchObject({ status: 'failed' })
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('an agent that refuses leaves the run failed, not live', async () => {
    const { AgentUnreachableError } = await import('@/lib/agentFetch')
    h.agentFetch.mockRejectedValue(new AgentUnreachableError('agent down'))
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(503)
    expect(h.runUpdateMany.mock.calls.at(-1)![0]).toMatchObject({
      where: { id: 'run1', status: 'running' }, data: { status: 'failed' },
    })
  })

  test("an agent refusal shows its own sentence, FastAPI's detail included, with the agent status", async () => {
    h.agentFetch.mockResolvedValue(new Response(JSON.stringify({ detail: 'Unauthorized' }), { status: 401 }))
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Unauthorized', code: 'agent_error', upstreamStatus: 401 })
    expect(h.runUpdateMany.mock.calls.at(-1)![0].data).toMatchObject({ status: 'failed', error: 'Unauthorized' })
  })

  test('an agent crash is 502 with the agent status, the run failed', async () => {
    h.agentFetch.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'The agent refused the apply.', code: 'agent_error', upstreamStatus: 500 })
    expect(h.runUpdateMany.mock.calls.at(-1)![0].data).toMatchObject({ status: 'failed', error: 'the agent answered 500' })
  })

  test('an unreachable agent keeps its explanation and adds the code', async () => {
    const { AgentUnreachableError } = await import('@/lib/agentFetch')
    h.agentFetch.mockRejectedValue(new AgentUnreachableError('Cannot reach the RedAmon agent service'))
    const res = await apply({ target: 'current', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(503)
    expect(await res.json()).toMatchObject({ error: 'Cannot reach the RedAmon agent service', code: 'agent_unreachable' })
  })

  test('New scans only arms, and touches neither the graph nor the agent', async () => {
    const res = await apply({ target: 'scans', revision: 3 })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ runId: null, armed: true })
    expect(h.runCreate).not.toHaveBeenCalled()
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(h.writers).not.toHaveBeenCalled()
    expect(h.filterUpsert.mock.calls[0][0].update).toEqual({ applyToScans: true })
    expect(h.audit.mock.calls.map(c => c[0].action)).toEqual(['node_filters.armed'])
  })

  test('New scans only works on a past version too: it changes no graph', async () => {
    expect((await apply({ target: 'scans', versionId: 'v3', revision: 3 })).status).toBe(200)
  })

  test('Both runs the apply and arms', async () => {
    const res = await apply({ target: 'both', versionId: 'v7', revision: 3 })
    expect(res.status).toBe(202)
    expect(await res.json()).toEqual({ runId: 'run1', armed: true })
  })

  test('an unknown target is a 400', async () => {
    expect((await apply({ target: 'everything', revision: 3 })).status).toBe(400)
  })
})

describe('runs, disarm and exemptions', () => {
  test('a run is read within the project only', async () => {
    await getRun(new NextRequest('http://x'), { params: Promise.resolve({ id: P, runId: 'run1' }) })
    expect(h.runFindFirst.mock.calls.at(-1)![0].where).toEqual({ id: 'run1', projectId: P })
  })

  test('disarm clears applyToScans and audits it', async () => {
    const res = await postDisarm(json('/d', {}), params)
    expect(await res.json()).toEqual({ armed: false })
    expect(h.filterUpdateMany.mock.calls[0][0]).toEqual({
      where: { projectId: P, applyToScans: true }, data: { applyToScans: false } })
    expect(h.audit.mock.calls[0][0].action).toBe('node_filters.disarmed')
  })

  test('exemptions can be cleared for one label, and only a finding label', async () => {
    const res = await deleteExemptions(new NextRequest('http://x/e?label=Secret', { method: 'DELETE' }), params)
    expect(await res.json()).toEqual({ cleared: 2 })
    expect(h.exemptionDeleteMany.mock.calls[0][0].where).toEqual({ projectId: P, label: 'Secret' })
    expect(h.audit.mock.calls[0][0]).toMatchObject({ action: 'node_filters.exemptions_cleared' })
    const bad = await deleteExemptions(new NextRequest('http://x/e?label=IP', { method: 'DELETE' }), params)
    expect(bad.status).toBe(400)
  })
})
