/**
 * Multi mute's routes: suggest, apply, the batch-scoped Undo and the Muted
 * Nodes filter.
 *
 * What is pinned here:
 *  - ownership (someone else's project is 404) and the activation lock (409
 *    `activation_busy`, failing closed when the lock cannot be read);
 *  - suggest reads the OWNER's saved model (`model_required` without one),
 *    sends the project's exemptions, and maps the agent's answers: an
 *    outdated agent, a coded error, and a 502 that still carries groups;
 *  - apply validates its input, writes as the effective user, audits the
 *    REAL actor, and counts the open CypherFix items the mute touches;
 *  - an Undo is scoped to its batch and writes no exemption.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockRequireEff = vi.fn()
const mockProjectFind = vi.fn()
const mockSettings = vi.fn()
const mockExemptions = vi.fn()
const mockExemptionCreate = vi.fn()
const mockRemediationCount = vi.fn()
const mockAgentFetch = vi.fn()
const mockAudit = vi.fn()
const mockSession = vi.fn()
const mockLiveRun = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overProjectOwner()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockRequireEff() }))
vi.mock('@/lib/session', () => ({ getSession: () => mockSession() }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFind(...a) },
    userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) },
    projectNodeFilter: { findUnique: async () => null },
    nodeFilterExemption: {
      findMany: (...a: unknown[]) => mockExemptions(...a),
      createManyAndReturn: (...a: unknown[]) => mockExemptionCreate(...a),
    },
    remediation: { count: (...a: unknown[]) => mockRemediationCount(...a) },
  },
}))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {
    cause_: unknown
    constructor(cause: unknown) { super('down'); this.cause_ = cause }
  }
  return { agentFetch: (...a: unknown[]) => mockAgentFetch(...a), AgentUnreachableError }
})
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (b: Record<string, string> = {}) => ({ ...b, 'x-internal-key': 'k' }),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (e: unknown) => mockAudit(e) }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: (...a: unknown[]) => mockLiveRun(...a) }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))

import { POST as suggest } from './suggest/route'
import { POST as apply } from './apply/route'
import { POST as unmute } from '../unmute/route'
import { GET as getMuted } from '../muted/route'

const OWNER = 'alice'
const PROJECT = 'p1'
const BATCH = 'mm-0123abcd'

function post(url: string, body: unknown) {
  return new NextRequest(url, {
    method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
  })
}

function reply(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status })
}

function sent(i = 0) {
  return JSON.parse((mockAgentFetch.mock.calls[i][1] as RequestInit).body as string)
}

const SUGGESTION = {
  multi_mute: 1, model_used: 'gpt-5-mini', status: 'ok', batch_id: BATCH,
  prompt_version: 'multi-mute-v1', model: 'gpt-5-mini', seed: { key: 's1' }, read: {},
  pool: { total: 4 }, groups: [{ id: 'g1', members: [] }],
}

beforeEach(() => {
  vi.clearAllMocks()
  mockRequireEff.mockResolvedValue({ userId: OWNER })
  mockProjectFind.mockResolvedValue({ id: PROJECT, userId: OWNER })
  mockSettings.mockResolvedValue({ featureModels: { multi_mute: 'gpt-5-mini' } })
  mockExemptions.mockResolvedValue([{ label: 'Vulnerability', nodeKey: 'kept-1' }])
  mockRemediationCount.mockResolvedValue(2)
  mockSession.mockResolvedValue({ userId: 'admin-bob', role: 'admin' })
  mockLiveRun.mockResolvedValue(null)
  mockAgentFetch.mockResolvedValue(reply(SUGGESTION))
})

describe('suggest', () => {
  const body = { projectId: PROJECT, nodeId: 's1' }

  test('someone else\'s project is 404 and nothing is read', async () => {
    mockProjectFind.mockResolvedValue({ id: PROJECT, userId: 'mallory' })
    const res = await suggest(post('http://x/s', body))
    expect(res.status).toBe(404)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an activation in progress is 409 activation_busy', async () => {
    mockProjectFind.mockImplementation(async (args: { select?: Record<string, boolean> }) =>
      args.select?.activationState
        ? { activationState: 'activating', activationStartedAt: new Date() }
        : { id: PROJECT, userId: OWNER })
    const res = await suggest(post('http://x/s', body))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('activation_busy')
  })

  test('an unreadable lock fails closed', async () => {
    mockProjectFind.mockImplementation(async (args: { select?: Record<string, boolean> }) => {
      if (args.select?.activationState) throw new Error('db down')
      return { id: PROJECT, userId: OWNER }
    })
    expect((await suggest(post('http://x/s', body))).status).toBe(409)
  })

  test('no saved model is model_required', async () => {
    mockSettings.mockResolvedValue(null)
    const res = await suggest(post('http://x/s', body))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'model_required', featureId: 'multi_mute' })
  })

  test('the owner\'s model, the tenant and the exemptions go to the agent', async () => {
    const res = await suggest(post('http://x/s', { ...body, model: 'claude-opus-4-6' }))
    expect(res.status).toBe(200)
    expect(mockAgentFetch.mock.calls[0][0]).toBe('/graph/multi-mute/suggest')
    expect(sent()).toEqual({
      user_id: OWNER, project_id: PROJECT, seed_key: 's1', model: 'gpt-5-mini',
      exempt_pairs: [['Vulnerability', 'kept-1']],
    })
    const payload = await res.json()
    expect(payload.batch_id).toBe(BATCH)
    expect(payload).not.toHaveProperty('model_used')
  })

  // Review finding, accepted: the browser's abort never reaches the agent call.
  // FastAPI would not stop the handler on a disconnect anyway, so passing the
  // signal only saves a request that is aborted before it is sent.
  test.fails('passes the browser\'s abort signal to the agent call', async () => {
    const controller = new AbortController()
    const req = post('http://x/s', body)
    await suggest(new NextRequest(req, { signal: controller.signal }))
    expect((mockAgentFetch.mock.calls[0][1] as RequestInit).signal).toBeDefined()
  })

  test('an agent without the marker, or without the endpoint, is agent_outdated', async () => {
    mockAgentFetch.mockResolvedValue(reply({ ...SUGGESTION, multi_mute: undefined }))
    expect((await (await suggest(post('http://x/s', body))).json()).code).toBe('agent_outdated')
    mockAgentFetch.mockResolvedValue(reply({ detail: 'Not Found' }, 404))
    expect((await (await suggest(post('http://x/s', body))).json()).code).toBe('agent_outdated')
  })

  test('a 502 model_unreadable still reaches the client with its groups', async () => {
    mockAgentFetch.mockResolvedValue(reply({ ...SUGGESTION, status: 'model_unreadable' }, 502))
    const res = await suggest(post('http://x/s', body))
    expect(res.status).toBe(502)
    expect((await res.json()).groups).toHaveLength(1)
  })

  test('the agent\'s own codes pass through', async () => {
    for (const [code, status] of [['seed_changed', 409], ['busy', 429], ['seed_not_muteable', 400]] as const) {
      mockAgentFetch.mockResolvedValue(reply({ code, error: 'x', multi_mute: 1, model_used: 'gpt-5-mini' }, status))
      const res = await suggest(post('http://x/s', body))
      expect(res.status).toBe(status)
      expect((await res.json()).code).toBe(code)
    }
  })

  test('the model codes keep their meaning', async () => {
    mockAgentFetch.mockResolvedValue(reply({ code: 'model_unavailable', error: 'x', multi_mute: 1, model_used: 'gpt-5-mini' }, 503))
    expect((await (await suggest(post('http://x/s', body))).json()).code).toBe('model_unavailable')
    const timeout = Object.assign(new Error('t'), { name: 'TimeoutError' })
    const { AgentUnreachableError } = await import('@/lib/agentFetch')
    mockAgentFetch.mockRejectedValue(new AgentUnreachableError(timeout))
    expect((await (await suggest(post('http://x/s', body))).json()).code).toBe('agent_timeout')
  })

  test('a failed exemption read refuses instead of re-hiding findings', async () => {
    mockExemptions.mockRejectedValue(new Error('db'))
    expect((await suggest(post('http://x/s', body))).status).toBe(503)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('neither a node id nor a graph id is a 400', async () => {
    expect((await suggest(post('http://x/s', { projectId: PROJECT }))).status).toBe(400)
  })
})

describe('apply', () => {
  const body = { projectId: PROJECT, batchId: BATCH, keys: ['k1', 'k2'], includeSeed: true, concept: 'same_detector' }
  const written = {
    multi_mute: 1, model: 'gpt-5-mini', prompt_version: 'multi-mute-v1', not_found: [],
    items: [
      { key: 'k1', label: 'Vulnerability', node_id: '1', name: 'n', severity: 'low', outcome: 'muted' },
      { key: 'k2', label: 'Vulnerability', node_id: '2', name: 'n', severity: 'low', outcome: 'above_seed' },
    ],
  }

  beforeEach(() => mockAgentFetch.mockResolvedValue(reply(written)))

  test('writes mute_batch as the effective user with the exemptions', async () => {
    const res = await apply(post('http://x/a', body))
    expect(res.status).toBe(200)
    expect(sent()).toMatchObject({
      op: 'mute_batch', user_id: OWNER, project_id: PROJECT, batch_id: BATCH,
      keys: ['k1', 'k2'], include_seed: true, concept: 'same_detector', muted_by: OWNER,
      exempt_pairs: [['Vulnerability', 'kept-1']],
    })
  })

  test('audits the real actor, the batch, the model and only what was muted', async () => {
    await apply(post('http://x/a', body))
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'muted_nodes.multi_muted', actorId: 'admin-bob', targetId: PROJECT,
      after: expect.objectContaining({
        realActorUserId: 'admin-bob', effectiveUserId: OWNER, batchId: BATCH,
        model: 'gpt-5-mini', promptVersion: 'multi-mute-v1', concept: 'same_detector',
        count: 1, keys: ['k1'],
      }),
    }))
  })

  test('counts the open work items that reference a muted key', async () => {
    const payload = await (await apply(post('http://x/a', body))).json()
    expect(payload.workItemsAffected).toBe(2)
    expect(mockRemediationCount.mock.calls[0][0].where).toMatchObject({
      projectId: PROJECT, findingIds: { hasSome: ['k1'] },
    })
  })

  test('says when a triage run is live', async () => {
    mockLiveRun.mockResolvedValue({ id: 'r1' })
    expect((await (await apply(post('http://x/a', body))).json()).triageRunLive).toBe(true)
  })

  test.each([
    [{ batchId: 'mm-XYZ' }],
    [{ concept: 'everything' }],
    [{ keys: [] }],
    [{ keys: ['k1', 7] }],
    [{ keys: Array.from({ length: 501 }, (_, i) => `k${i}`) }],
  ])('refuses bad input %j before the agent', async (patch) => {
    expect((await apply(post('http://x/a', { ...body, ...patch }))).status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an expired batch passes its code through', async () => {
    mockAgentFetch.mockResolvedValue(reply({ error: 'expired', code: 'batch_expired', multi_mute: 1 }, 409))
    const res = await apply(post('http://x/a', body))
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('batch_expired')
    expect(mockAudit).not.toHaveBeenCalled()
  })

  test('an agent that does not know the op is agent_outdated', async () => {
    mockAgentFetch.mockResolvedValue(reply({ error: "unknown op 'mute_batch'" }, 400))
    expect((await (await apply(post('http://x/a', body))).json()).code).toBe('agent_outdated')
  })

  test('someone else\'s project is 404', async () => {
    mockProjectFind.mockResolvedValue({ id: PROJECT, userId: 'mallory' })
    expect((await apply(post('http://x/a', body))).status).toBe(404)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})

describe('undo', () => {
  test('is scoped to its batch, writes no exemption and audits as multi_undo', async () => {
    mockAgentFetch.mockResolvedValue(reply({
      multi_mute: 1, unmuted: 1, skipped: [{ key: 'k2' }],
      items: [{ key: 'k1', label: 'Vulnerability', muted_by: OWNER, was_via: 'multi' }],
    }))
    const res = await unmute(post('http://x/u', { projectId: PROJECT, keys: ['k1', 'k2'], undoBatch: BATCH }))
    expect(res.status).toBe(200)
    expect(sent()).toMatchObject({ op: 'unmute_many', keys: ['k1', 'k2'], only_batch: BATCH })
    expect(mockExemptionCreate).not.toHaveBeenCalled()
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'muted_nodes.unmuted', source: 'multi_undo',
      after: expect.objectContaining({ batchId: BATCH, exempted: 0 }),
    }))
    expect(await res.json()).toMatchObject({ unmuted: 1, exempted: 0, skipped: [{ key: 'k2' }] })
  })

  test('a malformed batch id is refused', async () => {
    const res = await unmute(post('http://x/u', { projectId: PROJECT, keys: ['k1'], undoBatch: 'x' }))
    expect(res.status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an agent that ignores only_batch is reported as outdated', async () => {
    mockAgentFetch.mockResolvedValue(reply({ unmuted: 1, items: [] }))
    const res = await unmute(post('http://x/u', { projectId: PROJECT, keys: ['k1'], undoBatch: BATCH }))
    expect((await res.json()).code).toBe('agent_outdated')
  })

  test('what an agent that ignores only_batch unmuted is still audited (review: unmuted, then no audit)', async () => {
    mockAgentFetch.mockResolvedValue(reply({
      unmuted: 1, items: [{ key: 'k1', label: 'Vulnerability', muted_by: 'rule:vuln.nuclei/k3f9a2' }],
    }))
    const res = await unmute(post('http://x/u', { projectId: PROJECT, keys: ['k1'], undoBatch: BATCH }))
    expect((await res.json()).code).toBe('agent_outdated')
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'muted_nodes.unmuted', source: 'multi_undo',
    }))
  })

  test('a plain unmute still writes exemptions', async () => {
    mockExemptionCreate.mockResolvedValue([{ label: 'Vulnerability', nodeKey: 'k1' }])
    mockAgentFetch.mockResolvedValue(reply({
      unmuted: 1, items: [{ key: 'k1', label: 'Vulnerability', muted_by: OWNER }],
    }))
    await unmute(post('http://x/u', { projectId: PROJECT, keys: ['k1'] }))
    expect(sent()).not.toHaveProperty('only_batch')
    expect(mockExemptionCreate).toHaveBeenCalled()
  })
})

describe('the Muted Nodes filters', () => {
  test('multi is a muted_via filter, and a batch id is a token', async () => {
    mockAgentFetch.mockResolvedValue(reply({ findings: [], total: 0 }))
    await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}&mutedVia=multi&token=${BATCH}`))
    expect(sent()).toMatchObject({ op: 'list_muted', muted_via: 'multi', token: BATCH })
  })

  test('a token that is neither a prefix nor a batch id is dropped', async () => {
    mockAgentFetch.mockResolvedValue(reply({ findings: [], total: 0 }))
    await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}&token=mm-nope`))
    expect(sent().token).toBeUndefined()
  })
})
