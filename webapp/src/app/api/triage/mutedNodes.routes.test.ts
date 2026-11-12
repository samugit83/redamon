/**
 * Muted Nodes: the paged muted list and the batch unmute that records exemptions.
 *
 * What is pinned here:
 *  - the list is paged and filtered by the agent, and a rule mute is annotated
 *    with its rule's name, or as deleted when the rule no longer exists;
 *  - an unmute ALWAYS records an exemption, so no filter rule mutes that node
 *    again, and the audit row names the real actor behind an act-as session;
 *  - a mute or unmute is refused while a version activation holds the graph,
 *    and when that cannot be read, because activation would swallow it;
 *  - the mutating triage routes refuse a body that is not JSON (the CSRF
 *    control for a SameSite=lax cookie).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockRequireEff = vi.fn()
const mockProjectFind = vi.fn()
const mockFilterFind = vi.fn()
const mockExemptionCreate = vi.fn()
const mockAgentFetch = vi.fn()
const mockAudit = vi.fn()
const mockSession = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overProjectOwner()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockRequireEff() }))
vi.mock('@/lib/session', () => ({ getSession: () => mockSession() }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFind(...a) },
    projectNodeFilter: { findUnique: (...a: unknown[]) => mockFilterFind(...a) },
    nodeFilterExemption: { createManyAndReturn: (...a: unknown[]) => mockExemptionCreate(...a) },
  },
}))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (b: Record<string, string> = {}) => ({ ...b, 'x-internal-key': 'k' }),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (e: unknown) => mockAudit(e) }))
const mockNodeFilterWriter = vi.fn()
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: (...a: unknown[]) => mockNodeFilterWriter(...a) }))

import { getCached, setCached } from '@/app/api/graph/cache'
import { GET as getMuted } from './muted/route'
import { POST as postUnmute } from './unmute/route'
import { POST as postMute } from './mute/route'
import { POST as postVerdict } from './verdict/route'

const OWNER = 'alice'
const PROJECT = 'p1'

const DOC = {
  version: 1,
  kinds: {
    'vuln.nuclei': {
      enabled: true, action: 'mute',
      rules: [{ id: 'k3f9a2', name: 'Informational templates', enabled: true, all: [] }],
    },
  },
}

function agentReply(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status })
}

function sentBodies(): Record<string, unknown>[] {
  return mockAgentFetch.mock.calls.map(c => JSON.parse((c[1] as RequestInit).body as string))
}

function post(url: string, body: unknown, contentType = 'application/json') {
  return new NextRequest(url, {
    method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': contentType },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockRequireEff.mockResolvedValue({ userId: OWNER })
  mockProjectFind.mockResolvedValue({ id: PROJECT, userId: OWNER })
  mockFilterFind.mockResolvedValue({ rules: DOC })
  mockSession.mockResolvedValue({ userId: 'admin-bob', role: 'admin' })
  mockExemptionCreate.mockImplementation(({ data }: { data: { label: string; nodeKey: string }[] }) =>
    Promise.resolve(data.map(d => ({ label: d.label, nodeKey: d.nodeKey }))))
  mockNodeFilterWriter.mockResolvedValue(null)
})

describe('GET /api/triage/muted', () => {
  test('pages and filters through the agent, with a default page of 50', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ findings: [], total: 0 }))
    await getMuted(new NextRequest(
      `http://x/api/triage/muted?projectId=${PROJECT}&offset=100&label=Secret&mutedVia=rule&search=aws&order=person_first`))
    const [sent] = sentBodies()
    expect(sent).toMatchObject({
      op: 'list_muted', user_id: OWNER, project_id: PROJECT,
      offset: 100, limit: 50, label: 'Secret', muted_via: 'rule', search: 'aws', order: 'person_first',
    })
  })

  test('an out-of-range limit is clamped and an unknown filter value is dropped', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ findings: [], total: 0 }))
    await getMuted(new NextRequest(
      `http://x/api/triage/muted?projectId=${PROJECT}&limit=999999&mutedVia=everyone&order=random`))
    const [sent] = sentBodies()
    expect(sent.limit).toBe(5000)
    expect(sent.muted_via).toBeUndefined()
    expect(sent.order).toBeUndefined()
  })

  test('a rule mute is named by its rule, and a mute from a deleted rule says so', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({
      total: 3,
      findings: [
        { id: 'v1', muted_by: 'rule:vuln.nuclei/k3f9a2' },
        { id: 'v2', muted_by: 'rule:vuln.nuclei/gone01' },
        { id: 'v3', muted_by: OWNER },
      ],
    }))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))
    const body = await res.json()
    expect(body.total).toBe(3)
    expect(body.findings[0]).toMatchObject({ rule_name: 'Informational templates', rule_deleted: false })
    expect(body.findings[1]).toMatchObject({ rule_name: null, rule_deleted: true })
    expect(body.findings[2]).toMatchObject({ rule_name: null, rule_deleted: false, rule_kind: null })
  })

  test('the graph node id the table shows survives the rule annotation', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({
      total: 2,
      findings: [
        { id: 'v1', node_id: '812', muted_by: 'rule:vuln.nuclei/k3f9a2' },
        { id: 'v2', node_id: '813', muted_by: OWNER },
      ],
    }))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))
    const body = await res.json()
    expect(body.findings.map((f: { id: string; node_id: string }) => [f.id, f.node_id]))
      .toEqual([['v1', '812'], ['v2', '813']])
  })

  test('the deleted-rules filter names the rules that still exist', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ findings: [], total: 0 }))
    await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}&mutedVia=deleted_rule`))
    const [sent] = sentBodies()
    expect(sent.live_rules).toEqual(['rule:vuln.nuclei/allowlist', 'rule:vuln.nuclei/k3f9a2'])
  })

  test('failing to load the rules still lists every mute', async () => {
    mockFilterFind.mockRejectedValue(new Error('db down'))
    mockAgentFetch.mockResolvedValue(agentReply({ findings: [{ id: 'v1', muted_by: 'rule:x/abc123' }], total: 1 }))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))
    expect(res.status).toBe(200)
    expect((await res.json()).findings).toHaveLength(1)
  })

  test('facets are fetched only on request, with deleted rules flagged', async () => {
    mockAgentFetch
      .mockResolvedValueOnce(agentReply({ findings: [], total: 0 }))
      .mockResolvedValueOnce(agentReply({
        total: 2, by_person: 0, labels: {},
        rules: [{ muted_by: 'rule:vuln.nuclei/k3f9a2', count: 1 }, { muted_by: 'rule:old.kind/abc123', count: 1 }],
      }))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}&facets=1`))
    const body = await res.json()
    expect(sentBodies().map(b => b.op)).toEqual(['list_muted', 'muted_facets'])
    expect(body.facets.rules[0]).toMatchObject({ rule_name: 'Informational templates', rule_deleted: false })
    expect(body.facets.rules[1]).toMatchObject({ rule_deleted: true })
  })

  test('an agent failure is passed through, not reported as an empty table', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ error: 'boom' }, 500))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))
    expect(res.status).toBe(500)
  })
})

describe('POST /api/triage/unmute', () => {
  const URL = 'http://x/api/triage/unmute'

  test('refuses a body that is not JSON, before anything else', async () => {
    const res = await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }, 'text/plain'))
    expect(res.status).toBe(415)
    expect(mockProjectFind).not.toHaveBeenCalled()
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a non-owner gets 404 and nothing is unmuted or exempted', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'mallory' })
    const res = await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }))
    expect(res.status).toBe(404)
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(mockExemptionCreate).not.toHaveBeenCalled()
  })

  test('unmutes the batch and exempts every finding it actually unmuted', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({
      unmuted: 2,
      items: [
        { key: 'v1', label: 'Vulnerability', muted_by: 'rule:vuln.nuclei/k3f9a2' },
        { key: 'f9', label: 'MalPackageFinding', muted_by: OWNER },
      ],
    }))
    const res = await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1', 'f9', 'v1', 'nope'] }))
    const body = await res.json()
    expect(sentBodies()[0]).toMatchObject({ op: 'unmute_many', keys: ['v1', 'f9', 'nope'] })
    expect(body).toMatchObject({ unmuted: 2, exempted: 2 })
    // A person's mute is exempted too: an operator's unmute always sticks.
    expect(mockExemptionCreate).toHaveBeenCalledOnce()
    const { data, skipDuplicates } = mockExemptionCreate.mock.calls[0][0] as {
      data: Record<string, unknown>[]; skipDuplicates: boolean
    }
    expect(skipDuplicates).toBe(true)
    expect(data).toHaveLength(2)
    expect(data[1]).toEqual({
      projectId: PROJECT, label: 'MalPackageFinding', nodeKey: 'f9',
      createdBy: OWNER, realActorUserId: 'admin-bob',
    })
  })

  test('graph_cache_after_unmute: an unmute or a mute drops the project\'s cached graph', async () => {
    // The Graph Map is served from a 10 s cache: without this an unmuted
    // finding stayed missing from it, and a muted one stayed visible.
    mockAgentFetch.mockImplementation(() => Promise.resolve(agentReply({
      unmuted: 1, items: [{ key: 'v1', label: 'Vulnerability', muted_by: OWNER }],
    })))
    setCached(PROJECT, { nodes: [{ id: 'n1' }], links: [] })
    await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }))
    expect(getCached(PROJECT)).toBeNull()

    mockAgentFetch.mockImplementation(() => Promise.resolve(agentReply({ muted: true })))
    setCached(PROJECT, { nodes: [{ id: 'n1' }], links: [] })
    await postMute(post('http://x/api/triage/mute', { projectId: PROJECT, nodeId: 'v1', reason: 'noise' }))
    expect(getCached(PROJECT)).toBeNull()
  })

  test('unmute_during_live_apply: refused while an apply run is live, before the graph is touched', async () => {
    // A running apply holds the exemptions it read at its start. A node
    // unmuted now, before the sweep reaches its page, would be muted again by
    // that sweep, silently undoing what the operator just did.
    mockNodeFilterWriter.mockResolvedValue('mute rules are being applied to the graph')
    const res = await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }))
    expect(res.status).toBe(409)
    expect((await res.json()).error).toMatch(/mute rules are being applied/)
    expect(mockNodeFilterWriter).toHaveBeenCalledWith(PROJECT)
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(mockExemptionCreate).not.toHaveBeenCalled()
  })

  test('an unmute is refused while a version activation holds the graph', async () => {
    // Activation freezes, clears and restores the graph: an unmute in between
    // returns success and is gone.
    mockProjectFind.mockResolvedValue({
      id: PROJECT, userId: OWNER, activationState: 'activating', activationStartedAt: new Date(),
    })
    const res = await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }))
    expect(res.status).toBe(409)
    expect((await res.json()).activationInProgress).toBe(true)
    expect(mockAgentFetch).not.toHaveBeenCalled()
    expect(mockExemptionCreate).not.toHaveBeenCalled()
  })

  test('the audit names the effective user and the real actor', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({
      unmuted: 1, items: [{ key: 'v1', label: 'Vulnerability', muted_by: 'rule:vuln.nuclei/k3f9a2' }],
    }))
    await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }))
    expect(mockAudit).toHaveBeenCalledOnce()
    const entry = mockAudit.mock.calls[0][0]
    expect(entry).toMatchObject({ actorId: OWNER, action: 'muted_nodes.unmuted', targetId: PROJECT })
    expect(entry.after).toMatchObject({ realActorUserId: 'admin-bob', count: 1, exempted: 1 })
    expect(entry.after.items[0]).toEqual({ key: 'v1', label: 'Vulnerability', mutedBy: 'rule:vuln.nuclei/k3f9a2' })
  })

  test('nothing unmuted means no exemption and no audit row', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ unmuted: 0, items: [] }))
    const res = await postUnmute(post(URL, { projectId: PROJECT, nodeId: 'stale-id' }))
    expect((await res.json()).unmuted).toBe(0)
    expect(sentBodies()[0].keys).toEqual(['stale-id'])
    expect(mockExemptionCreate).not.toHaveBeenCalled()
    expect(mockAudit).not.toHaveBeenCalled()
  })

  test('a failed exemption write is reported, not swallowed', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({
      unmuted: 1, items: [{ key: 'v1', label: 'Vulnerability', muted_by: OWNER }],
    }))
    mockExemptionCreate.mockRejectedValue(new Error('db down'))
    const res = await postUnmute(post(URL, { projectId: PROJECT, keys: ['v1'] }))
    const body = await res.json()
    expect(res.status).toBe(200)
    expect(body.exempted).toBe(0)
    expect(body.exemptionError).toMatch(/may mute it again/)
  })

  test('no keys, or too many, is a 400 before the agent is called', async () => {
    expect((await postUnmute(post(URL, { projectId: PROJECT, keys: [] }))).status).toBe(400)
    const many = Array.from({ length: 501 }, (_, i) => `v${i}`)
    expect((await postUnmute(post(URL, { projectId: PROJECT, keys: many }))).status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})

describe('POST /api/triage/mute', () => {
  const URL = 'http://x/api/triage/mute'

  test('refused while a version activation holds the graph, before the agent is called', async () => {
    mockProjectFind.mockResolvedValue({
      id: PROJECT, userId: OWNER, activationState: 'activating', activationStartedAt: new Date(),
    })
    const res = await postMute(post(URL, { projectId: PROJECT, nodeId: 'v1', reason: 'noise' }))
    expect(res.status).toBe(409)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an activation state that cannot be read is treated as busy', async () => {
    mockProjectFind
      .mockResolvedValueOnce({ id: PROJECT, userId: OWNER })
      .mockRejectedValueOnce(new Error('db down'))
    const res = await postMute(post(URL, { projectId: PROJECT, nodeId: 'v1' }))
    expect(res.status).toBe(409)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an already-muted finding is reported as such, and the agent was asked to leave it', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ muted: true, already: true, label: 'Vulnerability' }))
    const res = await postMute(post(URL, { projectId: PROJECT, nodeId: 'v1', reason: 'noise' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ muted: true, already: true, label: 'Vulnerability' })
    expect(sentBodies()[0]).toMatchObject({ op: 'mute', node_id: 'v1', muted_by: OWNER })
  })

  // HD-14: the MCP mute tools' row shape (`lib/mcp/muteTools.ts`), source `ui`, the
  // real signed-in actor, and the account an admin acted as.
  test('single mute audited', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ muted: true, already: false, label: 'Vulnerability' }))
    const res = await postMute(post(URL, { projectId: PROJECT, nodeId: 'v1', reason: 'scanner noise' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ muted: true, already: false, label: 'Vulnerability' })
    expect(mockAudit).toHaveBeenCalledTimes(1)
    expect(mockAudit).toHaveBeenCalledWith({
      actorId: 'admin-bob',
      onBehalfOfUserId: OWNER,
      action: 'muted_nodes.muted',
      targetType: 'project',
      targetId: PROJECT,
      after: {
        reason: 'scanner noise',
        count: 1,
        items: [{ key: 'v1', label: 'Vulnerability', outcome: 'muted' }],
        actingAsUserId: OWNER,
      },
      source: 'ui',
    })
  })

  test('single mute audited: the owner muting in their own project is the actor', async () => {
    mockSession.mockResolvedValue({ userId: OWNER, role: 'standard' })
    mockAgentFetch.mockResolvedValue(agentReply({ muted: true, label: 'Secret' }))
    await postMute(post(URL, { projectId: PROJECT, nodeId: 'v1' }))
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({
      actorId: OWNER,
      after: { reason: '', count: 1, items: [{ key: 'v1', label: 'Secret', outcome: 'muted' }] },
    }))
  })

  test('no row when nothing was muted: already muted, no match, an agent failure', async () => {
    for (const [body, status] of [
      [{ muted: true, already: true, label: 'Vulnerability' }, 200],
      [{ muted: false, label: null }, 200],
      [{ error: 'boom', code: 'neo4j_down' }, 503],
    ] as const) {
      mockAgentFetch.mockResolvedValue(agentReply(body, status))
      await postMute(post(URL, { projectId: PROJECT, nodeId: 'v1', reason: 'noise' }))
    }
    expect(mockAudit).not.toHaveBeenCalled()
  })
})

describe('the Muted Nodes list splits agents from people', () => {
  test('mutedVia=mcp and a token prefix reach the agent', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ findings: [], total: 0 }))
    await getMuted(new NextRequest(
      `http://x/api/triage/muted?projectId=${PROJECT}&mutedVia=mcp&token=rdmn_mcp_ab12cd34`))
    expect(sentBodies()[0]).toMatchObject({ muted_via: 'mcp', token: 'rdmn_mcp_ab12cd34' })
  })

  test('a token that is not a prefix is dropped, never forwarded', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ findings: [], total: 0 }))
    for (const bad of ['rdmn_mcp_ab12cd34ef', 'x', 'rdmn_mcp_ZZ12cd34']) {
      mockAgentFetch.mockClear()
      await getMuted(new NextRequest(
        `http://x/api/triage/muted?projectId=${PROJECT}&token=${encodeURIComponent(bad)}`))
      expect(sentBodies()[0].token, bad).toBeUndefined()
    }
  })

  test('an agent mute keeps its channel and token through the annotation', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({
      total: 1,
      findings: [{ id: 'v1', muted_by: OWNER, muted_via: 'mcp', muted_channel: 'mcp', muted_token: 'rdmn_mcp_ab12cd34' }],
    }))
    const body = await (await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))).json()
    expect(body.findings[0]).toMatchObject({
      muted_via: 'mcp', muted_token: 'rdmn_mcp_ab12cd34', rule_name: null, rule_deleted: false,
    })
  })
})

describe('the other mutating triage routes refuse a non-JSON body', () => {
  test.each([
    ['mute', postMute, { projectId: PROJECT, nodeId: 'v1' }],
    ['verdict', postVerdict, { projectId: PROJECT, nodeId: 'v1', status: 'confirmed' }],
  ] as const)('%s', async (_name, handler, body) => {
    const res = await handler(post('http://x/api/triage/x', body, 'application/x-www-form-urlencoded'))
    expect(res.status).toBe(415)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })
})

describe('a database failure is a readable 500 (G-17)', () => {
  test('mute answers its fixed text and the Prisma code, not an empty body', async () => {
    mockProjectFind.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const res = await postMute(post('http://x/api/triage/mute', { projectId: PROJECT, nodeId: 'n1' }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'The finding could not be muted.', code: 'P1001' })
  })

  test('the muted list does too', async () => {
    mockProjectFind.mockRejectedValue(Object.assign(new Error('pool'), { code: 'P2024' }))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not load the muted nodes', code: 'P2024' })
  })

  test('an agent refusal reaches the browser with the agent status', async () => {
    mockAgentFetch.mockResolvedValue(agentReply({ detail: 'Unauthorized' }, 401))
    const res = await getMuted(new NextRequest(`http://x/api/triage/muted?projectId=${PROJECT}`))
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ error: 'Unauthorized', upstreamStatus: 401 })
  })
})
