/**
 * The Priority Board routes of the layered model: the detail and evidence reads,
 * the verdict (rescored, audited) and the board's filters.
 *
 * Same authorisation rule as the rest of /api/triage: a caller who does not own
 * the project gets 404 (ownership is always enforced; ACCESS_ENFORCE is ignored),
 * and the tenant sent to the agent comes from the project row, never the request.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  eff: vi.fn(), project: vi.fn(), fetch: vi.fn(), audit: vi.fn(), session: vi.fn(),
  activation: vi.fn(), latestRun: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overProjectOwner()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => h.eff() }))
vi.mock('@/lib/session', () => ({ getSession: () => h.session() }))
vi.mock('@/lib/prisma', () => ({ default: { project: { findUnique: (...a: unknown[]) => h.project(...a) } } }))
vi.mock('@/lib/agentFetch', () => ({
  agentBaseUrl: () => 'http://agent',
  agentFetch: vi.fn(),
  AgentUnreachableError: class extends Error {},
}))
vi.mock('@/lib/agentAuth', () => ({ internalKeyHeaders: (b: Record<string, string> = {}) => b }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.activation(...a) }))
vi.mock('@/lib/triageRun', () => ({
  findLiveTriageRun: async () => null,
  latestPublishedRunId: (...a: unknown[]) => h.latestRun(...a),
  latestRunIdFrom: (rows: Array<{ triage_run_id?: string; triaged_at?: string }>) =>
    rows.length ? rows[0].triage_run_id ?? null : null,
}))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { GET as getFinding } from './finding/route'
import { GET as getEvidence } from './evidence/route'
import { GET as getFindings } from './findings/route'
import { POST as postVerdict } from './verdict/route'

const OWNER = 'alice'
const PROJECT = 'victim-project'

const get = (path: string, query = '') =>
  new NextRequest(`http://x/api/triage/${path}?projectId=${PROJECT}${query}`)
const post = (body: unknown) => new NextRequest('http://x/api/triage/verdict', {
  method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' },
})
const answer = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const sentBody = (i = 0) => JSON.parse((h.fetch.mock.calls[i][1] as RequestInit).body as string)

const ROUTES = [
  { name: 'GET finding', call: () => getFinding(get('finding', '&findingId=v1')) },
  { name: 'GET evidence', call: () => getEvidence(get('evidence', '&findingId=v1')) },
  { name: 'GET findings', call: () => getFindings(get('findings')) },
  { name: 'POST verdict', call: () => postVerdict(post({ projectId: PROJECT, nodeId: 'v1', status: 'confirmed' })) },
]

const originalEnforce = process.env.ACCESS_ENFORCE

beforeEach(() => {
  vi.clearAllMocks()
  globalThis.fetch = h.fetch as unknown as typeof fetch
  h.eff.mockResolvedValue({ userId: OWNER })
  h.session.mockResolvedValue({ userId: 'admin-behind' })
  h.project.mockResolvedValue({ id: PROJECT, userId: OWNER })
  h.activation.mockResolvedValue(false)
  h.latestRun.mockResolvedValue('run-latest')
  h.fetch.mockResolvedValue(answer({ found: true, row: { id: 'v1' }, findings: [], total: 0,
                                     updated: true, label: 'Vulnerability', rescored: true,
                                     before: { score: 40 }, after: { score: 75 } }))
})

afterEach(() => {
  if (originalEnforce === undefined) delete process.env.ACCESS_ENFORCE
  else process.env.ACCESS_ENFORCE = originalEnforce
})

describe('BOLA', () => {
  test.each(ROUTES)('EXPLOIT: $name on someone else\'s project -> 404, agent never called', async ({ call }) => {
    h.eff.mockResolvedValue({ userId: 'mallory' })
    const res = await call()
    expect(res.status).toBe(404)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('$name: ACCESS_ENFORCE=0 still hard-blocks', async ({ call }) => {
    process.env.ACCESS_ENFORCE = '0'
    h.eff.mockResolvedValue({ userId: 'mallory' })
    expect((await call()).status).toBe(404)
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test.each(ROUTES)('$name: the tenant comes from the project row', async ({ call }) => {
    await call()
    const body = sentBody()
    expect(body.user_id).toBe(OWNER)
    expect(body.project_id).toBe(PROJECT)
    expect(body.source).toBeUndefined()
  })
})

describe('the detail and evidence reads', () => {
  test('a bad finding id or label is 400 before the agent is called', async () => {
    for (const q of ['', '&findingId=v1;DROP', '&findingId=v1&label=Domain']) {
      expect((await getFinding(get('finding', q))).status).toBe(400)
      expect((await getEvidence(get('evidence', q))).status).toBe(400)
    }
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('the label narrows the read', async () => {
    await getFinding(get('finding', '&findingId=v1&label=Secret'))
    expect(sentBody()).toMatchObject({ op: 'finding_detail', node_id: 'v1', label: 'Secret' })
  })

  test('a finding that is not there is 404, an ambiguous one 409 with its labels', async () => {
    h.fetch.mockResolvedValueOnce(answer({ found: false }))
    expect((await getFinding(get('finding', '&findingId=v1'))).status).toBe(404)
    h.fetch.mockResolvedValueOnce(answer({ found: false, ambiguous: ['Secret', 'Vulnerability'] }))
    const res = await getEvidence(get('evidence', '&findingId=v1'))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'ambiguous', labels: ['Secret', 'Vulnerability'] })
  })
})

describe('the board', () => {
  test('filters are validated and pushed down, facets and the latest run come back', async () => {
    h.fetch.mockResolvedValueOnce(answer({ findings: [{ id: 'v1' }], total: 1 }))
    h.fetch.mockResolvedValueOnce(answer({ total: 1, decided_by: { person: 1 } }))
    const res = await getFindings(get('findings', '&decidedBy=person&reviewedVia=mcp'))
    const body = await res.json()
    expect(sentBody(0)).toMatchObject({ op: 'list_findings', decided_by: 'person', reviewed_via: 'mcp' })
    expect(body).toMatchObject({ total: 1, latestRunId: 'run-latest',
                                 facets: { decided_by: { person: 1 } } })
  })

  test('an unknown filter value is a 400', async () => {
    for (const q of ['&decidedBy=anyone', '&reviewedVia=x', '&reviewCurrent=maybe']) {
      expect((await getFindings(get('findings', q))).status).toBe(400)
    }
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('facets that cannot be read are omitted, not an error', async () => {
    h.fetch.mockResolvedValueOnce(answer({ findings: [], total: 0 }))
    h.fetch.mockResolvedValueOnce(answer({ error: 'boom' }, 500))
    const res = await getFindings(get('findings'))
    expect(res.status).toBe(200)
    expect(await res.json()).not.toHaveProperty('facets')
  })

  test('an imported project with no runs falls back to its findings\' run id', async () => {
    h.latestRun.mockResolvedValue(null)
    h.fetch.mockResolvedValueOnce(answer({
      findings: [{ id: 'v1', triage_run_id: 'imported-run', triaged_at: '2026-01-01' }], total: 1 }))
    h.fetch.mockResolvedValueOnce(answer({}))
    expect((await (await getFindings(get('findings'))).json()).latestRunId).toBe('imported-run')
  })
})

describe('the verdict', () => {
  test('is rescored, returns the new row, and is audited with the real actor', async () => {
    const res = await postVerdict(post({ projectId: PROJECT, nodeId: 'v1', status: 'confirmed',
                                         reason: 'checked by hand' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ updated: true, rescored: true, after: { score: 75 } })
    expect(sentBody()).toMatchObject({ op: 'human_verdict', status: 'confirmed',
                                       reason: 'checked by hand' })
    await new Promise((r) => setTimeout(r, 0))
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'triage.verdict',
      after: expect.objectContaining({ realActorUserId: 'admin-behind', status: 'confirmed',
                                       before: { score: 40 }, after: { score: 75 } }),
    }))
  })

  test('Reset is a verdict status', async () => {
    await postVerdict(post({ projectId: PROJECT, nodeId: 'v1', status: 'unreviewed' }))
    expect(sentBody().status).toBe('unreviewed')
  })

  test('a bad label is named as the label, not as a missing nodeId', async () => {
    const res = await postVerdict(post({ projectId: PROJECT, nodeId: 'v1', status: 'confirmed',
                                         label: 'Host' }))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/^label must be one of/)
    const missing = await postVerdict(post({ projectId: PROJECT, status: 'confirmed' }))
    expect((await missing.json()).error).toBe('nodeId is required')
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('is refused during a version switch, with no write', async () => {
    h.activation.mockResolvedValue(true)
    const res = await postVerdict(post({ projectId: PROJECT, nodeId: 'v1', status: 'confirmed' }))
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'busy' })
    expect(h.fetch).not.toHaveBeenCalled()
  })
})
