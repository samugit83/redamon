/**
 * The queue's start path refuses what only a person can fix with a status the
 * queue treats as permanent: a 409 reads as "busy" there and would requeue the
 * job forever. Two such refusals: an old-model graph (§4.11.6) for the writers
 * that attach to Domain nodes, and a third-party engagement that is not startable.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  legacy: vi.fn(),
  orchestratorFetch: vi.fn(),
  engagement: vi.fn(),
  roeSha: vi.fn(),
  nodeFilterWriter: vi.fn(),
  scanJobCreate: vi.fn(),
  trufflehog: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findUnique(...a) },
    scanJob: { create: (...a: unknown[]) => h.scanJobCreate(...a) },
  },
}))
vi.mock('@/lib/engagement', () => ({
  loadEngagement: (...a: unknown[]) => h.engagement(...a),
  currentRoeTextSha256: (...a: unknown[]) => h.roeSha(...a),
}))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: (...a: unknown[]) => h.nodeFilterWriter(...a) }))
vi.mock('@/lib/trufflehogStart', () => ({ resolveTrufflehogStart: (...a: unknown[]) => h.trufflehog(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/startFullScan', async orig => ({
  ...(await orig<typeof import('@/lib/startFullScan')>()),
  startFullScan: vi.fn(),
}))
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: (...a: unknown[]) => h.legacy(...a),
}))

import { dispatchStart } from './startScan'
import { classifyStartFailure, isCapacityWait } from './scanStartOutcome'

const PROJECT = {
  id: 'p1', userId: 'u1', supplyChainInputMode: null, targetDomain: '',
  domainBatchMode: true, domainBatchHosts: ['www.acme.co.uk'],
}

beforeEach(() => {
  vi.clearAllMocks()
  h.findUnique.mockResolvedValue(PROJECT)
  h.legacy.mockResolvedValue(['co.uk'])
  h.engagement.mockResolvedValue({ blockers: [] })
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1' }) })
  h.roeSha.mockResolvedValue('sha-roe')
  h.nodeFilterWriter.mockResolvedValue(null)
  h.scanJobCreate.mockResolvedValue({ id: 'sj1' })
  h.trufflehog.mockResolvedValue({
    ok: true, source: 'docker', body: { project_id: 'p1', user_id: 'u1', source: 'docker', config: {} },
  })
})

describe('dispatchStart on an old-model graph', () => {
  test.each(['partial_recon', 'gvm', 'ai_attack'])('%s is refused, permanently', async kind => {
    const r = await dispatchStart(kind, 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(false)
    expect(r.status).toBe(422)
    expect(r.error).toMatch(/built before the current scope model; run a full recon first/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(classifyStartFailure(r.status, { error: r.error }).temporary).toBe(false)
  })

  test('a scanner that never attaches to Domain nodes is not asked', async () => {
    await dispatchStart('github_hunt', 'p1')
    expect(h.legacy).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })

  test('a current graph starts', async () => {
    h.legacy.mockResolvedValue([])
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(true)
  })
})

describe('dispatchStart on a third-party engagement that is not startable', () => {
  test('is refused permanently, so the queue does not retry it as busy', async () => {
    h.engagement.mockResolvedValue({ blockers: ['No authorization record.'] })
    const r = await dispatchStart('gvm', 'p1')
    expect(r.status).toBe(422)
    expect(classifyStartFailure(r.status, { error: r.error }).temporary).toBe(false)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('says what the full start and the manual routes say, word for word', async () => {
    h.legacy.mockResolvedValue([])
    h.engagement.mockResolvedValue({ blockers: ['No authorization record.'] })
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.error).toBe(
      'This is a third-party engagement and it is not startable: No authorization record. '
        + 'Use preflight_scope_check to see the whole picture.',
    )
  })
})

// L-12: the queue re-runs the start a person's button makes, so it must not start
// a run the button would refuse, and must leave the same history row.
describe('dispatchStart makes the manual start\'s graph checks and records the run', () => {
  const NON_FULL_KINDS = ['partial_recon', 'gvm', 'github_hunt', 'trufflehog', 'supply_chain', 'supply_chain_repo', 'ai_attack']

  beforeEach(() => {
    h.legacy.mockResolvedValue([])
  })

  test.each(NON_FULL_KINDS)('%s is requeued while a version activation swaps the graph, never started', async kind => {
    h.findUnique.mockResolvedValue({ ...PROJECT, activationState: 'activating', activationStartedAt: new Date() })
    const r = await dispatchStart(kind, 'p1', { payload: { tool_id: 'Tlsx', repo_url: 'https://example.com/r' } })
    expect(r).toMatchObject({ ok: false, status: 409, activationInProgress: true })
    expect(r.error).toMatch(/version activation is in progress/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.scanJobCreate).not.toHaveBeenCalled()
    const cls = classifyStartFailure(r.status, { error: r.error, activationInProgress: r.activationInProgress },
      { orchestratorAnswered: true })
    expect(cls.blockedCode).toBe('activating')
    expect(isCapacityWait(cls.blockedCode)).toBe(true)
  })

  test('a stale activation lock does not hold the queue', async () => {
    h.findUnique.mockResolvedValue({
      ...PROJECT, activationState: 'activating', activationStartedAt: new Date(Date.now() - 24 * 3600_000),
    })
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(true)
  })

  test('a partial recon is requeued while mute rules are being applied', async () => {
    h.nodeFilterWriter.mockResolvedValue('mute rules are being applied to the graph')
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 409 })
    expect(r.error).toBe('Cannot start a partial recon while mute rules are being applied to the graph. '
      + 'Try again when it finishes.')
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    const cls = classifyStartFailure(r.status, { error: r.error, busy: r.busy }, { orchestratorAnswered: true })
    expect(cls.blockedCode).toBe('busy')
    expect(isCapacityWait(cls.blockedCode)).toBe(true)
  })

  // The GVM button does not check the mute-rule apply either: only the partial
  // recon races it for the findings' mute state.
  test('a mute-rule apply does not hold a GVM scan', async () => {
    h.nodeFilterWriter.mockResolvedValue('mute rules are being applied to the graph')
    const r = await dispatchStart('gvm', 'p1')
    expect(r.ok).toBe(true)
    expect(h.nodeFilterWriter).not.toHaveBeenCalled()
  })

  test('a queued partial recon leaves the history row its button leaves', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true, json: async () => ({ run_id: 'r1', roots: ['alpha.test', 7, 'beta.test'] }),
    })
    const r = await dispatchStart('partial_recon', 'p1', { actorUserId: 'u1', payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: true, runId: 'r1', scanJobId: 'sj1' })
    expect(h.scanJobCreate).toHaveBeenCalledTimes(1)
    expect(h.scanJobCreate.mock.calls[0][0].data).toMatchObject({
      projectId: 'p1', kind: 'partial_recon', runId: 'r1', status: 'running',
      trigger: 'scheduled', mode: null, versionId: null, initiatedByUserId: 'u1',
      targets: ['alpha.test', 'beta.test'], roeTextSha256: 'sha-roe',
    })
    // Read before the start, as the routes do, so a RoE replaced mid-start
    // cannot misattribute the run.
    expect(h.roeSha.mock.invocationCallOrder[0]).toBeLessThan(h.orchestratorFetch.mock.invocationCallOrder[0])
  })

  test.each([
    ['trufflehog', 'docker'],
    ['ai_attack', 'r1'],
    ['gvm', ''],
    ['github_hunt', ''],
    ['supply_chain', ''],
  ])('a queued %s run is recorded under the run id the reconcile matches it by (%j)', async (kind, expected) => {
    const r = await dispatchStart(kind, 'p1', { actorUserId: 'u1' })
    expect(r.ok).toBe(true)
    expect(r.scanJobId).toBe('sj1')
    expect(h.scanJobCreate.mock.calls[0][0].data).toMatchObject({ kind, runId: expected, trigger: 'scheduled' })
  })

  test('an org-batch repo item writes no ScanJob: its history is the queue row', async () => {
    const r = await dispatchStart('supply_chain_repo', 'p1', { payload: { repo_url: 'https://example.com/r' } })
    expect(r.ok).toBe(true)
    expect(r.scanJobId ?? null).toBeNull()
    expect(h.scanJobCreate).not.toHaveBeenCalled()
  })

  test('a refused start records no run', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 500, json: async () => ({ detail: 'boom' }) })
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r.ok).toBe(false)
    expect(h.scanJobCreate).not.toHaveBeenCalled()
  })

  test('a history write that fails does not fail the scan that started', async () => {
    h.scanJobCreate.mockRejectedValue(new Error('db down'))
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: true, runId: 'r1', scanJobId: null })
  })
})

describe('dispatchStart tells the queue what the start really did (plan 12.6)', () => {
  test('a full recon forwards startOutcome, snapshotFailed and the body code', async () => {
    const { startFullScan } = await import('@/lib/startFullScan')
    const full = vi.mocked(startFullScan)
    full.mockResolvedValueOnce({
      ok: false, status: 503, startOutcome: 'unknown', error: 'no answer', scanJobId: 'sj1',
    })
    expect(await dispatchStart('full_recon', 'p1')).toMatchObject({
      ok: false, status: 503, startOutcome: 'unknown', scanJobId: 'sj1',
    })
    full.mockResolvedValueOnce({ ok: false, status: 500, error: 'freeze failed', snapshotFailed: true })
    expect(await dispatchStart('full_recon', 'p1')).toMatchObject({ snapshotFailed: true })
    full.mockResolvedValueOnce({ ok: false, status: 500, error: 'no image', code: 'spawn_failed' })
    expect(await dispatchStart('full_recon', 'p1')).toMatchObject({ code: 'spawn_failed' })
  })

  test('the queue starts full recons headless, so a transient refusal records no ScanJob', async () => {
    const { startFullScan } = await import('@/lib/startFullScan')
    const full = vi.mocked(startFullScan)
    full.mockResolvedValueOnce({ ok: false, status: 503, error: 'x' })
    await dispatchStart('full_recon', 'p1')
    expect(full).toHaveBeenLastCalledWith(expect.objectContaining({ quietTransient: true }))
  })

  test('a non-full start whose orchestrator call throws has an unknown outcome', async () => {
    h.legacy.mockResolvedValue([])
    h.orchestratorFetch.mockRejectedValue(new Error('The operation was aborted due to timeout'))
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 503, startOutcome: 'unknown' })
    expect(classifyStartFailure(r.status, { error: r.error, startOutcome: r.startOutcome },
      { orchestratorAnswered: false }).kind).toBe('unknown')
  })

  test('a refused connection certainly started nothing, so the queue may retry it', async () => {
    h.legacy.mockResolvedValue([])
    const refused = Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8010'), { code: 'ECONNREFUSED' }),
    })
    h.orchestratorFetch.mockRejectedValue(refused)
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 503, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(r.startOutcome).toBeUndefined()
    expect(classifyStartFailure(r.status, { error: r.error, code: r.code },
      { orchestratorAnswered: r.startOutcome !== 'unknown' }).kind).toBe('transient')
  })

  test('a timed-out start is 504 orchestrator_timeout with an unknown outcome', async () => {
    h.legacy.mockResolvedValue([])
    h.orchestratorFetch.mockRejectedValue(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }))
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 504, code: 'orchestrator_timeout', startOutcome: 'unknown' })
  })

  test('a non-full refusal carries the orchestrator status', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 502, json: async () => { throw new SyntaxError('html') } })
    const r = await dispatchStart('github_hunt', 'p1')
    expect(r).toMatchObject({ ok: false, status: 502, upstreamStatus: 502, error: 'Failed to start GitHub Secret Hunt' })
  })

  test('a non-full refusal forwards the orchestrator body code', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 500,
      json: async () => ({ detail: { detail: 'Failed to start: image missing', code: 'spawn_failed' } }),
    })
    const r = await dispatchStart('github_hunt', 'p1')
    expect(r).toMatchObject({ ok: false, status: 500, code: 'spawn_failed', error: 'Failed to start: image missing' })
  })
})

describe('dispatchStart on an IP project whose hostname policy recon would refuse', () => {
  const IP_PROJECT = {
    id: 'p1', userId: 'u1', supplyChainInputMode: null, targetDomain: '', ipMode: true,
    domainBatchMode: false, domainBatchHosts: [], engagementKind: 'internal',
  }

  test('a queued partial recon is refused permanently, with the reason', async () => {
    h.findUnique.mockResolvedValue({ ...IP_PROJECT, ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: false })
    h.legacy.mockResolvedValue([])
    const r = await dispatchStart('partial_recon', 'p1', { payload: { tool_id: 'Tlsx' } })
    expect(r).toMatchObject({ ok: false, status: 422 })
    expect(r.error).toContain('not confirmed')
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(classifyStartFailure(r.status, { error: r.error }).temporary).toBe(false)
    expect(h.findUnique.mock.calls.some(([arg]) => arg?.select?.ipHostnameScanAllConfirmed === true)).toBe(true)
  })

  test('a scanner that never loads the recon settings is not judged on it', async () => {
    h.findUnique.mockResolvedValue({ ...IP_PROJECT, ipHostnameMode: 'record_filter', ipHostnameInclude: [] })
    await dispatchStart('github_hunt', 'p1')
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })
})

describe('dispatchStart sends every kind a job credential for the project owner (step 1.16)', () => {
  test.each(['gvm', 'github_hunt', 'supply_chain', 'supply_chain_repo', 'partial_recon', 'ai_attack', 'trufflehog'])(
    '%s', async kind => {
      const { verifyJobCredential } = await import('@/lib/authz/machineCredential')
      const saved = process.env.INTERNAL_API_KEY
      process.env.INTERNAL_API_KEY = 'dispatch-test-master'
      h.legacy.mockResolvedValue([])
      try {
        const r = await dispatchStart(kind, 'p1', { actorUserId: 'admin-1', payload: { source: 'docker' } })
        expect(r.ok).toBe(true)
        const sent = JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)
        expect(verifyJobCredential(sent.job_credential)).toMatchObject({ aud: 'scan', ten: 'u1', pid: 'p1' })
        expect(sent.user_id).toBe('u1')
      } finally {
        if (saved === undefined) delete process.env.INTERNAL_API_KEY
        else process.env.INTERNAL_API_KEY = saved
      }
    },
  )
})

describe('dispatchStart names the job\'s actor beside the owner (step 5.5)', () => {
  test.each(['gvm', 'github_hunt', 'supply_chain', 'supply_chain_repo', 'partial_recon', 'ai_attack', 'trufflehog'])(
    '%s', async kind => {
      const saved = process.env.INTERNAL_API_KEY
      process.env.INTERNAL_API_KEY = 'dispatch-test-master'
      h.legacy.mockResolvedValue([])
      try {
        const r = await dispatchStart(kind, 'p1', { actorUserId: 'collab-1', payload: { source: 'docker' } })
        expect(r.ok).toBe(true)
        const sent = JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)
        expect(sent.actor_user_id).toBe('collab-1')
        expect(sent.user_id).toBe('u1')

        h.orchestratorFetch.mockClear()
        const owner = await dispatchStart(kind, 'p1', { actorUserId: null, payload: { source: 'docker' } })
        expect(owner.ok).toBe(true)
        expect(JSON.parse(h.orchestratorFetch.mock.calls[0][1].body).actor_user_id).toBe('u1')
      } finally {
        if (saved === undefined) delete process.env.INTERNAL_API_KEY
        else process.env.INTERNAL_API_KEY = saved
      }
    },
  )
})
