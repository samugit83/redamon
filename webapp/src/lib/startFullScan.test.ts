/**
 * The shared full-scan start path (Sections 3 + 7.2).
 *
 * Manual and scheduled scans both go through here, so this is where the
 * load-bearing behavior is pinned: the activation lock, freeze-before-start
 * (fail closed), `mode` passthrough, and the ScanJob history for every outcome.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  orchestratorFetch: vi.fn(),
  isActivating: vi.fn(),
  busy: vi.fn(),
  prepare: vi.fn(),
  rollback: vi.fn(),
  createJob: vi.fn(),
  retention: vi.fn(),
  countAuthorizations: vi.fn(),
  findAuthorization: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.findProject(...a) },
    // A third-party engagement must carry an authorization record before a scan
    // starts, so the start path counts them.
    engagementAuthorization: {
      count: (...a: unknown[]) => h.countAuthorizations(...a),
      findFirst: (...a: unknown[]) => h.findAuthorization(...a),
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.isActivating(...a) }))
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: (...a: unknown[]) => h.busy(...a) }))
vi.mock('@/lib/scanRetention', () => ({ applyRetentionSafe: (...a: unknown[]) => h.retention(...a) }))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  prepareVersionsForFullScan: (...a: unknown[]) => h.prepare(...a),
  rollbackPreparedVersions: (...a: unknown[]) => h.rollback(...a),
  createScanJob: (...a: unknown[]) => h.createJob(...a),
}))

import { startFullScan } from './startFullScan'
import { SnapshotFreezeError } from './scanTimeline'
import { classifyStartFailure } from './scanStartOutcome'

const orchestratorBody = () => JSON.parse(h.orchestratorFetch.mock.calls[0][1].body)

beforeEach(() => {
  vi.clearAllMocks()
  h.isActivating.mockResolvedValue(false)
  h.busy.mockResolvedValue(null)
  // `internal` is what every project created before engagement kinds existed
  // reads as, and it is the shape these tests are about.
  h.findProject.mockResolvedValue({
    id: 'p1', userId: 'owner', targetDomain: 'x.tld', ipMode: false, targetIps: [],
    engagementKind: 'internal', roeGlobalMaxRps: 0,
  })
  h.countAuthorizations.mockResolvedValue(0)
  h.findAuthorization.mockResolvedValue(null)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ project_id: 'p1', status: 'starting' }) })
  h.prepare.mockResolvedValue({
    currentVersion: { id: 'v3', seq: 3, label: 'Scan 3' },
    frozenVersionId: 'v2',
    frozenNodeCount: 120,
  })
  h.rollback.mockResolvedValue(true)
  h.createJob.mockResolvedValue({ id: 'job1' })
  h.retention.mockResolvedValue(null)
})

describe('a third-party engagement cannot start without its ceiling and its authorization', () => {
  // The rule lives HERE rather than in the MCP tool, because an agent-facing
  // rule that only applies when an agent is present is not a control: the
  // scheduler and the queue dispatcher reach this same function with nobody
  // watching.
  const thirdParty = (over: Record<string, unknown> = {}) => ({
    id: 'p1', userId: 'owner', targetDomain: 'x.tld', ipMode: false, targetIps: [],
    engagementKind: 'third_party', roeGlobalMaxRps: 3,
    ...over,
  })

  test('a ceiling and a record together are enough', async () => {
    h.findProject.mockResolvedValue(thirdParty())
    h.countAuthorizations.mockResolvedValue(1)
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(true)
  })

  test('no authorization record refuses the start', async () => {
    h.findProject.mockResolvedValue(thirdParty())
    h.countAuthorizations.mockResolvedValue(0)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.error).toMatch(/authorization record/i)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('the refusal is 422, which the queue and the scheduler treat as permanent', async () => {
    // A 409 reads as "busy" and is requeued for ever; only a person can add the
    // ceiling or the record.
    h.findProject.mockResolvedValue(thirdParty())
    h.countAuthorizations.mockResolvedValue(0)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 422 })
    if (res.ok) throw new Error('unreachable')
    expect(classifyStartFailure(res.status, res).kind).toBe('permanent')
  })

  test('a ceiling of 0 refuses the start, because 0 means NO ceiling', async () => {
    h.findProject.mockResolvedValue(thirdParty({ roeGlobalMaxRps: 0 }))
    h.countAuthorizations.mockResolvedValue(1)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.error).toMatch(/NO ceiling/)
  })

  test('a ceiling written IS a ceiling applied', async () => {
    // There is no second switch that could leave the number configured and
    // inert. The engagement's limits are derived from whether a limit is SET,
    // so a project cannot show a 3 rps ceiling and run unlimited.
    h.findProject.mockResolvedValue(thirdParty({ roeGlobalMaxRps: 3 }))
    h.countAuthorizations.mockResolvedValue(1)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(true)
  })

  test('an unreadable authorization set blocks rather than passes', async () => {
    // "We could not check" is not "it is allowed".
    h.findProject.mockResolvedValue(thirdParty())
    h.countAuthorizations.mockRejectedValue(new Error('database down'))
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(false)
  })

  test('an internal project with no ceiling still starts', async () => {
    // Every project that predates the column reads as internal. Turning them
    // all red at once is not a fix; they are flagged instead.
    h.countAuthorizations.mockResolvedValue(0)
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(true)
  })

  test('the refusal happens BEFORE the graph is frozen', async () => {
    // A refused start must leave no version behind: a frozen graph for a scan
    // that never ran consumes a retention slot and deletes the oldest unpinned
    // version.
    h.findProject.mockResolvedValue(thirdParty())
    h.countAuthorizations.mockResolvedValue(0)
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.prepare).not.toHaveBeenCalled()
  })
})

describe('provenance is recorded on the job row', () => {
  test('a started run carries its settings hash and its authorization', async () => {
    // Without these the chain from a graph node back to the configuration that
    // produced it breaks: JobQueue.settingsHash is the only other settings
    // fingerprint and it is deleted with the queue row at dispatch.
    h.findAuthorization.mockResolvedValue({ id: 'auth1' })
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    const data = h.createJob.mock.calls.at(-1)![0]
    expect(typeof data.settingsHash).toBe('string')
    expect(data.settingsHash).toHaveLength(64)
    expect(data.authorizationId).toBe('auth1')
  })

  test('an internal project records no authorization, which is not an error', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.createJob.mock.calls.at(-1)![0].authorizationId).toBeNull()
  })

  test('a provenance failure does not fail the start', async () => {
    // History is a side effect of starting a scan. A null hash reads as "not
    // recorded", which is honest; a failed start would not be.
    h.findAuthorization.mockRejectedValue(new Error('database down'))
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(true)
    expect(h.createJob.mock.calls.at(-1)![0].authorizationId).toBeNull()
  })
})

describe('activation lock (4A.3)', () => {
  test('refuses while the graph is being swapped, before any freeze or spawn', async () => {
    h.isActivating.mockResolvedValue(true)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.status).toBe(409)
    expect(res.activationInProgress).toBe(true)
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('Risk 1: never snapshot a mid-write graph', () => {
  test('a scan already running is rejected BEFORE the freeze, with no version churn', async () => {
    // The orchestrator would reject the duplicate start anyway, but by then we
    // would have captured a snapshot of a graph the running scan is rewriting
    // AND minted a version for a scan that never happens.
    h.busy.mockResolvedValue('a full recon scan is running')
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.status).toBe(409)
    expect(res.error).toMatch(/already running|scan is running/i)
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('an active partial recon also blocks the freeze', async () => {
    h.busy.mockResolvedValue('a partial recon run is active')
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 409 })
    expect(h.prepare).not.toHaveBeenCalled()
  })

  test('a running AGENT session does not block a scan (unchanged behavior)', async () => {
    // Agents legitimately run while a scan runs; only the graph-swapping
    // activation is mutually exclusive with them.
    h.busy.mockResolvedValue(null)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(true)
  })
})

describe('preconditions', () => {
  test('unknown project → 404 before any version work', async () => {
    h.findProject.mockResolvedValue(null)
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 404 })
    expect(h.prepare).not.toHaveBeenCalled()
  })

  test('no target configured → 400 before any version work', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [] })
    expect(await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .toMatchObject({ ok: false, status: 400 })
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', targetDomain: '', ipMode: true, targetIps: [] })
    expect(await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .toMatchObject({ ok: false, status: 400 })
    expect(h.prepare).not.toHaveBeenCalled()
  })
})

describe('an IP project\'s hostname policy (Hostnames on target IPs)', () => {
  const ipProject = (over: Record<string, unknown> = {}) => ({
    id: 'p1', userId: 'owner', targetDomain: '', ipMode: true, targetIps: ['203.0.113.0/30'],
    engagementKind: 'internal', roeGlobalMaxRps: 0, ipHostnameMode: 'record_only', ipHostnameInclude: [],
    ...over,
  })

  test('the start loads every policy column, so none reads as its default', async () => {
    h.findProject.mockResolvedValue(ipProject())
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    const select = h.findProject.mock.calls[0][0].select
    for (const key of ['ipHostnameMode', 'ipHostnameInclude', 'ipHostnameExclude', 'ipHostnamePassiveExpand',
      'ipHostnameScanAllConfirmed', 'ipHostnameMaxScanned', 'ipHostnamePassiveMaxNames', 'engagementKind']) {
      expect(select[key], key).toBe(true)
    }
  })

  test.each([
    ['an unconfirmed scan_all', { ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: false }, 'not confirmed'],
    ['a record_filter with no include entry', { ipHostnameMode: 'record_filter' }, 'no include entry'],
  ])('%s is refused with 422 before any version work, scheduled or queued', async (_name, over, needle) => {
    h.findProject.mockResolvedValue(ipProject(over))
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 422, code: 'scope_invalid' })
    if (res.ok) throw new Error('unreachable')
    expect(res.error).toContain(needle)
    expect(classifyStartFailure(res.status, res).kind).toBe('permanent')
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test.each([
    ['record_only', {}],
    ['a confirmed scan_all', { ipHostnameMode: 'scan_all', ipHostnameScanAllConfirmed: true }],
    ['a record_filter with an include entry', { ipHostnameMode: 'record_filter', ipHostnameInclude: ['*.example.com'] }],
  ])('%s starts', async (_name, over) => {
    h.findProject.mockResolvedValue(ipProject(over))
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(true)
  })
})

describe('freeze ordering and fail-closed', () => {
  test('the freeze happens BEFORE the orchestrator is asked to start', async () => {
    const order: string[] = []
    h.prepare.mockImplementation(async () => {
      order.push('freeze')
      return { currentVersion: { id: 'v3', seq: 3, label: 'Scan 3' }, frozenVersionId: 'v2', frozenNodeCount: 1 }
    })
    h.orchestratorFetch.mockImplementation(async () => {
      order.push('start')
      return { ok: true, json: async () => ({}) }
    })
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(order).toEqual(['freeze', 'start'])
  })

  test('a freeze failure aborts: no scan started, no job row (Risk 4)', async () => {
    h.prepare.mockRejectedValue(new SnapshotFreezeError('Could not snapshot the current graph'))
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 500, snapshotFailed: true })
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('an unexpected error is not swallowed as a "snapshot failed"', async () => {
    h.prepare.mockRejectedValue(new Error('programming error'))
    await expect(startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .rejects.toThrow('programming error')
  })
})

describe('mode + trigger', () => {
  test.each(['new', 'overwrite'] as const)('mode %s is forwarded to the orchestrator', async mode => {
    await startFullScan({ projectId: 'p1', mode, trigger: 'manual' })
    expect(h.prepare).toHaveBeenCalledWith('p1', mode, null)
    expect(orchestratorBody().mode).toBe(mode)
  })

  test('a scheduled run records trigger + scheduleId on the job', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1', actorUserId: 'u1' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      trigger: 'scheduled', scheduleId: 's1', status: 'running', initiatedByUserId: 'u1',
    }))
  })
})

describe('history for every outcome', () => {
  test('success records a running job against the new current version', async () => {
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual', actorUserId: 'u1' })
    expect(res).toMatchObject({ ok: true, versionId: 'v3', frozenVersionId: 'v2', scanJobId: 'job1' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'p1', versionId: 'v3', status: 'running',
    }))
  })

  test('a RAM rejection is recorded as deferred_ram with its reason', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 429,
      json: async () => ({ detail: { limitType: 'ram', detail: 'Not enough free memory' } }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 429 })
    if (res.ok) throw new Error('unreachable')
    expect(res.limit).toMatchObject({ limitType: 'ram' })
    expect(res.error).toMatch(/RAM limit/)
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      status: 'deferred_ram', ramReason: 'Not enough free memory', scheduleId: 's1',
    }))
  })

  test('a configured (hard) limit is recorded as failed, not deferred', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 429,
      json: async () => ({ detail: { limitType: 'hard', detail: '2 of 2 concurrent scans allowed', settingName: 'RECON_MAX_CONCURRENT_GLOBAL' } }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    if (res.ok) throw new Error('unreachable')
    expect(res.error).toMatch(/configured limit/)
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }))
  })

  test('a plain rejection (e.g. RoE window) is recorded as failed and surfaced verbatim', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 403, json: async () => ({ detail: 'Outside the RoE time window' }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })
    expect(res).toMatchObject({ ok: false, status: 403, error: 'Outside the RoE time window' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }))
  })

  test('a job-write failure does not fail the start (history is best-effort)', async () => {
    h.createJob.mockRejectedValue(new Error('db down'))
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(true)
    if (!res.ok) throw new Error('unreachable')
    expect(res.scanJobId).toBeNull()
  })
})

// P0-2: a start the orchestrator refuses must cost the user nothing. Before
// this, the freeze ran first and carried retention with it, so retrying a 403
// in a loop minted a version, stored a duplicate snapshot and evicted the
// oldest saved version on every attempt.
describe('P0-2: a refused start leaves the timeline untouched', () => {
  const refuse = (status: number, detail: unknown) =>
    h.orchestratorFetch.mockResolvedValue({ ok: false, status, json: async () => ({ detail }) })

  test('retention never runs for a start that did not begin', async () => {
    refuse(403, 'Hard guardrail: government domain')
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.retention).not.toHaveBeenCalled()
  })

  test('retention runs once the orchestrator has accepted', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.retention).toHaveBeenCalledWith('p1')
  })

  test('a definitive refusal rolls the prepared version back', async () => {
    refuse(403, 'Outside the RoE time window')
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 403 })
    expect(h.rollback).toHaveBeenCalledWith('p1', expect.objectContaining({ frozenVersionId: 'v2' }))
  })

  test.each([400, 403, 409, 429, 500])('status %i rolls back', async status => {
    refuse(status, 'nope')
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.rollback).toHaveBeenCalledOnce()
  })

  test('the failure ScanJob is recorded against the RESTORED current version', async () => {
    refuse(403, 'Outside the RoE time window')
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ versionId: 'v2' }))
  })

  test('a rollback that could not be applied keeps the job on the minted version', async () => {
    // Honesty over tidiness: if the rollback failed, v3 is still the current
    // version, so pointing the history row at v2 would misdescribe the timeline.
    h.rollback.mockResolvedValue(false)
    refuse(403, 'nope')
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ versionId: 'v3' }))
  })

  test('an overwrite start has nothing to roll back and says so', async () => {
    h.prepare.mockResolvedValue({
      currentVersion: { id: 'v3', seq: 3, label: 'Scan 3' },
      frozenVersionId: null,
      frozenNodeCount: 0,
    })
    h.rollback.mockResolvedValue(false)
    refuse(403, 'nope')
    await startFullScan({ projectId: 'p1', mode: 'overwrite', trigger: 'manual' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ versionId: 'v3' }))
  })

  test('a successful start never rolls back', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.rollback).not.toHaveBeenCalled()
  })
})

describe('P0-2: a thrown orchestrator call is an UNKNOWN outcome, not a refusal', () => {
  beforeEach(() => {
    h.orchestratorFetch.mockRejectedValue(new Error('fetch timeout'))
  })

  test('it does NOT roll back: the container may already be running', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.rollback).not.toHaveBeenCalled()
  })

  test('it returns a distinct startOutcome so callers poll before retrying', async () => {
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res.ok).toBe(false)
    if (res.ok) throw new Error('unreachable')
    expect(res.startOutcome).toBe('unknown')
    expect(res.status).toBe(503)
    expect(res.error).toMatch(/unknown whether the scan started/i)
  })

  test('it writes a failed ScanJob rather than leaving no history at all', async () => {
    // Previously this case threw straight out of startFullScan, so the attempt
    // left no trace anywhere.
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed', versionId: 'v3',
    }))
  })

  test('it does not throw out of startFullScan', async () => {
    await expect(startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .resolves.toMatchObject({ ok: false })
  })

  test('retention does not run on an unknown outcome', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.retention).not.toHaveBeenCalled()
  })
})

describe('P0-2: the per-project mutex serialises every start path', () => {
  test('two concurrent starts produce exactly one orchestrator call', async () => {
    // The loser must be refused by the writer check it can now actually see,
    // instead of racing past it and freezing a second time.
    let started = false
    h.busy.mockImplementation(async () => (started ? 'a full recon scan is running' : null))
    h.orchestratorFetch.mockImplementation(async () => {
      started = true
      return { ok: true, json: async () => ({}) }
    })

    const [a, b] = await Promise.all([
      startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }),
      startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }),
    ])

    expect(h.orchestratorFetch).toHaveBeenCalledOnce()
    expect(h.prepare).toHaveBeenCalledOnce()
    expect([a.ok, b.ok].sort()).toEqual([false, true])
  })

  test('different projects are not serialised against each other', async () => {
    const seen: string[] = []
    let release: (() => void) | undefined
    const gate = new Promise<void>(r => { release = r })
    h.orchestratorFetch.mockImplementation(async (url: string) => {
      seen.push(url)
      if (seen.length === 1) await gate
      return { ok: true, json: async () => ({}) }
    })

    const p1 = startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    const p2 = startFullScan({ projectId: 'p2', mode: 'new', trigger: 'manual' })
    // p2 must reach the orchestrator while p1 is still blocked on the gate.
    await vi.waitFor(() => expect(seen.length).toBe(2))
    release!()
    await Promise.all([p1, p2])
  })

  test('a rejected start releases the lock for the next caller', async () => {
    h.prepare.mockRejectedValueOnce(new Error('programming error'))
    await expect(startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .rejects.toThrow('programming error')
    // The next start must not hang behind the failed one.
    await expect(startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .resolves.toMatchObject({ ok: true })
  })
})

// Strategy row 1: a Domain-batch project must be able to start a scan.
// Its scope is derived from domainBatchHosts, not targetDomain (which is empty),
// so the single-domain precondition would have refused every batch scan outright.
describe('domain batch preconditions', () => {
  const batchProject = (hosts: unknown, over: Record<string, unknown> = {}) => ({
    id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [],
    domainBatchMode: true, domainBatchHosts: hosts, ...over,
  })

  test('a batch with hosts starts and reaches the orchestrator', async () => {
    h.findProject.mockResolvedValue(batchProject(['sub1.domain1.com', 'sub2.domain2.it']))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(true)
    expect(h.orchestratorFetch).toHaveBeenCalledOnce()
    expect(orchestratorBody().project_id).toBe('p1')
  })

  test.each([[[]], [null]])('no hosts (%j) is refused as scope_invalid and never starts a container', async hosts => {
    h.findProject.mockResolvedValue(batchProject(hosts))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r).toMatchObject({ ok: false, status: 422, code: 'scope_invalid' })
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
    expect(h.prepare).not.toHaveBeenCalled()
  })

  test('a batch is not held to the single-domain targetDomain requirement', async () => {
    h.findProject.mockResolvedValue(batchProject(['*.a.com', 'a.com']))
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(true)
  })

  test('the stored group record is never read: hosts decide', async () => {
    h.findProject.mockResolvedValue(batchProject(['www.example.com'], {
      domainBatchGroups: [],
    }))
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(true)
  })

  test('a non-batch project with no target still fails as before', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [],
      domainBatchMode: false, domainBatchHosts: [],
    })
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })

    expect(r.ok).toBe(false)
    expect((r as { error: string }).error).toContain('no target domain')
  })
})

// WEB-14: a stored scope the current rules refuse (a list saved before a public
// suffix was added, a legacy wildcard on a suffix) fails closed with a distinct
// code. 422, never 409: the queue requeues a 409 as "busy" for ever.
describe('a saved scope the rules now refuse', () => {
  test('a batch entry on a public suffix is refused, naming the entry', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: '', ipMode: false, targetIps: [],
      domainBatchMode: true, domainBatchHosts: ['*.com.vn', 'www.example.com'],
    })
    const r = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', scheduleId: 's1' })

    expect(r).toMatchObject({
      ok: false, status: 422, code: 'scope_invalid',
      invalidEntries: [{ entry: '*.com.vn', reason: 'wildcard_on_suffix' }],
    })
    if (r.ok) throw new Error('unreachable')
    expect(r.error).toContain('*.com.vn')
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('a single-domain target that is a public suffix is refused', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: 'co.uk', ipMode: false, targetIps: [],
      domainBatchMode: false, subdomainList: [],
    })
    expect(await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .toMatchObject({ ok: false, status: 422, code: 'scope_invalid' })
  })

  test('a single-domain prefix the rules refuse is refused', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: 'example.com', ipMode: false, targetIps: [],
      domainBatchMode: false, subdomainList: ['www.', '*'],
    })
    expect(await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' }))
      .toMatchObject({ ok: false, status: 422, code: 'scope_invalid', invalidEntries: [{ entry: '*', reason: 'invalid_prefix' }] })
  })

  test('an IP-mode project is not judged on its leftover domain fields', async () => {
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: 'co.uk', ipMode: true, targetIps: ['192.0.2.10'],
      domainBatchMode: false, subdomainList: [],
    })
    expect((await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })).ok).toBe(true)
  })
})

describe('the run records which RoE document it started under', () => {
  test('the digest of the stored RoE text reaches the job, read before the start', async () => {
    const { digestScopeDocument } = await import('./engagement')
    h.findProject.mockResolvedValue({
      id: 'p1', userId: 'owner', targetDomain: 'x.tld', ipMode: false, targetIps: [],
      engagementKind: 'internal', roeGlobalMaxRps: 0, roeRawText: 'RoE v1: max 5 rps',
    })
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual', actorUserId: 'owner' })
    expect(h.createJob.mock.calls[0][0].roeTextSha256).toBe(digestScopeDocument('RoE v1: max 5 rps'))
  })

  test('no document records null', async () => {
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual', actorUserId: 'owner' })
    expect(h.createJob.mock.calls[0][0].roeTextSha256).toBeNull()
  })
})

describe('a failed container spawn is a refusal, not an accepted start (plan 12.9)', () => {
  test('an older orchestrator answering 2xx with status error rolls back and records a failed run', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: true, json: async () => ({ project_id: 'p1', status: 'error', error: 'No such image: redamon-recon:latest' }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 500, code: 'spawn_failed' })
    if (res.ok) throw new Error('unreachable')
    expect(res.error).toMatch(/No such image/)
    expect(h.rollback).toHaveBeenCalledOnce()
    expect(h.retention).not.toHaveBeenCalled()
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed', versionId: 'v2' }))
    expect(h.createJob).not.toHaveBeenCalledWith(expect.objectContaining({ status: 'running' }))
  })

  test('the orchestrator\'s 500 spawn_failed carries its code through', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 500,
      json: async () => ({ detail: { detail: 'Failed to start: image missing', code: 'spawn_failed' } }),
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 500, code: 'spawn_failed', error: 'Failed to start: image missing' })
    if (res.ok) throw new Error('unreachable')
    expect(classifyStartFailure(res.status, res, { orchestratorAnswered: true }).temporary).toBe(false)
  })
})

describe('a headless caller records no failed run for a transient refusal (plan 12.6)', () => {
  const answered503 = () => h.orchestratorFetch.mockResolvedValue({
    ok: false, status: 503,
    json: async () => ({ detail: 'Cannot verify scan scope: the webapp is unreachable (URLError). Refusing to start.' }),
  })

  test('quietTransient skips the failed ScanJob, still rolls back', async () => {
    answered503()
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', quietTransient: true })
    expect(res).toMatchObject({ ok: false, status: 503 })
    expect(h.createJob).not.toHaveBeenCalled()
    expect(h.rollback).toHaveBeenCalledOnce()
  })

  test('a manual start still records it', async () => {
    answered503()
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }))
  })

  test('quietTransient still records a permanent refusal', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: false, status: 403, json: async () => ({ detail: 'RoE window' }) })
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', quietTransient: true })
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }))
  })
})

describe('an orchestrator that never answered says why, and whether anything started', () => {
  const refused = () => Object.assign(new TypeError('fetch failed'), {
    cause: Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8010'), { code: 'ECONNREFUSED' }),
  })
  const timedOut = () => Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' })

  test('a refused connection is 503 orchestrator_unreachable: certainly not started', async () => {
    h.orchestratorFetch.mockRejectedValue(refused())
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({
      ok: false, status: 503, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED',
      error: 'The orchestrator could not be reached, so the scan was not started.',
    })
    if (res.ok) throw new Error('unreachable')
    expect(res.startOutcome).toBeUndefined()
  })

  test('nothing reached the orchestrator, so the freeze is undone like any refusal', async () => {
    h.orchestratorFetch.mockRejectedValue(refused())
    await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(h.rollback).toHaveBeenCalledOnce()
    expect(h.retention).not.toHaveBeenCalled()
    expect(h.createJob).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed', versionId: 'v2', ramReason: 'the orchestrator could not be reached',
    }))
  })

  test('the queue and the scheduler retry it as transient, with no failed run per attempt', async () => {
    h.orchestratorFetch.mockRejectedValue(refused())
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'scheduled', quietTransient: true })
    if (res.ok) throw new Error('unreachable')
    expect(classifyStartFailure(res.status, res, { orchestratorAnswered: res.startOutcome !== 'unknown' }).kind)
      .toBe('transient')
    expect(h.createJob).not.toHaveBeenCalled()
  })

  test('a timeout is 504 orchestrator_timeout and keeps the outcome unknown', async () => {
    h.orchestratorFetch.mockRejectedValue(timedOut())
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 504, code: 'orchestrator_timeout', startOutcome: 'unknown' })
    expect(h.rollback).not.toHaveBeenCalled()
  })

  test('a reset after the request went out keeps the outcome unknown', async () => {
    h.orchestratorFetch.mockRejectedValue(Object.assign(new TypeError('fetch failed'), {
      cause: Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }),
    }))
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ status: 503, code: 'orchestrator_unreachable', cause: 'ECONNRESET', startOutcome: 'unknown' })
    expect(h.rollback).not.toHaveBeenCalled()
  })

  test('an answered error carries the orchestrator status, even with a non-JSON body', async () => {
    h.orchestratorFetch.mockResolvedValue({
      ok: false, status: 500, json: async () => { throw new SyntaxError('Unexpected token I') },
    })
    const res = await startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
    expect(res).toMatchObject({ ok: false, status: 500, upstreamStatus: 500, error: 'Failed to start recon' })
  })
})
