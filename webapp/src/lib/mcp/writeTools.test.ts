/**
 * The MCP write tools.
 *
 * These are the three places an external agent changes something, and each is
 * deliberately STRICTER than the equivalent button. The tests below are
 * written around the three ways that strictness could be quietly lost:
 *
 *  - start_recon stops being stricter than the button and wipes the graph
 *    under a human who is mid-session with the in-app agent
 *  - mode:"overwrite" stops needing its own scope, so an agent that read an
 *    injected instruction can discard a user's graph history
 *  - update_recon_settings starts accepting a scope field, turning a "rescan
 *    my own projects" credential into an attack-launching one
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  updateProject: vi.fn(),
  updateManyProjects: vi.fn(),
  findQueued: vi.fn(),
  findAuthProfile: vi.fn(),
  fireteamAudit: vi.fn(),
  findSchedules: vi.fn(),
  orchestratorFetch: vi.fn(),
  liveWriters: vi.fn(),
  scanWriters: vi.fn(),
  startFullScan: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findProject(...a),
      update: (...a: unknown[]) => h.updateProject(...a),
      updateMany: (...a: unknown[]) => h.updateManyProjects(...a),
    },
    jobQueue: { findMany: (...a: unknown[]) => h.findQueued(...a) },
    projectAuthProfile: { findUnique: (...a: unknown[]) => h.findAuthProfile(...a) },
    fireteamSettingsAudit: { createMany: (...a: unknown[]) => h.fireteamAudit(...a) },
    scanSchedule: { findMany: (...a: unknown[]) => h.findSchedules(...a) },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/graphWriters', () => ({
  describeLiveGraphWriters: (...a: unknown[]) => h.liveWriters(...a),
  describeScanWriters: (...a: unknown[]) => h.scanWriters(...a),
}))
vi.mock('@/lib/startFullScan', () => ({ startFullScan: (...a: unknown[]) => h.startFullScan(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { McpScopeError, McpAccessDenied, __resetRateLimiter } from '@/lib/mcpAuth'
import { settingsFingerprint } from '@/lib/jobQueue'
import { authProfileFingerprint } from '@/lib/authProfileFingerprint'
import { startRecon, stopRecon, updateReconSettings } from './writeTools'
import type { McpContext } from './tools'

const ALL_SCOPES = ['recon:read', 'recon:scan', 'recon:overwrite', 'recon:settings', 'graph:cypher']

const ctx = (scopes: string[] = ALL_SCOPES): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

/** The project updatedAt a write reads before its compare-and-swap. */
const READ_AT = new Date('2026-09-29T08:00:00.000Z')

const OK_START = {
  ok: true,
  state: { status: 'starting', current_phase: 'domain_discovery' },
  versionId: 'v4', versionSeq: 4, versionLabel: 'Scan 4',
  frozenVersionId: 'v3', frozenNodeCount: 120, scanJobId: 'job1',
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  __resetRateLimiter()
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', updatedAt: READ_AT })
  h.liveWriters.mockResolvedValue(null)
  h.scanWriters.mockResolvedValue(null)
  h.startFullScan.mockResolvedValue(OK_START)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'stopping' }) })
  h.findQueued.mockResolvedValue([])
  h.findAuthProfile.mockResolvedValue(null)
  h.findSchedules.mockResolvedValue([])
  h.updateProject.mockResolvedValue({})
  h.updateManyProjects.mockResolvedValue({ count: 1 })
  h.audit.mockResolvedValue(undefined)
})

// --- start_recon -----------------------------------------------------------------

describe('start_recon scopes', () => {
  test('needs recon:scan', async () => {
    await expect(startRecon(ctx(['recon:read']), 'p1')).rejects.toBeInstanceOf(McpScopeError)
    expect(h.startFullScan).not.toHaveBeenCalled()
  })

  test('mode "new" needs only recon:scan', async () => {
    await expect(startRecon(ctx(['recon:scan']), 'p1', 'new')).resolves.toBeTruthy()
  })

  test('mode "overwrite" needs recon:overwrite ON TOP of recon:scan', async () => {
    // The one irreversible action on this surface, so the containment is a
    // code check rather than prompt wording.
    await expect(startRecon(ctx(['recon:scan']), 'p1', 'overwrite'))
      .rejects.toBeInstanceOf(McpScopeError)
    expect(h.startFullScan).not.toHaveBeenCalled()
  })

  test('the scope error names recon:overwrite', async () => {
    await expect(startRecon(ctx(['recon:scan']), 'p1', 'overwrite'))
      .rejects.toThrow(/recon:overwrite/)
  })

  test('with both scopes, overwrite is allowed', async () => {
    await expect(startRecon(ctx(['recon:scan', 'recon:overwrite']), 'p1', 'overwrite'))
      .resolves.toBeTruthy()
  })

  test('the default mode is the non-destructive one', async () => {
    await startRecon(ctx(['recon:scan']), 'p1')
    expect(h.startFullScan.mock.calls[0][0].mode).toBe('new')
  })
})

describe('start_recon is stricter than the button', () => {
  test('a live in-app AGENT session blocks the start', async () => {
    // describeScanWriters deliberately excludes agent sessions, because a human
    // running the agent alongside a scan is normal AND VISIBLE to them. An
    // unattended external caller has no way to know.
    h.liveWriters.mockResolvedValue('an agent session is running')
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/agent session is running/)
    expect(h.startFullScan).not.toHaveBeenCalled()
  })

  test('a live TRIAGE run blocks the start', async () => {
    h.liveWriters.mockResolvedValue('a triage run is in progress')
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/triage run/)
  })

  test('it uses describeLiveGraphWriters, not the narrower describeScanWriters', async () => {
    await startRecon(ctx(), 'p1')
    expect(h.liveWriters).toHaveBeenCalledWith('p1')
  })

  test('the refusal explains that a scan would wipe the graph', async () => {
    h.liveWriters.mockResolvedValue('an agent session is running')
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/wipe the graph/)
  })
})

describe('start_recon results and failures', () => {
  test('it reports the version it minted and what happened to the old one', async () => {
    const r = await startRecon(ctx(), 'p1', 'new')
    expect(r.scanVersion).toEqual({ id: 'v4', seq: 4, label: 'Scan 4' })
    expect(r.frozenVersionId).toBe('v3')
    expect(r.frozenNodeCount).toBe(120)
    expect(r.note).toMatch(/retention slot/)
  })

  test('overwrite says plainly that the old graph is gone', async () => {
    const r = await startRecon(ctx(), 'p1', 'overwrite')
    expect(r.note).toMatch(/DISCARDED/)
    expect(r.note).toMatch(/cannot be recovered/)
  })

  test('the scan is attributed to the token owner', async () => {
    await startRecon(ctx(), 'p1')
    expect(h.startFullScan.mock.calls[0][0].actorUserId).toBe('owner')
  })

  test('the trigger stays "manual" - the audit record carries the channel', async () => {
    // Extending the ScanTrigger union would break the timeline UI that renders it.
    await startRecon(ctx(), 'p1')
    expect(h.startFullScan.mock.calls[0][0].trigger).toBe('manual')
  })

  test.each([
    [403, 'Outside the RoE time window'],
    [409, 'A scan is already running'],
    [400, 'Project has no target domain configured'],
  ])('a %i refusal surfaces its reason', async (status, error) => {
    h.startFullScan.mockResolvedValue({ ok: false, status, error })
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(error)
  })

  test('a memory-admission refusal carries the structured limit payload', async () => {
    h.startFullScan.mockResolvedValue({
      ok: false, status: 409, error: 'RAM limit reached',
      limit: { limitType: 'ram', detail: 'Not enough free memory' },
    })
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/limitType/)
  })

  test('an UNKNOWN start outcome tells the caller to poll before retrying', async () => {
    h.startFullScan.mockResolvedValue({
      ok: false, status: 503, startOutcome: 'unknown',
      error: 'The orchestrator did not answer, so it is unknown whether the scan started.',
    })
    await expect(startRecon(ctx(), 'p1')).rejects.toMatchObject({
      code: 'start_outcome_unknown',
      message: expect.stringMatching(/get_recon_status/),
    })
  })

  test('a REFUSED start still consumes the strict bucket', async () => {
    // Deliberate: the bucket exists precisely to stop a retry loop against a
    // 403 from churning the version timeline.
    h.startFullScan.mockResolvedValue({ ok: false, status: 403, error: 'RoE window' })
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/RoE window/)
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/rate limit/i)
  })

  test('a refusal is audited, not just a success', async () => {
    h.startFullScan.mockResolvedValue({ ok: false, status: 403, error: 'nope' })
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow()
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'mcp.start_recon.refused',
    }))
  })

  test("another user's project is refused before anything starts", async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(startRecon(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.startFullScan).not.toHaveBeenCalled()
  })
})

describe('start_recon rate limiting', () => {
  test('the strict bucket is PER PROJECT', async () => {
    await startRecon(ctx(), 'p1')
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/rate limit/i)
    // A different project has its own budget.
    await expect(startRecon(ctx(), 'p2')).resolves.toBeTruthy()
  })

  test('the limit is checked AFTER ownership, so it cannot be used to probe', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(startRecon(ctx(), 'pX')).rejects.toBeInstanceOf(McpAccessDenied)
  })
})

// --- stop_recon --------------------------------------------------------------------

describe('stop_recon', () => {
  test('needs recon:scan', async () => {
    await expect(stopRecon(ctx(['recon:read']), 'p1')).rejects.toBeInstanceOf(McpScopeError)
  })

  test('an agent that can start can stop', async () => {
    await expect(stopRecon(ctx(['recon:scan']), 'p1'))
      .resolves.toMatchObject({ status: 'stopping' })
  })

  // REGRESSION (e2e finding: a stop that stopped nothing looked like a stop
  // that worked). The orchestrator answers a stop with the post-stop state,
  // which is `idle` either way, and this tool returned it verbatim. An agent
  // winding a test down inside its rules of engagement could not report whether
  // it had actually halted anything, and the audit row said `outcome: ok` for
  // both. Worse in the other direction: a stray stop that DID kill a running
  // scan was indistinguishable from a harmless no-op.
  describe('REGRESSION: a stop says whether it stopped anything', () => {
    test('stopping a running scan reports stopped: true', async () => {
      h.orchestratorFetch
        .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'running' }) })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'stopping' }) })
      const r = await stopRecon(ctx(), 'p1') as Record<string, unknown>
      expect(r.stopped).toBe(true)
      expect(String(r.note)).toMatch(/was running/i)
    })

    test('stopping an idle project reports stopped: false, not a bare success',
      async () => {
        h.orchestratorFetch
          .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'idle' }) })
          .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'idle' }) })
        const r = await stopRecon(ctx(), 'p1') as Record<string, unknown>
        expect(r.stopped).toBe(false)
        expect(String(r.note)).toMatch(/nothing/i)
      })

    test('an unreadable pre-stop status reports UNKNOWN, never false', async () => {
      // Fails closed the way the rest of this surface does: "I could not tell"
      // must not be reported as "there was nothing to stop".
      h.orchestratorFetch
        .mockResolvedValueOnce({ ok: false, status: 500 })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'idle' }) })
      const r = await stopRecon(ctx(), 'p1') as Record<string, unknown>
      expect(r.stopped).toBeNull()
      expect(String(r.note)).toMatch(/could not be read/i)
    })

    test('the stop is still issued when the pre-stop read fails', async () => {
      h.orchestratorFetch
        .mockRejectedValueOnce(new Error('ECONNREFUSED'))
        .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'idle' }) })
      await expect(stopRecon(ctx(), 'p1')).resolves.toMatchObject({ stopped: null })
      expect(h.orchestratorFetch).toHaveBeenCalledTimes(2)
      expect(String(h.orchestratorFetch.mock.calls[1][0])).toMatch(/\/stop$/)
    })

    test('the audit row records whether anything was stopped', async () => {
      h.orchestratorFetch
        .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'idle' }) })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'idle' }) })
      await stopRecon(ctx(), 'p1')
      expect(h.audit).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'mcp.stop_recon',
          after: expect.objectContaining({ outcome: 'nothing_running' }),
        })
      )
    })
  })

  test('an unreachable orchestrator reports UNKNOWN, not "stopped"', async () => {
    h.orchestratorFetch.mockRejectedValue(new Error('ECONNREFUSED'))
    await expect(stopRecon(ctx(), 'p1')).rejects.toMatchObject({ code: 'status_unknown' })
  })

  test("another user's project is refused", async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else' })
    await expect(stopRecon(ctx(), 'p1')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

// --- update_recon_settings -------------------------------------------------------------

describe('update_recon_settings refuses what would redirect the platform', () => {
  test('needs recon:settings', async () => {
    await expect(updateReconSettings(ctx(['recon:read']), 'p1', { naabuThreads: 25 }))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('THE attack: a target change is refused by name', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { targetDomain: 'victim.com' }))
      .rejects.toThrow(/targetDomain/)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('THE attack: disabling the guardrail is refused', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { targetGuardrailEnabled: false }))
      .rejects.toThrow(/targetGuardrailEnabled/)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('a denied field alongside a valid one rejects the WHOLE call', async () => {
    await expect(
      updateReconSettings(ctx(), 'p1', { naabuThreads: 25, targetDomain: 'victim.com' })
    ).rejects.toThrow()
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  // Still refused, and each for a DIFFERENT reason, which is the point of the
  // dispositions replacing one allowlist.
  test.each([
    ['roeEnabled', /derived/i, 'derived from whether any engagement limit is set'],
    ['roeClientName', /engagement RECORD/, 'the contract: a person writes it, nothing enforces it'],
    ['targetDomain', /create_project/, 'scope: fixed at creation'],
    ['cypherfixGithubToken', /credential/, 'a stored credential'],
    ['activationState', /not a pipeline parameter/, 'an application-written lock flag'],
    ['jsReconUploadedFiles', /upload/, 'written by the endpoint that places the file on disk'],
    ['agentModel', /not a recon setting/, 'not a column at all'],
  ])('%s is refused (%s)', async (field, pattern) => {
    await expect(updateReconSettings(ctx(), 'p1', { [field]: 'x' })).rejects.toThrow(pattern)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('a wrong-typed value is refused whatever the disposition', async () => {
    // nucleiCustomTemplates and httpxCustomHeaders are String[] columns, so a
    // bare string is refused on type before any policy question arises.
    for (const field of ['nucleiCustomTemplates', 'httpxCustomHeaders']) {
      await expect(updateReconSettings(ctx(), 'p1', { [field]: 'x' }))
        .rejects.toThrow(/must be an array/)
    }
  })

  test('a container image is refused by name, the shipped one included', async () => {
    // Every tool runs the image RedAmon ships; no image is a setting, so a
    // write naming one is refused rather than stored and silently ignored.
    for (const image of ['attacker/evil:latest', 'projectdiscovery/nuclei:latest']) {
      await expect(updateReconSettings(ctx(), 'p1', { nucleiDockerImage: image }))
        .rejects.toThrow(/is not a recon setting/)
    }
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('a path outside the project directory is still refused at the write', async () => {
    // The scan side drops it to the default anyway, but refusing here names the
    // problem while the caller is still there to fix it.
    await expect(updateReconSettings(ctx(), 'p1', { ffufWordlist: '/etc/shadow' }))
      .rejects.toThrow(/absolute path inside/)
  })

  test('a header that would re-point or authenticate the request is refused', async () => {
    for (const bad of ['Host: victim.com', 'Authorization: Bearer x', 'X-A: b\r\nX-C: d']) {
      await expect(updateReconSettings(ctx(), 'p1', { httpxCustomHeaders: [bad] }))
        .rejects.toThrow()
    }
    // An ordinary annotating header is fine.
    await expect(updateReconSettings(ctx(), 'p1', { httpxCustomHeaders: ['X-Scan-Id: abc'] }))
      .resolves.toBeTruthy()
  })

  test('an out-of-range value is refused, not clamped', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 999_999 }))
      .rejects.toThrow(/between/)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })
})

describe('update_recon_settings applies what it should', () => {
  test('an allowlisted change is written', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 10, updatedAt: READ_AT })
      .mockResolvedValueOnce({ naabuThreads: 25 })

    const r = await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(h.updateManyProjects).toHaveBeenCalledWith({
      where: { id: 'p1', updatedAt: READ_AT }, data: { naabuThreads: 25 },
    })
    expect(r.changed).toEqual(['naabuThreads'])
  })

  test('only the filtered data reaches prisma, never the raw body', async () => {
    await updateReconSettings(ctx(), 'p1', { nucleiEnabled: false })
    expect(h.updateManyProjects.mock.calls[0][0].data).toEqual({ nucleiEnabled: false })
  })

  test('the before and after of each changed field are audited', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ naabuThreads: 10, updatedAt: new Date() })
      .mockResolvedValueOnce({ naabuThreads: 25 })

    await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    const entry = h.audit.mock.calls[0][0]
    expect(entry.action).toBe('mcp.update_recon_settings')
    expect(entry.before).toEqual({ naabuThreads: 10 })
    expect(entry.after.changes).toEqual({ naabuThreads: 25 })
  })

  test('it says settings apply to the NEXT scan', async () => {
    const r = await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(r.note).toMatch(/NEXT scan/)
  })
})

describe('update_recon_settings refuses mid-scan', () => {
  test('a running scan blocks the write', async () => {
    // Recon reads its settings ONCE at spawn, so a mid-scan write is inert.
    // Accepting it would report success for a change that does nothing.
    h.scanWriters.mockResolvedValue('a full recon scan is running')
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 25 }))
      .rejects.toThrow(/will not see the change/)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('the refusal explains why, not just that', async () => {
    h.scanWriters.mockResolvedValue('a full recon scan is running')
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 25 }))
      .rejects.toThrow(/read its settings when it started/)
  })
})

describe('update_recon_settings optimistic concurrency', () => {
  test('expectedUpdatedAt uses a conditional update', async () => {
    const ts = '2026-09-01T10:00:00.000Z'
    await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 }, ts)
    expect(h.updateManyProjects).toHaveBeenCalledWith({
      where: { id: 'p1', updatedAt: new Date(ts) },
      data: { naabuThreads: 25 },
    })
    expect(h.updateProject).not.toHaveBeenCalled()
  })

  test('a stale expectedUpdatedAt is a conflict, not a silent overwrite', async () => {
    h.updateManyProjects.mockResolvedValue({ count: 0 })
    await expect(
      updateReconSettings(ctx(), 'p1', { naabuThreads: 25 }, '2026-09-01T10:00:00.000Z')
    ).rejects.toMatchObject({ code: 'conflict' })
  })

  test('a malformed expectedUpdatedAt is refused', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 25 }, 'yesterday'))
      .rejects.toThrow(/valid timestamp/)
  })

  test('C-5: without expectedUpdatedAt it is STILL a compare-and-swap, on the value it read', async () => {
    // Two agents writing at once each read, then wrote, and the later write's
    // audit `before` described a state that no longer existed.
    await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(h.updateManyProjects.mock.calls[0][0].where).toEqual({ id: 'p1', updatedAt: READ_AT })
    expect(h.updateProject).not.toHaveBeenCalled()
  })

  test('C-5: a concurrent write between the read and the write is a conflict, never retried', async () => {
    h.updateManyProjects.mockResolvedValue({ count: 0 })
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 25 }))
      .rejects.toMatchObject({ code: 'conflict' })
    expect(h.updateManyProjects).toHaveBeenCalledTimes(1)
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('an unread updatedAt refuses rather than writing unconditionally', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })).rejects.toThrow(/unconditional/)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })
})

describe('update_recon_settings runs the rules the project form\'s save runs', () => {
  test('a fireteam value inside the registry bound but outside the form\'s rule is refused', async () => {
    // The registry allows propensity 0-10; the form's schema allows 1-5. Only the
    // form enforced its rule, so an MCP write could store a value the form refuses.
    await expect(updateReconSettings(ctx(), 'p1', { fireteamPropensity: 9 }))
      .rejects.toMatchObject({ code: 'setting_rejected' })
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('a rule over two fields sees the stored one the caller did not send', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ fireteamMaxMembers: 4, updatedAt: READ_AT })
    await expect(updateReconSettings(ctx(), 'p1', { fireteamMaxConcurrent: 8 }))
      .rejects.toThrow(/cannot exceed fireteamMaxMembers/)
    expect(h.updateManyProjects).not.toHaveBeenCalled()
  })

  test('a fireteam change is written to the fireteam audit, as mcp', async () => {
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ fireteamMaxMembers: 5, fireteamMaxConcurrent: 2, updatedAt: READ_AT })
      .mockResolvedValueOnce({ fireteamMaxConcurrent: 3 })
    await updateReconSettings(ctx(), 'p1', { fireteamMaxConcurrent: 3 })
    const rows = h.fireteamAudit.mock.calls[0][0].data
    expect(rows).toEqual([expect.objectContaining({
      projectId: 'p1', field: 'fireteamMaxConcurrent', oldValue: 2, newValue: 3, source: 'mcp',
    })])
  })

  test('a write that touches no fireteam field writes no fireteam audit', async () => {
    await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(h.fireteamAudit).not.toHaveBeenCalled()
  })
})

describe('update_recon_settings refusals name the rejected key in the audit', () => {
  test('a registry key is recorded as itself', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { naabuThreads: 5, targetDomain: 'x.tld' }))
      .rejects.toMatchObject({ code: 'setting_rejected', audit: { rejectedKey: 'targetDomain' } })
  })

  test('anything else is recorded as a placeholder, so caller text never reaches the log line', async () => {
    await expect(updateReconSettings(ctx(), 'p1', { 'evil\n[audit] forged': 1 }))
      .rejects.toMatchObject({ code: 'setting_rejected', audit: { rejectedKey: '<unknown>' } })
  })
})

describe('update_recon_settings reports what it silently affected', () => {
  test('a queued scan whose fingerprint moved is counted', async () => {
    // Of the fingerprinted fields only scanModules is allowlisted, so this can
    // genuinely happen - and an agent not told would wait for a scan that is
    // now parked for a human.
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ scanModules: ['port_scan'], updatedAt: new Date() })
      .mockResolvedValueOnce({ scanModules: ['port_scan'] })
      .mockResolvedValueOnce({ id: 'p1', scanModules: ['port_scan'], targetDomain: 'x.tld' })
    h.findQueued.mockResolvedValue([
      { id: 'j1', kind: 'full_recon', projectId: 'p1', payload: {}, settingsHash: 'a-stale-hash' },
    ])

    const r = await updateReconSettings(ctx(), 'p1', { scanModules: ['port_scan'] })
    expect(r.queuedJobsNeedingReview).toEqual({ count: 1, jobIds: ['j1'] })
  })

  test('C-6: a job the settings did not move is NOT reported, auth profile included', async () => {
    // The hash was taken from the row alone, while enqueue and the dispatcher
    // fold in the auth profile, so every queued full recon read as parked.
    const row = { id: 'p1', scanModules: ['port_scan'], targetDomain: 'x.tld' }
    const profile = {
      authType: 'bearer', authHeaderName: 'Authorization', authValue: 'v',
      extraHeaders: {}, scopeHosts: ['x.tld'], reconEnabled: true,
    }
    h.findAuthProfile.mockResolvedValue(profile)
    const enqueuedHash = settingsFingerprint('full_recon', row, {
      authProfileFp: authProfileFingerprint(profile as never),
    })
    h.findProject
      .mockResolvedValueOnce({ id: 'p1', userId: 'owner' })
      .mockResolvedValueOnce({ scanModules: ['port_scan'], updatedAt: READ_AT })
      .mockResolvedValueOnce({ scanModules: ['port_scan'] })
      .mockResolvedValueOnce(row)
    h.findQueued.mockResolvedValue([
      { id: 'j1', kind: 'full_recon', projectId: 'p1', payload: {}, settingsHash: enqueuedHash },
    ])

    const r = await updateReconSettings(ctx(), 'p1', { scanModules: ['port_scan'] })
    expect(r.queuedJobsNeedingReview).toEqual({ count: 0, jobIds: [] })
  })

  test('enabled schedules are named, because they have NO fingerprint guard', async () => {
    h.findSchedules.mockResolvedValue([
      { id: 's1', label: 'Nightly' },
      { id: 's2', label: '' },
    ])
    const r = await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(r.affectedSchedules.count).toBe(2)
    expect(r.affectedSchedules.names).toEqual(['Nightly', 's2'])
  })

  test('only ENABLED schedules are counted', async () => {
    await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(h.findSchedules).toHaveBeenCalledWith(
      expect.objectContaining({ where: { projectId: 'p1', enabled: true } })
    )
  })

  test('a reporting failure does not fail the write that already happened', async () => {
    h.findSchedules.mockRejectedValue(new Error('db hiccup'))
    h.findQueued.mockRejectedValue(new Error('db hiccup'))
    const r = await updateReconSettings(ctx(), 'p1', { naabuThreads: 25 })
    expect(r.affectedSchedules).toEqual({ count: 0, names: [] })
    expect(r.queuedJobsNeedingReview).toEqual({ count: 0, jobIds: [] })
  })
})

// =============================================================================
// REGRESSION: the start bucket was per-TOKEN (audit finding F10)
// =============================================================================

describe('REGRESSION: the start bucket is per PROJECT, not per token', () => {
  const otherToken = (): McpContext => ({
    token: {
      tokenId: 'DIFFERENT-TOKEN', userId: 'owner',
      tokenPrefix: 'rdmn_mcp_bbbbbbbb', name: 'second', scopes: ALL_SCOPES as never,
    },
  })

  test('a SECOND token cannot start the same project again in the window', async () => {
    // The limit exists because a 'new' start consumes a retention slot and
    // permanently deletes the oldest unpinned version. Keying it on the token
    // let a user holding N tokens churn the timeline N times faster than the
    // documented one-per-5-minutes.
    await startRecon(ctx(), 'p1')
    await expect(startRecon(otherToken(), 'p1')).rejects.toThrow(/rate limit/i)
  })

  test('a second token CAN start a different project', async () => {
    await startRecon(ctx(), 'p1')
    await expect(startRecon(otherToken(), 'p2')).resolves.toBeTruthy()
  })
})

describe('REGRESSION: a busy refusal does not burn the start window (F10)', () => {
  test('a start refused for a live agent session leaves the bucket intact', async () => {
    // It launched nothing and consumed no retention slot, so charging it the
    // 5-minute window punishes an agent that did nothing wrong.
    h.liveWriters.mockResolvedValue('an agent session is running')
    await expect(startRecon(ctx(), 'p1')).rejects.toThrow(/agent session/)

    h.liveWriters.mockResolvedValue(null)
    await expect(startRecon(ctx(), 'p1')).resolves.toBeTruthy()
  })
})
