/**
 * GET/POST /api/users/[id]/settings/api-usage.
 *
 * The POST sends a user's plaintext keys to external providers, so the guard is
 * the effective-user check (owner, or an admin while acting as them), internal
 * and scanner principals are refused before any DB read, and every refusal path
 * releases the per-user lock.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  reportFind: vi.fn(),
  reportUpsert: vi.fn(),
  scanFind: vi.fn(),
  convFind: vi.fn(),
  settingsFind: vi.fn(),
  rotationFind: vi.fn(),
  llmFind: vi.fn(),
  userFind: vi.fn(),
  getEffectiveUser: vi.fn(),
  getSession: vi.fn(),
  isInternal: vi.fn(),
  isScanner: vi.fn(),
  writeAudit: vi.fn(),
  runJobs: vi.fn(),
}))

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/prisma', () => ({
  default: {
    apiUsageReport: { findUnique: (...a: unknown[]) => h.reportFind(...a), upsert: (...a: unknown[]) => h.reportUpsert(...a) },
    scanJob: { findMany: (...a: unknown[]) => h.scanFind(...a) },
    conversation: { findMany: (...a: unknown[]) => h.convFind(...a) },
    userSettings: { findUnique: (...a: unknown[]) => h.settingsFind(...a) },
    apiKeyRotationConfig: { findMany: (...a: unknown[]) => h.rotationFind(...a) },
    userLlmProvider: { findMany: (...a: unknown[]) => h.llmFind(...a) },
    user: { findUnique: (...a: unknown[]) => h.userFind(...a) },
  },
}))
vi.mock('@/lib/session', () => ({
  getEffectiveUser: (...a: unknown[]) => h.getEffectiveUser(...a),
  getSession: (...a: unknown[]) => h.getSession(...a),
  isInternalRequest: (...a: unknown[]) => h.isInternal(...a),
  isScannerRequest: (...a: unknown[]) => h.isScanner(...a),
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.writeAudit(...a) }))
vi.mock('@/lib/apiUsage/runner', () => ({ runJobs: (...a: unknown[]) => h.runJobs(...a) }))
vi.mock('@/lib/apiUsage/registry', () => ({
  PROBES: [{
    id: 'shodan', service: 'shodan', label: 'Shodan', group: 'keys', field: 'shodanApiKey', rotationTool: 'shodan',
    kind: 'usage', costNote: '', docsUrl: '', dashboardUrl: '', verifiedOn: null, endpoint: 'GET x',
    run: async () => ({ outcome: 'valid_no_usage', meters: [] }),
  }],
  LLM_PROBES: {},
  NOT_PROBED: {},
}))

import { GET, POST } from './route'
import { resetRunState } from '@/lib/apiUsage/state'
import type { ApiUsageReportV1 } from '@/lib/apiUsage/types'

const OWNER = 'user-owner'
const OTHER = 'user-other'
const ADMIN = 'user-admin'
const FIXTURE_KEY = 'SHODAN-FIXTURE-KEY-7777'

const params = (id: string) => ({ params: Promise.resolve({ id }) })
const get = (id = OWNER) => GET(new NextRequest(`http://x/api/users/${id}/settings/api-usage`), params(id))
const post = (body: unknown = {}, id = OWNER, contentType = 'application/json') =>
  POST(new NextRequest(`http://x/api/users/${id}/settings/api-usage`, {
    method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { 'Content-Type': contentType },
  }), params(id))

function report(over: Partial<ApiUsageReportV1> = {}): ApiUsageReportV1 {
  return {
    schemaVersion: 1,
    startedAt: '2026-09-26T14:32:00.000Z',
    finishedAt: '2026-09-26T14:32:05.000Z',
    durationMs: 5000,
    counts: { services: 1, keys: 1, usage: 0, validNoUsage: 1, notChecked: 0, errors: 0, low: 0, exhausted: 0 },
    skippedEmpty: [],
    inventory: { shodanApiKey: { hint: '••••••••7777', extraKeys: 0 } },
    results: [{
      serviceId: 'shodan', serviceLabel: 'Shodan', group: 'keys', field: 'shodanApiKey', keyRole: 'primary', keyIndex: 0,
      keyHint: '••••••••7777', outcome: 'valid_no_usage', meters: [], costNote: '', dashboardUrl: '', docsUrl: '',
      endpoint: 'GET x', checkedAt: '2026-09-26T14:32:01.000Z', latencyMs: 12,
    }],
    ...over,
  }
}

function deferred<T>() {
  let resolve!: (v: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

beforeEach(() => {
  vi.clearAllMocks()
  resetRunState()
  delete process.env.API_USAGE_CHECK_ENABLED
  h.isInternal.mockReturnValue(false)
  h.isScanner.mockReturnValue(false)
  h.getEffectiveUser.mockResolvedValue({ userId: OWNER })
  h.getSession.mockResolvedValue({ userId: OWNER, role: 'standard' })
  h.reportFind.mockResolvedValue(null)
  h.reportUpsert.mockResolvedValue({})
  h.scanFind.mockResolvedValue([])
  h.convFind.mockResolvedValue([])
  h.settingsFind.mockResolvedValue({ userId: OWNER, shodanApiKey: FIXTURE_KEY })
  h.rotationFind.mockResolvedValue([])
  h.llmFind.mockResolvedValue([])
  h.userFind.mockResolvedValue(null)
  h.runJobs.mockResolvedValue(report())
  h.writeAudit.mockResolvedValue(undefined)
})

describe('authorization', () => {
  test.each([['internal', 'isInternal'], ['scanner', 'isScanner']] as const)('%s principal -> 403 before any DB read (GET and POST)', async (_n, flag) => {
    h[flag].mockReturnValue(true)
    expect((await get()).status).toBe(403)
    expect((await post({ overwrite: true })).status).toBe(403)
    expect(h.reportFind).not.toHaveBeenCalled()
    expect(h.settingsFind).not.toHaveBeenCalled()
    expect(h.runJobs).not.toHaveBeenCalled()
  })

  test('no session -> 401', async () => {
    h.getEffectiveUser.mockResolvedValue(null)
    expect((await get()).status).toBe(401)
    expect((await post()).status).toBe(401)
  })

  test("another user's id -> 403, no DB read", async () => {
    expect((await get(OTHER)).status).toBe(403)
    expect((await post({}, OTHER)).status).toBe(403)
    expect(h.reportFind).not.toHaveBeenCalled()
    expect(h.runJobs).not.toHaveBeenCalled()
  })

  test('an admin NOT acting as the user is refused (stricter than the settings routes)', async () => {
    h.getEffectiveUser.mockResolvedValue({ userId: ADMIN })
    h.getSession.mockResolvedValue({ userId: ADMIN, role: 'admin' })
    expect((await get(OWNER)).status).toBe(403)
    expect((await post({ overwrite: true }, OWNER)).status).toBe(403)
    expect(h.runJobs).not.toHaveBeenCalled()
  })

  test('an admin acting as the user may read and run; the actor is recorded', async () => {
    h.getEffectiveUser.mockResolvedValue({ userId: OWNER })
    h.getSession.mockResolvedValue({ userId: ADMIN, role: 'admin' })
    expect((await get(OWNER)).status).toBe(200)
    const res = await post({}, OWNER)
    expect(res.status).toBe(200)
    expect(h.reportUpsert.mock.calls[0][0].create).toMatchObject({ createdById: ADMIN, updatedById: ADMIN })
    expect(h.writeAudit.mock.calls[0][0]).toMatchObject({ actorId: ADMIN, targetId: OWNER })
  })
})

describe('GET', () => {
  test('no report yet -> report: null, enabled, tracked fields, no-store', async () => {
    const res = await get()
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = await res.json()
    expect(body).toMatchObject({ enabled: true, report: null, running: null, runBy: null })
    expect(body.activity).toEqual({ runningScans: [], agentRuns: [] })
    expect(body.tracked).toEqual([{ field: 'shodanApiKey', probeId: 'shodan', label: 'Shodan', role: 'key', rotationTool: 'shodan' }])
  })

  test('a database failure -> 500 with its code, never its message', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.reportFind.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const res = await get()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to load the API usage report', code: 'P1001' })
  })

  test('returns the saved report, and "run by" when an admin ran it while acting', async () => {
    h.reportFind.mockResolvedValue({ report: report(), updatedById: ADMIN, finishedAt: new Date() })
    h.userFind.mockResolvedValue({ id: ADMIN, name: 'Ada Admin' })
    const body = await (await get()).json()
    expect(body.report.counts.keys).toBe(1)
    expect(body.runBy).toEqual({ id: ADMIN, name: 'Ada Admin' })
  })

  test('the owner running it themselves -> runBy null', async () => {
    h.reportFind.mockResolvedValue({ report: report(), updatedById: OWNER, finishedAt: new Date() })
    expect((await (await get()).json()).runBy).toBeNull()
  })

  test('API_USAGE_CHECK_ENABLED=false is reported, and the last report stays readable', async () => {
    process.env.API_USAGE_CHECK_ENABLED = 'false'
    h.reportFind.mockResolvedValue({ report: report(), updatedById: OWNER, finishedAt: new Date() })
    const body = await (await get()).json()
    expect(body.enabled).toBe(false)
    expect(body.report).not.toBeNull()
  })

  test('activity is read from the user\'s OWN projects only', async () => {
    h.scanFind.mockResolvedValue([{ projectId: 'p1', kind: 'full_recon', startedAt: new Date('2026-09-26T14:00:00Z'), project: { name: 'acme' } }])
    h.convFind.mockResolvedValue([{ projectId: 'p2', project: { name: 'beta' } }])
    const body = await (await get()).json()
    expect(h.scanFind.mock.calls[0][0].where).toEqual({ status: 'running', project: { userId: OWNER } })
    expect(h.convFind.mock.calls[0][0].where).toEqual({ agentRunning: true, project: { userId: OWNER } })
    expect(body.activity).toEqual({
      runningScans: [{ projectId: 'p1', projectName: 'acme', kind: 'full_recon', startedAt: '2026-09-26T14:00:00.000Z' }],
      agentRuns: [{ projectId: 'p2', projectName: 'beta' }],
    })
  })

  test('shows a run in flight (started in another tab)', async () => {
    const d = deferred<ApiUsageReportV1>()
    h.runJobs.mockReturnValue(d.promise)
    const pending = post()
    await vi.waitFor(() => expect(h.runJobs).toHaveBeenCalled())
    const body = await (await get()).json()
    expect(body.running).toMatchObject({ keys: 1 })
    expect(typeof body.running.startedAt).toBe('string')
    d.resolve(report())
    await pending
    expect((await (await get()).json()).running).toBeNull()
  })
})

describe('POST guards, in order', () => {
  test('disabled -> 409 disabled, nothing read or run', async () => {
    process.env.API_USAGE_CHECK_ENABLED = 'false'
    const res = await post({ overwrite: true })
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'disabled' })
    expect(h.settingsFind).not.toHaveBeenCalled()
  })

  // The switch exists for air-gapped hosts. The other egress switches it is
  // modelled on (OSV_DB_AUTO_REFRESH, SCA_INTEL_AUTO_REFRESH) read 0/false/no in
  // any case; an operator who writes the same here must not keep egress on.
  test.each(['FALSE', 'False', ' false ', '0', 'no', 'off'])(
    'REGRESSION kill-switch-fails-open: API_USAGE_CHECK_ENABLED=%j turns the check off',
    async value => {
      process.env.API_USAGE_CHECK_ENABLED = value
      expect((await (await get()).json()).enabled).toBe(false)
      const res = await post({ overwrite: true })
      expect(res.status).toBe(409)
      expect(await res.json()).toEqual({ error: 'disabled' })
      expect(h.runJobs).not.toHaveBeenCalled()
    },
  )

  test.each(['', 'true', 'TRUE', '1', 'yes', 'on'])('API_USAGE_CHECK_ENABLED=%j leaves the check on', async value => {
    process.env.API_USAGE_CHECK_ENABLED = value
    expect((await (await get()).json()).enabled).toBe(true)
  })

  test('a second POST while one runs -> 409 run_in_progress; the lock is released afterwards', async () => {
    const d = deferred<ApiUsageReportV1>()
    h.runJobs.mockReturnValue(d.promise)
    const first = post()
    await vi.waitFor(() => expect(h.runJobs).toHaveBeenCalled())
    const second = await post({ overwrite: true })
    expect(second.status).toBe(409)
    expect((await second.json()).error).toBe('run_in_progress')
    d.resolve(report())
    expect((await first).status).toBe(200)
  })

  test('two POSTs arriving together: exactly one runs', async () => {
    const d = deferred<ApiUsageReportV1>()
    h.runJobs.mockReturnValue(d.promise)
    const [a, b] = [post(), post()]
    const second = await b
    expect(second.status).toBe(409)
    d.resolve(report())
    expect((await a).status).toBe(200)
    expect(h.runJobs).toHaveBeenCalledTimes(1)
  })

  test('a 4th concurrent run on the server -> 429 busy', async () => {
    const d = deferred<ApiUsageReportV1>()
    h.runJobs.mockReturnValue(d.promise)
    const users = ['u1', 'u2', 'u3']
    const running = users.map(u => {
      h.getEffectiveUser.mockResolvedValueOnce({ userId: u })
      return post({}, u)
    })
    await vi.waitFor(() => expect(h.runJobs).toHaveBeenCalledTimes(3))
    h.getEffectiveUser.mockResolvedValueOnce({ userId: 'u4' })
    const fourth = await post({}, 'u4')
    expect(fourth.status).toBe(429)
    expect(await fourth.json()).toEqual({ error: 'busy', retryAfterSec: 30 })
    d.resolve(report())
    await Promise.all(running)
  })

  test('cooldown: 429 within 60 s of the last run, checked BEFORE the overwrite question', async () => {
    h.reportFind.mockResolvedValue({ finishedAt: new Date(Date.now() - 20_000) })
    const res = await post({})
    expect(res.status).toBe(429)
    const body = await res.json()
    expect(body.error).toBe('cooldown')
    expect(body.retryAfterSec).toBeGreaterThan(30)
    expect(body.retryAfterSec).toBeLessThanOrEqual(40)
  })

  test('cooldown also covers a run whose save failed (in-memory clock)', async () => {
    h.reportUpsert.mockRejectedValue(new Error('db down'))
    expect((await post()).status).toBe(200)
    const again = await post({ overwrite: true })
    expect(again.status).toBe(429)
  })

  test('a report exists and no overwrite -> 409 report_exists with its date', async () => {
    const finishedAt = new Date(Date.now() - 3_600_000)
    h.reportFind.mockResolvedValue({ finishedAt })
    const res = await post({})
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: 'report_exists', finishedAt: finishedAt.toISOString() })
    expect(h.runJobs).not.toHaveBeenCalled()
    // The refusal released the lock: the confirmed retry goes through.
    expect((await post({ overwrite: true })).status).toBe(200)
  })

  test('running scans or agent runs -> 409 scans_running unless confirmed', async () => {
    h.scanFind.mockResolvedValue([{ projectId: 'p1', kind: 'gvm', startedAt: null, project: { name: 'acme' } }])
    h.convFind.mockResolvedValue([{ projectId: 'p1', project: { name: 'acme' } }])
    const res = await post({})
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body).toMatchObject({ error: 'scans_running', scans: [{ projectName: 'acme', kind: 'gvm' }], agentRuns: [{ projectName: 'acme' }] })
    expect(h.runJobs).not.toHaveBeenCalled()
    expect((await post({ ignoreRunningScans: true })).status).toBe(200)
  })

  test('an activity lookup that fails -> 503 activity_unknown, fail closed, runner never called', async () => {
    h.scanFind.mockRejectedValue(new Error('db timeout'))
    const res = await post({ ignoreRunningScans: true })
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: 'activity_unknown' })
    expect(h.runJobs).not.toHaveBeenCalled()
  })

  test('no saved key at all -> 400 no_keys, and the saved report is never replaced by an empty one', async () => {
    h.settingsFind.mockResolvedValue({ userId: OWNER, shodanApiKey: '' })
    const res = await post({ overwrite: true })
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'no_keys' })
    expect(h.runJobs).not.toHaveBeenCalled()
    expect(h.reportUpsert).not.toHaveBeenCalled()
  })

  // The session cookie is SameSite=lax, so a same-site page can submit a plain
  // form with it. An enctype=text/plain form can carry a body that parses as
  // JSON, overwrite flags included: only the Content-Type tells it from the
  // page's own fetch (lib/jsonBody.ts).
  test.each(['text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x'])(
    'REGRESSION csrf-form-post: a %s POST is refused (415) before anything runs',
    async type => {
      h.reportFind.mockResolvedValue({ finishedAt: new Date(Date.now() - 3_600_000) })
      const res = await post('{"overwrite":true,"ignoreRunningScans":true,"x":"="}', OWNER, type)
      expect(res.status).toBe(415)
      expect(h.runJobs).not.toHaveBeenCalled()
      expect(h.reportUpsert).not.toHaveBeenCalled()
      expect(h.writeAudit).not.toHaveBeenCalled()
      // Nothing was left locked: the page's own JSON POST still runs.
      expect((await post({ overwrite: true })).status).toBe(200)
    },
  )

  test('only the two booleans of the body are read; anything else is ignored', async () => {
    h.reportFind.mockResolvedValue({ finishedAt: new Date(Date.now() - 3_600_000) })
    const res = await post({ overwrite: 'true', userId: OTHER })
    expect(res.status).toBe(409)
  })
})

describe('POST run and save', () => {
  test('happy path: upsert AFTER the run, audit with counts only, no key in the response', async () => {
    const res = await post({})
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const text = await res.text()
    expect(text).not.toContain(FIXTURE_KEY)
    expect(JSON.parse(text)).toMatchObject({ saved: true, report: { counts: { keys: 1 } } })

    expect(h.runJobs.mock.invocationCallOrder[0]).toBeLessThan(h.reportUpsert.mock.invocationCallOrder[0])
    const up = h.reportUpsert.mock.calls[0][0]
    expect(up.where).toEqual({ userId: OWNER })
    expect(up.create).toMatchObject({ userId: OWNER, schemaVersion: 1, createdById: OWNER, updatedById: OWNER })
    expect(up.update).toMatchObject({ updatedById: OWNER })
    expect(up.update.createdById).toBeUndefined()

    expect(h.writeAudit).toHaveBeenCalledTimes(1)
    const audit = h.writeAudit.mock.calls[0][0]
    expect(audit).toMatchObject({ action: 'api-usage.check', targetType: 'user', targetId: OWNER, source: 'ui' })
    const auditText = JSON.stringify(audit)
    expect(auditText).not.toContain(FIXTURE_KEY)
    expect(auditText).not.toContain('7777')
    expect(auditText).not.toContain('@')
  })

  test('the runner receives the jobs built from the stored keys', async () => {
    await post({})
    const plan = h.runJobs.mock.calls[0][0]
    expect(plan.jobs.map((j: { key: string }) => j.key)).toEqual([FIXTURE_KEY])
  })

  test('the runner throwing -> 500, no upsert, previous report kept, lock released', async () => {
    h.runJobs.mockRejectedValue(new Error(`exploded with ${FIXTURE_KEY}`))
    const res = await post({})
    expect(res.status).toBe(500)
    const text = await res.text()
    expect(text).not.toContain(FIXTURE_KEY)
    expect(JSON.parse(text)).toEqual({ error: 'run_failed', code: 'run_failed' })
    expect(h.reportUpsert).not.toHaveBeenCalled()
    h.runJobs.mockResolvedValue(report())
    expect((await post({})).status).toBe(200)
  })

  test('the save failing -> 200 saved:false with the fresh report; audit still written', async () => {
    h.reportUpsert.mockRejectedValue(new Error('Foreign key constraint failed on the field: `user_id`'))
    const res = await post({})
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.saved).toBe(false)
    expect(body.saveError).toBe('the database refused the save')
    expect(body.report.counts.keys).toBe(1)
    expect(h.writeAudit.mock.calls[0][0].after.saved).toBe(false)
    // The lock was released (a user deleted mid-run does not wedge anything).
    expect((await (await get()).json()).running).toBeNull()
  })
})
