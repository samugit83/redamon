import { describe, it, test, expect } from 'vitest'
import { normalizeOrchestratorStartError } from './orchestratorError'

/**
 * Root cause of the reported "Application error: a client-side exception" after
 * starting a partial scan: the memory governor rejects the start with a
 * structured object detail, and the start routes forwarded that OBJECT as
 * `error`. A `toast.error(data.error)` then rendered an object -> React throws
 * "Objects are not valid as a React child" and the page goes down.
 *
 * The invariant these tests lock: normalize ALWAYS returns a string `error`,
 * for every input shape. That is what makes the value safe to render.
 */
describe('normalizeOrchestratorStartError', () => {
  // The exact payload from the crash report (keys: admitted, limitType,
  // resource, current, ceiling, settingName, detail).
  const GOVERNOR_RAM = {
    admitted: false,
    limitType: 'ram',
    resource: 'scan',
    current: 1,
    ceiling: 2,
    settingName: null,
    detail: 'not enough reserved memory budget for another scan',
  }
  const GOVERNOR_HARD = {
    admitted: false,
    limitType: 'hard',
    resource: 'scan',
    current: 12,
    ceiling: 12,
    settingName: 'RECON_MAX_CONCURRENT_GLOBAL',
    detail: 'Maximum concurrent scans reached',
  }

  it('turns a RAM-limit object into a string message and keeps the payload as limit', () => {
    const r = normalizeOrchestratorStartError({ detail: GOVERNOR_RAM }, 'fallback')
    expect(typeof r.error).toBe('string')
    expect(r.error).toContain('not enough reserved memory budget')
    expect(r.error).toContain('RAM limit')
    expect(r.limit).toEqual(GOVERNOR_RAM)
  })

  it('turns a HARD-limit object into a string that names the setting to raise', () => {
    const r = normalizeOrchestratorStartError({ detail: GOVERNOR_HARD }, 'fallback')
    expect(typeof r.error).toBe('string')
    expect(r.error).toContain('Maximum concurrent scans reached')
    expect(r.error).toContain('RECON_MAX_CONCURRENT_GLOBAL')
    expect(r.limit).toEqual(GOVERNOR_HARD)
  })

  it('a refusal by the actor\'s quota (step 6.8) names the quota, never a restart', () => {
    const quota = { ...GOVERNOR_HARD, current: 2, ceiling: 2, settingName: 'maxConcurrentScans', detail: "2 of 2 concurrent scans allowed by this person's quota" }
    const r = normalizeOrchestratorStartError({ detail: quota }, 'fallback')
    expect(r.error).toBe("2 of 2 concurrent scans allowed by this person's quota. Wait for one of these scans to finish, or ask an administrator to raise your quota.")
    expect(r.error).not.toContain('restart')
    expect(r.limit).toEqual(quota)
  })

  it('never returns an object as error, even for an unknown object shape', () => {
    const weird = { detail: { admitted: false, resource: 'scan', unexpected: true } }
    const r = normalizeOrchestratorStartError(weird, 'fallback message')
    expect(typeof r.error).toBe('string')
    // No limitType => falls back (object has no usable detail string).
    expect(r.error).toBe('fallback message')
  })

  it('uses a plain string detail directly', () => {
    const r = normalizeOrchestratorStartError({ detail: 'Full recon is running. Stop it first.' }, 'fallback')
    expect(r.error).toBe('Full recon is running. Stop it first.')
    expect(r.limit).toBeUndefined()
  })

  it('falls back when detail is missing or the body is empty/garbage', () => {
    expect(normalizeOrchestratorStartError({}, 'fb').error).toBe('fb')
    expect(normalizeOrchestratorStartError(undefined, 'fb').error).toBe('fb')
    expect(normalizeOrchestratorStartError(null, 'fb').error).toBe('fb')
    expect(normalizeOrchestratorStartError('a string body', 'fb').error).toBe('fb')
  })

  it('INVARIANT: error is a string for every input shape', () => {
    const inputs: unknown[] = [
      { detail: GOVERNOR_RAM },
      { detail: GOVERNOR_HARD },
      { detail: { admitted: false } },
      { detail: 'plain' },
      { detail: 123 },
      { detail: null },
      {},
      undefined,
      null,
      42,
      'str',
      [],
    ]
    for (const input of inputs) {
      const r = normalizeOrchestratorStartError(input, 'fb')
      expect(typeof r.error, `error must be string for input ${JSON.stringify(input)}`).toBe('string')
    }
  })
})

describe('the orchestrator reason code (plan 12.6, 12.9)', () => {
  test('a detail object naming a code carries it, with its message as the error', () => {
    const n = normalizeOrchestratorStartError(
      { detail: { detail: 'The scan container could not be started: no image', code: 'spawn_failed' } },
      'Failed to start recon',
    )
    expect(n.error).toBe('The scan container could not be started: no image')
    expect(n.code).toBe('spawn_failed')
  })

  test('a plain string detail has no code', () => {
    expect(normalizeOrchestratorStartError({ detail: 'nope' }, 'f').code).toBeUndefined()
  })

  test('a non-string code is ignored', () => {
    expect(normalizeOrchestratorStartError({ detail: { detail: 'x', code: 7 } }, 'f').code).toBeUndefined()
  })
})

describe('a refused start never echoes the request back (step 1.16 review)', () => {
  // FastAPI answers a body it cannot validate with 422 and an ARRAY detail whose
  // items carry `input`: for a missing field, the whole request body, job
  // credential included. None of it may reach the browser.
  const CREDENTIAL = 'eyJhdWQiOiJzY2FuIn0.SECRET-SIGNATURE'
  const echoed = {
    detail: [
      {
        type: 'missing', loc: ['body', 'tool_id'], msg: 'Field required',
        input: { project_id: 'p1', user_id: 'u1', job_credential: CREDENTIAL },
      },
    ],
  }

  test('a validation error array becomes the fallback, with no limit and no echo', () => {
    const n = normalizeOrchestratorStartError(echoed, 'Failed to start partial recon')
    expect(n).toEqual({ error: 'Failed to start partial recon' })
    expect(JSON.stringify(n)).not.toContain(CREDENTIAL)
  })

  test('an unknown detail object keeps its message and code, never the object itself', () => {
    const n = normalizeOrchestratorStartError(
      { detail: { detail: 'Refused', code: 'job_credential_missing', input: { job_credential: CREDENTIAL } } },
      'fallback',
    )
    expect(n).toEqual({ error: 'Refused', code: 'job_credential_missing' })
    expect(JSON.stringify(n)).not.toContain(CREDENTIAL)
  })

  test('only a governor refusal (limitType) is passed on as the limit', () => {
    const limit = { admitted: false, limitType: 'hard', detail: 'Maximum concurrent scans reached' }
    expect(normalizeOrchestratorStartError({ detail: limit }, 'f').limit).toEqual(limit)
  })
})
