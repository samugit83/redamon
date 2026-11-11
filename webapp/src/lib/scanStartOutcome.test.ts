import { describe, test, expect } from 'vitest'
import { classifyStartFailure, isCapacityWait } from './scanStartOutcome'

describe('classifyStartFailure', () => {
  test('RAM limit is temporary with code ram', () => {
    const c = classifyStartFailure(429, { error: 'no mem', limit: { limitType: 'ram' } })
    expect(c).toMatchObject({ kind: 'temporary', temporary: true, blockedCode: 'ram' })
  })

  test('hard limit is temporary with code hard', () => {
    const c = classifyStartFailure(429, { error: 'max concurrent', limit: { limitType: 'hard' } })
    expect(c).toMatchObject({ kind: 'temporary', temporary: true, blockedCode: 'hard' })
  })

  test('activationInProgress is temporary with code activating', () => {
    const c = classifyStartFailure(409, { error: 'activating', activationInProgress: true })
    expect(c).toMatchObject({ kind: 'temporary', blockedCode: 'activating' })
  })

  test('any bare 409 (no limit, plain string) is temporary/busy', () => {
    const c = classifyStartFailure(409, { error: 'Cannot start a scan while a full recon scan is running' })
    expect(c).toMatchObject({ kind: 'temporary', temporary: true, blockedCode: 'busy' })
    expect(typeof c.reason).toBe('string')
  })

  test('400 is permanent', () => {
    expect(classifyStartFailure(400, { error: 'no target' })).toMatchObject({ kind: 'permanent', temporary: false, blockedCode: '' })
  })

  test('404 is permanent', () => {
    expect(classifyStartFailure(404, { error: 'gone' }).temporary).toBe(false)
  })

  test('500 is permanent for a caller that does not say the orchestrator answered (the browser)', () => {
    expect(classifyStartFailure(500, { error: 'boom' }).temporary).toBe(false)
  })

  test('missing body never throws and yields a string reason', () => {
    const c = classifyStartFailure(undefined, undefined)
    expect(c.kind).toBe('permanent')
    expect(typeof c.reason).toBe('string')
  })

  test('a RAM limit wins even if status is not 409', () => {
    expect(classifyStartFailure(200, { limit: { limitType: 'ram' } }).blockedCode).toBe('ram')
  })
})

describe('classifyStartFailure for the queue and the scheduler (plan 12.6, 12.9)', () => {
  const answered = { orchestratorAnswered: true }

  test('an unknown outcome is checked first, and is never temporary', () => {
    // Even with a limit and a 409 in the body: the orchestrator did not answer,
    // so nobody knows whether the scan started.
    const c = classifyStartFailure(503, {
      startOutcome: 'unknown', error: 'no answer', limit: { limitType: 'ram' },
    }, answered)
    expect(c).toMatchObject({ kind: 'unknown', temporary: false, blockedCode: 'start_unknown' })
  })

  test.each([500, 503])('an answered %i is transient', status => {
    expect(classifyStartFailure(status, { error: 'Cannot verify scan scope' }, answered))
      .toMatchObject({ kind: 'transient', temporary: true, blockedCode: 'transient' })
  })

  test('transient is not a capacity wait, so it spends attempts', () => {
    const c = classifyStartFailure(503, { error: 'x' }, answered)
    expect(isCapacityWait(c.blockedCode)).toBe(false)
  })

  test('without orchestratorAnswered a 503 stays permanent', () => {
    expect(classifyStartFailure(503, { error: 'x' }).kind).toBe('permanent')
    expect(classifyStartFailure(503, { error: 'x' }, { orchestratorAnswered: false }).kind).toBe('permanent')
  })

  test('a freeze failure (nothing started) is transient for the queue', () => {
    expect(classifyStartFailure(500, { error: 'freeze', snapshotFailed: true }, answered).kind).toBe('transient')
  })

  test('a failed spawn is permanent: a missing image fails every retry', () => {
    expect(classifyStartFailure(500, { error: 'no image', code: 'spawn_failed' }, answered))
      .toMatchObject({ kind: 'permanent', temporary: false, blockedCode: '' })
  })

  test('a configuration 503 is permanent', () => {
    expect(classifyStartFailure(503, {
      error: 'AI Attack Surface source not mounted into the orchestrator', code: 'not_configured',
    }, answered).kind).toBe('permanent')
  })

  test.each(['scanner_key_missing', 'job_credential_unverifiable'])(
    'a missing key at the orchestrator (%s) is permanent: only redamon.sh update fixes it', code => {
      expect(classifyStartFailure(503, { error: 'x', code }, answered).kind).toBe('permanent')
    },
  )

  test.each([400, 403, 404, 422])('an answered %i stays permanent', status => {
    expect(classifyStartFailure(status, { error: 'x' }, answered).kind).toBe('permanent')
  })

  test('capacity codes keep winning over transient', () => {
    expect(classifyStartFailure(503, { limit: { limitType: 'ram' } }, answered).blockedCode).toBe('ram')
    expect(classifyStartFailure(409, { error: 'busy' }, answered).blockedCode).toBe('busy')
  })
})
