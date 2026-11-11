/**
 * Classify a failed scan-start response body + HTTP status into "temporary"
 * (the work could succeed later, so it is queueable) vs "permanent" (a config or
 * request error that queueing cannot fix). Scan Queue plan Phase 1.
 *
 * Temporary:
 *   - a RAM admission limit   (body.limit.limitType === 'ram')
 *   - a hard admission limit  (body.limit.limitType === 'hard')  -- frees when
 *     other scans finish, so retrying later is the right move
 *   - an activation in progress (body.activationInProgress)
 *   - ANY 409. "Already active for project X" refusals arrive as plain strings
 *     with no limit object, so the status is the only reliable signal.
 *
 * Two more classes exist only for a headless caller (the queue's dispatch
 * route and the scheduler), which says whether the orchestrator answered:
 *   - unknown: body.startOutcome === 'unknown', checked FIRST. The orchestrator
 *     did not answer, so the container may or may not exist; retrying blindly
 *     can start a second scan. Never temporary.
 *   - transient: an answered 500 or 503, or the webapp's own freeze failure
 *     (snapshotFailed: nothing started). Retried with backoff, spending an
 *     attempt; not a capacity wait. A body code that names a configuration
 *     problem (`spawn_failed`, `not_configured`, `scanner_key_missing`,
 *     `job_credential_unverifiable`) stays permanent: it fails every retry.
 *
 * Permanent: everything else, notably 400 (bad config), 404 (missing project),
 * 403 (outside the RoE window), and a 500 when the caller did not say the
 * orchestrator answered (the browser hook keeps that). Nothing about queueing
 * changes those.
 *
 * Pure: no I/O, no globals. Given (status, body, opts) it always returns the same value.
 */

export type StartFailureKind = 'temporary' | 'transient' | 'unknown' | 'permanent'

/** Mirrors JobQueue.blockedCode so a queued row can record why it is waiting. */
export type StartBlockedCode =
  | ''
  | 'ram'
  | 'hard'
  | 'activating'
  | 'busy'
  | 'transient'
  | 'start_unknown'

export interface StartFailureBody {
  error?: string
  limit?: { limitType?: 'ram' | 'hard' | string } | null
  activationInProgress?: boolean
  snapshotFailed?: boolean
  busy?: string
  /** 'unknown' when the orchestrator call threw (startFullScan, dispatchStart). */
  startOutcome?: 'unknown'
  /** The orchestrator's reason code (orchestratorError.ts). */
  code?: string
}

export interface StartFailureOptions {
  /**
   * Set by the headless callers only. True when the orchestrator gave an answer
   * (whatever it was), which is what makes a 5xx safe to retry.
   */
  orchestratorAnswered?: boolean
}

/**
 * Body codes for a refusal no retry can fix. The two keys the orchestrator needs
 * for a scan (step 1.16) are configuration: `redamon.sh update` generates them.
 */
const PERMANENT_CODES = new Set(['spawn_failed', 'not_configured', 'scanner_key_missing', 'job_credential_unverifiable'])

export interface StartFailureClassification {
  kind: StartFailureKind
  /** True when queueing is a sensible offer. */
  temporary: boolean
  /** The JobQueue.blockedCode to seed a queued row with (empty for permanent). */
  blockedCode: StartBlockedCode
  /** A short human reason, safe to render (always a string). */
  reason: string
}

/**
 * Blocked codes that mean "the job is fine, it just cannot run YET" — waiting for
 * memory, a concurrency slot, the project's turn, or a version activation to
 * finish. These are NOT defects: they must requeue on a short fixed recheck
 * WITHOUT consuming the attempt budget and must never fail the job, or a job that
 * only waited its turn gets killed (and, worse, an escalating backoff delays its
 * promotion the moment a slot frees). Contrast with a genuine start error, which
 * classifyStartFailure returns as permanent (fails immediately).
 */
export const CAPACITY_WAIT_CODES: StartBlockedCode[] = ['ram', 'hard', 'activating', 'busy']

export function isCapacityWait(code: string): boolean {
  return (CAPACITY_WAIT_CODES as string[]).includes(code)
}

export function classifyStartFailure(
  status: number | undefined,
  body: StartFailureBody | null | undefined,
  opts: StartFailureOptions = {},
): StartFailureClassification {
  const b = body ?? {}
  const limitType = b.limit?.limitType

  if (b.startOutcome === 'unknown') {
    return {
      kind: 'unknown',
      temporary: false,
      blockedCode: 'start_unknown',
      reason: b.error || 'The orchestrator did not answer, so it is unknown whether the scan started.',
    }
  }

  if (limitType === 'ram') {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'ram',
      reason: b.error || 'Not enough memory to start this scan now.',
    }
  }
  if (limitType === 'hard') {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'hard',
      reason: b.error || 'A configured concurrency limit is currently reached.',
    }
  }
  if (b.activationInProgress) {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'activating',
      reason: b.error || 'A version activation is in progress for this project.',
    }
  }
  if (status === 409) {
    return {
      kind: 'temporary',
      temporary: true,
      blockedCode: 'busy',
      reason: b.error || b.busy || 'The project is busy with another scan right now.',
    }
  }
  if (
    opts.orchestratorAnswered
    && !(b.code && PERMANENT_CODES.has(b.code))
    && (b.snapshotFailed || status === 500 || status === 503)
  ) {
    return {
      kind: 'transient',
      temporary: true,
      blockedCode: 'transient',
      reason: b.error || 'The scan could not be started because of a passing error; it will be retried.',
    }
  }

  return {
    kind: 'permanent',
    temporary: false,
    blockedCode: '',
    reason: b.error || 'The scan could not be started.',
  }
}
