/**
 * The per-project graph-operation lock (S-4).
 *
 * Four paths check the project's graph and then change it or the version
 * timeline: a full-scan start (freeze, rotate, then the scan wipes the graph), a
 * partial-recon start (the run writes the graph), "save current as a version"
 * (freeze, rotate) and a version activation (freeze, clear, restore, move the
 * pointer). Each checks the others first, but a check holds only until the
 * checker's next await: a start that passed its activation check could freeze a
 * half-restored graph and spawn a scan into the swap. So each path holds this
 * lock from its guard check through its last write, which for a start is the
 * orchestrator's answer (from then on the writer checks see the scan).
 *
 * Starts queue behind the project's other starts, so a double-clicked Start
 * waits and then meets the first scan in its writer check. A save or an
 * activation never waits: it is refused while anything holds the lock, and a
 * start that arrives while one of them holds it is refused too. Callers answer
 * those refusals with 409, which the job queue reads as "busy, requeue".
 *
 * In-process on purpose: the webapp runs as one replica and every caller (the
 * buttons, the scheduler, the queue dispatcher, MCP) reaches these paths through
 * it. A lock that lives in the process dies with it, so a crash never leaves a
 * project locked, as a row lock would until its TTL; scaled out, this becomes a
 * Postgres advisory lock. It lives on globalThis so every route bundle, and a dev
 * hot reload, shares one map.
 *
 * The activation's row lock (activationLock.ts) stays: it is what the agent, the
 * mute routes and the other scanners read to learn that a swap is in flight.
 */

export type GraphLockHolder = 'scan-start' | 'version-save' | 'activation'
export type ExclusiveGraphOp = Exclude<GraphLockHolder, 'scan-start'>

export type GraphLockResult<T> =
  | { acquired: true; value: T }
  | { acquired: false; heldBy: GraphLockHolder }

/** Completes "Cannot <do X> while <phrase> for this project." */
export const GRAPH_LOCK_HOLDER_PHRASE: Record<GraphLockHolder, string> = {
  'scan-start': 'a scan is being started',
  'version-save': 'the current graph is being saved as a version',
  activation: 'a version activation is in progress',
}

interface ProjectGraphLock {
  exclusive: ExclusiveGraphOp | null
  /** Starts running or waiting their turn. */
  starts: number
  /** Settles when the last queued start has finished; never rejects. */
  tail: Promise<void>
}

const globalForGraphLock = globalThis as unknown as {
  __projectGraphLocks?: Map<string, ProjectGraphLock>
}
const locks: Map<string, ProjectGraphLock> =
  globalForGraphLock.__projectGraphLocks ?? new Map()
globalForGraphLock.__projectGraphLocks = locks

function lockFor(projectId: string): ProjectGraphLock {
  let lock = locks.get(projectId)
  if (!lock) {
    lock = { exclusive: null, starts: 0, tail: Promise.resolve() }
    locks.set(projectId, lock)
  }
  return lock
}

function releaseIfIdle(projectId: string, lock: ProjectGraphLock): void {
  if (!lock.exclusive && lock.starts === 0 && locks.get(projectId) === lock) locks.delete(projectId)
}

/** What holds the project's lock right now, or null when it is free. */
export function graphLockHolder(projectId: string): GraphLockHolder | null {
  const lock = locks.get(projectId)
  if (!lock) return null
  return lock.exclusive ?? (lock.starts > 0 ? 'scan-start' : null)
}

/**
 * Run a scan start under the lock, after the project's earlier starts. When a
 * save or an activation holds the lock, `fn` does not run. A rejection of `fn`
 * is passed on, and the next start still runs.
 */
export function withGraphStartLock<T>(
  projectId: string,
  fn: () => Promise<T>,
): Promise<GraphLockResult<T>> {
  const lock = lockFor(projectId)
  if (lock.exclusive) return Promise.resolve({ acquired: false, heldBy: lock.exclusive })
  lock.starts += 1
  const run = lock.tail.then(fn).finally(() => {
    lock.starts -= 1
    releaseIfIdle(projectId, lock)
  })
  lock.tail = run.then(() => undefined, () => undefined)
  return run.then(value => ({ acquired: true as const, value }))
}

/**
 * Run a save or an activation holding the lock alone, or refuse at once without
 * running `fn` when anything holds it. Never waits: both are a person's click,
 * and a 409 that names the holder is better than a request that hangs.
 */
export async function tryWithGraphLock<T>(
  projectId: string,
  op: ExclusiveGraphOp,
  fn: () => Promise<T>,
): Promise<GraphLockResult<T>> {
  // No await before the lock is set: the check and the take are one step.
  const heldBy = graphLockHolder(projectId)
  if (heldBy) return { acquired: false, heldBy }
  const lock = lockFor(projectId)
  lock.exclusive = op
  try {
    return { acquired: true, value: await fn() }
  } finally {
    lock.exclusive = null
    releaseIfIdle(projectId, lock)
  }
}

/**
 * The backstop for a writer the lock does not see: the version it read as
 * current was demoted by another writer before it could rotate
 * (rotateToNextVersion). Answered with 409, like a held lock.
 */
export class CurrentVersionMovedError extends Error {
  constructor(public versionId: string) {
    super('The current version changed while this request was freezing it (another scan start or ' +
      'version save rotated it first), so this request opened no new version and started nothing. Try again.')
    this.name = 'CurrentVersionMovedError'
  }
}
