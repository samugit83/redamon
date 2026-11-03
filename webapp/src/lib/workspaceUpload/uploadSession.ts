/**
 * Resumable uploads into the agent workspace: create a session, PUT the Blob in
 * chunks, commit it into a job, then follow that job to the end.
 *
 * Every failure is an ApiError read with readApiError, so the message carries
 * the server's sentence, code and status. Two outcomes are not failures: an
 * abort rejects with an AbortError, and a session the server no longer has
 * (swept by a workspace reset or an agent restart) rejects with
 * TransferCancelledError.
 *
 * Browser-only.
 */
import { ApiError, readApiError, toApiError } from '@/lib/apiError'

export type UploadKind = 'file' | 'folder' | 'archive'
export type ConflictPolicy = 'keep_both' | 'replace' | 'fail'

export type JobStatus = 'running' | 'done' | 'failed' | 'cancelled' | 'interrupted'

export interface JobProgress {
  phase?: string
  files?: number
  bytes?: number
  totalBytes?: number
  /** Set when the job is done: the final project-relative path (Keep both may have renamed it). */
  path?: string
}

export interface WorkspaceJob {
  job_id: string
  status: JobStatus
  /** A failure code such as `unsafe_path`, or null. */
  error: string | null
  progress: JobProgress | null
  tool_name?: string
}

export interface UploadProgress {
  sentBytes: number
  totalBytes: number
}

export interface UploadBlobOptions {
  projectId: string
  destDir: string
  name: string
  kind: UploadKind
  blob: Blob
  onConflict?: ConflictPolicy
  onProgress?: (progress: UploadProgress) => void
  /** True while the server answers 429 and the request waits to be retried; false when it goes through. */
  onWaiting?: (waiting: boolean) => void
  signal?: AbortSignal
}

export interface UploadResult {
  jobId: string
  uploadId: string
}

export interface WaitForJobOptions {
  onProgress?: (job: WorkspaceJob) => void
  onWaiting?: (waiting: boolean) => void
  signal?: AbortSignal
  intervalMs?: number
}

export const SESSION_SWEPT_REASON = 'the workspace was reset or the agent restarted'

/** The transfer ended without failing: the server dropped it on purpose. */
export class TransferCancelledError extends Error {
  readonly reason: string

  constructor(reason: string) {
    super(`Cancelled: ${reason}`)
    this.name = 'TransferCancelledError'
    this.reason = reason
  }
}

const SESSIONS_URL = '/api/agent/workspace/upload-sessions'
const JSON_HEADERS = { 'Content-Type': 'application/json' }

const DEFAULT_CHUNK_BYTES = 8 * 1024 * 1024
// The chunk proxy refuses a body over 16 MiB before it reaches the agent.
const MAX_CHUNK_BYTES = 16 * 1024 * 1024
const RETRY_DELAYS_MS = [500, 1000, 2000]
const RATE_LIMIT_DELAYS_MS = [1000, 2000, 4000, 8000]
const RATE_LIMIT_GIVE_UP_MS = 2 * 60 * 1000
// Caps a Retry-After so a misconfigured proxy cannot park the transfer for an hour.
const RETRY_AFTER_MAX_MS = 60 * 1000
const MAX_OFFSET_CORRECTIONS = 5

const RATE_LIMITED = 'The server is rate-limiting requests and refused this one for 2 minutes. Try again later'

export function isAbortError(err: unknown): boolean {
  return !!err && typeof err === 'object' && (err as { name?: unknown }).name === 'AbortError'
}

function abortError(): DOMException {
  return new DOMException('The transfer was aborted.', 'AbortError')
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError())
    const onAbort = () => {
      clearTimeout(timer)
      reject(abortError())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

function retryAfterMs(res: Response): number | null {
  const raw = res.headers.get('Retry-After')?.trim()
  if (!raw) return null
  if (/^\d+$/.test(raw)) return Number(raw) * 1000
  const at = Date.parse(raw)
  return Number.isNaN(at) ? null : Math.max(0, at - Date.now())
}

async function rateLimitedError(res: Response): Promise<ApiError> {
  const last = await readApiError(res, RATE_LIMITED)
  // nginx answers its limit with an HTML page; the agent's own 429s carry a code worth keeping.
  const code = last.code && last.code !== 'non_json_response' && last.code !== 'empty_response' ? last.code : 'rate_limited'
  return new ApiError({ reason: RATE_LIMITED, status: 429, code, ...(last.upstreamStatus ? { upstreamStatus: last.upstreamStatus } : {}) })
}

/**
 * fetch that waits out 429 answers: Retry-After when given, else 1, 2, 4, 8, 8… s,
 * until 2 minutes of nothing but 429. Any other answer is returned as is; a
 * request that got no answer throws.
 */
async function fetchPatiently(
  url: string,
  init: RequestInit,
  { signal, onWaiting }: { signal?: AbortSignal; onWaiting?: (waiting: boolean) => void },
): Promise<Response> {
  let limitedSince: number | null = null
  try {
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(url, { ...init, signal })
      if (res.status !== 429) return res
      if (limitedSince === null) {
        limitedSince = Date.now()
        onWaiting?.(true)
      } else if (Date.now() - limitedSince >= RATE_LIMIT_GIVE_UP_MS) {
        throw await rateLimitedError(res)
      }
      const backoff = RATE_LIMIT_DELAYS_MS[Math.min(attempt, RATE_LIMIT_DELAYS_MS.length - 1)]
      await sleep(Math.min(retryAfterMs(res) ?? backoff, RETRY_AFTER_MAX_MS), signal)
    }
  } finally {
    if (limitedSince !== null) onWaiting?.(false)
  }
}

function asApiError(err: unknown, fallback: string): unknown {
  if (isAbortError(err)) return abortError()
  return toApiError(err, fallback)
}

// This tab's sessions that are neither committed nor known to be deleted. A
// keepalive DELETE sent while the page unloads can be lost; the next drawer
// mount in this tab deletes what is left. sessionStorage, not localStorage: it
// is per tab, so a sweep never touches another tab's live upload.
const OPEN_UPLOADS_KEY = 'redamon-workspace-open-uploads'

interface OpenUpload { projectId: string; uploadId: string }

function readOpen(): OpenUpload[] {
  try {
    const list = JSON.parse(sessionStorage.getItem(OPEN_UPLOADS_KEY) || '[]')
    return Array.isArray(list) ? list.filter((e) => e && typeof e.uploadId === 'string' && typeof e.projectId === 'string') : []
  } catch {
    return []
  }
}

function writeOpen(list: OpenUpload[]): void {
  try {
    sessionStorage.setItem(OPEN_UPLOADS_KEY, JSON.stringify(list.slice(-50)))
  } catch {
    // storage unavailable or full: the server's idle sweep is the backstop
  }
}

function rememberOpen(projectId: string, uploadId: string): void {
  writeOpen([...readOpen().filter((e) => e.uploadId !== uploadId), { projectId, uploadId }])
}

function forgetOpen(uploadId: string): void {
  writeOpen(readOpen().filter((e) => e.uploadId !== uploadId))
}

/** Delete this tab's sessions an earlier page left behind. Call on mount. */
export function sweepAbandonedUploads(): void {
  for (const e of readOpen()) deleteUploadSession(e.projectId, e.uploadId)
}

/** `promise`, or an AbortError as soon as `signal` aborts (then `onAbandon` runs once). */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal | undefined, onAbandon: () => void): Promise<T> {
  if (!signal) return promise
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      onAbandon()
      reject(abortError())
    }
    if (signal.aborted) return onAbort()
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      (value) => { signal.removeEventListener('abort', onAbort); resolve(value) },
      (err) => { signal.removeEventListener('abort', onAbort); reject(err) },
    )
  })
}

/** Ask the server to drop a session. keepalive lets it leave with a closing page; a failure is left to the server's sweep. */
export function deleteUploadSession(projectId: string, uploadId: string): void {
  const url = `${SESSIONS_URL}/${encodeURIComponent(uploadId)}?projectId=${encodeURIComponent(projectId)}`
  try {
    fetch(url, { method: 'DELETE', keepalive: true })
      .then((res) => { if (res.ok) forgetOpen(uploadId) })
      .catch(() => {})
  } catch {
    // fetch can throw synchronously while the page is being torn down.
  }
}

async function createSession(opts: UploadBlobOptions, patience: Parameters<typeof fetchPatiently>[2]) {
  const failed = 'Could not start the upload'
  let res: Response
  try {
    res = await fetchPatiently(SESSIONS_URL, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({
        projectId: opts.projectId,
        destDir: opts.destDir,
        name: opts.name,
        size: opts.blob.size,
        kind: opts.kind,
        onConflict: opts.onConflict ?? 'keep_both',
      }),
    }, patience)
  } catch (err) {
    throw asApiError(err, failed)
  }
  if (!res.ok) throw await readApiError(res, failed)
  const body = await res.json().catch(() => null) as { uploadId?: unknown; chunkSize?: unknown } | null
  if (!body || typeof body.uploadId !== 'string' || !body.uploadId) {
    throw new ApiError({ reason: failed, status: res.status, code: 'invalid_json' })
  }
  const chunk = typeof body.chunkSize === 'number' && Number.isInteger(body.chunkSize) && body.chunkSize > 0
    ? Math.min(body.chunkSize, MAX_CHUNK_BYTES)
    : DEFAULT_CHUNK_BYTES
  return { uploadId: body.uploadId, chunkSize: chunk }
}

async function sendChunks(
  opts: UploadBlobOptions,
  uploadId: string,
  chunkSize: number,
  patience: Parameters<typeof fetchPatiently>[2],
): Promise<void> {
  const failed = 'Could not upload a chunk'
  const { blob, signal } = opts
  const size = blob.size
  let offset = 0
  let retries = 0
  let corrections = 0
  opts.onProgress?.({ sentBytes: 0, totalBytes: size })

  while (offset < size) {
    if (signal?.aborted) throw abortError()
    const end = Math.min(offset + chunkSize, size)
    const url = `${SESSIONS_URL}/${encodeURIComponent(uploadId)}/chunk?projectId=${encodeURIComponent(opts.projectId)}&offset=${offset}`
    let res: Response | null = null
    let noAnswer: unknown = null
    try {
      res = await fetchPatiently(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: blob.slice(offset, end),
      }, patience)
    } catch (err) {
      if (isAbortError(err)) throw abortError()
      if (err instanceof ApiError) throw err
      noAnswer = err
    }

    if (res === null || res.status >= 500) {
      if (retries >= RETRY_DELAYS_MS.length) throw res ? await readApiError(res, failed) : toApiError(noAnswer, failed)
      await sleep(RETRY_DELAYS_MS[retries++], signal)
      continue
    }

    if (res.ok) {
      const body = await res.json().catch(() => null) as { received?: unknown } | null
      const received = body?.received
      const next = typeof received === 'number' && Number.isInteger(received) && received >= 0 && received <= size ? received : end
      if (next <= offset && ++corrections > MAX_OFFSET_CORRECTIONS) {
        throw new ApiError({ reason: 'The server stopped accepting the upload', status: res.status, code: 'upload_stalled' })
      }
      if (next > offset) corrections = 0
      retries = 0
      offset = next
      opts.onProgress?.({ sentBytes: offset, totalBytes: size })
      continue
    }

    const err = await readApiError(res, failed)
    if (err.code === 'session_not_found') throw new TransferCancelledError(SESSION_SWEPT_REASON)
    const expected = err.body?.expectedOffset
    if (err.code === 'offset_mismatch' && typeof expected === 'number' && Number.isInteger(expected)
      && expected >= 0 && expected <= size && ++corrections <= MAX_OFFSET_CORRECTIONS) {
      offset = expected
      opts.onProgress?.({ sentBytes: offset, totalBytes: size })
      continue
    }
    throw err
  }
}

async function commitSession(opts: UploadBlobOptions, uploadId: string, patience: Parameters<typeof fetchPatiently>[2]) {
  const failed = 'Could not finish the upload'
  let res: Response
  try {
    res = await fetchPatiently(`${SESSIONS_URL}/${encodeURIComponent(uploadId)}/commit`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({ projectId: opts.projectId }),
    }, patience)
  } catch (err) {
    throw asApiError(err, failed)
  }
  if (!res.ok) {
    const err = await readApiError(res, failed)
    if (err.code === 'session_not_found') throw new TransferCancelledError(SESSION_SWEPT_REASON)
    throw err
  }
  const body = await res.json().catch(() => null) as { jobId?: unknown } | null
  if (!body || typeof body.jobId !== 'string' || !body.jobId) {
    throw new ApiError({ reason: failed, status: res.status, code: 'invalid_json' })
  }
  return body.jobId
}

/**
 * Send `blob` through an upload session and commit it. Resolves once the server
 * has started the job that places it; follow that job with waitForJob.
 *
 * Chunks are retried 3 times on no answer or a 5xx (after 0.5, 1 and 2 s); a
 * 409 offset_mismatch resumes where the server stands; a 429 waits and never
 * spends a retry. On abort the session is deleted and the promise rejects with
 * an AbortError; on any other failure the session is deleted too.
 */
export async function uploadBlob(opts: UploadBlobOptions): Promise<UploadResult> {
  const { signal, projectId } = opts
  if (signal?.aborted) throw abortError()
  const patience = { signal, onWaiting: opts.onWaiting }

  // The create is never aborted: the server may have made the session before
  // the abort, and only its answer names the session to delete. An abort
  // meanwhile rejects at once and deletes the session when the answer lands.
  const creating = createSession(opts, { onWaiting: opts.onWaiting })
  const { uploadId, chunkSize } = await untilAborted(creating, signal, () => {
    creating.then((c) => deleteUploadSession(projectId, c.uploadId), () => {})
  })
  rememberOpen(projectId, uploadId)
  let open = true
  const close = () => {
    if (!open) return
    open = false
    deleteUploadSession(projectId, uploadId)
  }
  // Sent from the abort itself, not after the rejection: an unmount or a
  // closing page may not run anything later.
  signal?.addEventListener('abort', close, { once: true })
  try {
    await sendChunks(opts, uploadId, chunkSize, patience)
    if (signal?.aborted) throw abortError()
    const jobId = await commitSession(opts, uploadId, patience)
    open = false
    forgetOpen(uploadId)
    return { jobId, uploadId }
  } catch (err) {
    if (signal?.aborted) {
      close()
      throw abortError()
    }
    if (err instanceof TransferCancelledError) {
      open = false
      forgetOpen(uploadId)
    }
    close()
    throw err
  } finally {
    signal?.removeEventListener('abort', close)
  }
}

const TERMINAL: ReadonlySet<string> = new Set<JobStatus>(['done', 'failed', 'cancelled', 'interrupted'])

/**
 * Poll a workspace job every `intervalMs` until it is done, failed, cancelled or
 * interrupted, and resolve with its last record. A 429 waits like an upload
 * does; no answer or a 5xx is retried 3 times in a row before it fails.
 */
export async function waitForJob(
  projectId: string,
  jobId: string,
  { onProgress, onWaiting, signal, intervalMs = 1000 }: WaitForJobOptions = {},
): Promise<WorkspaceJob> {
  const failed = 'Could not read the transfer status'
  const url = `/api/agent/workspace/jobs/${encodeURIComponent(jobId)}?projectId=${encodeURIComponent(projectId)}`
  let retries = 0
  for (;;) {
    if (signal?.aborted) throw abortError()
    let res: Response | null = null
    let noAnswer: unknown = null
    try {
      res = await fetchPatiently(url, { cache: 'no-store' }, { signal, onWaiting })
    } catch (err) {
      if (isAbortError(err)) throw abortError()
      if (err instanceof ApiError) throw err
      noAnswer = err
    }

    if (res && res.ok) {
      const job = await res.json().catch(() => null) as WorkspaceJob | null
      if (!job || typeof job.status !== 'string') throw new ApiError({ reason: failed, status: res.status, code: 'invalid_json' })
      retries = 0
      onProgress?.(job)
      if (TERMINAL.has(job.status)) return job
    } else if (res && res.status < 500) {
      throw await readApiError(res, failed)
    } else if (retries++ >= RETRY_DELAYS_MS.length) {
      throw res ? await readApiError(res, failed) : toApiError(noAnswer, failed)
    }
    await sleep(intervalMs, signal)
  }
}
