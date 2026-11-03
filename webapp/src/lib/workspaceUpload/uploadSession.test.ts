import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { ApiError } from '@/lib/apiError'
import {
  SESSION_SWEPT_REASON, TransferCancelledError, uploadBlob, waitForJob,
  type UploadBlobOptions, type WorkspaceJob,
} from './uploadSession'

const UPLOAD_ID = 'a'.repeat(32)
const JOB_ID = 'b'.repeat(32)

interface Call { url: string; method: string; init: RequestInit }
type Handler = (call: Call) => Response | Promise<Response>

let calls: Call[] = []
let routes: { create: Handler; chunk: Handler; commit: Handler; remove: Handler; job: Handler }

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } })
}

function offsetOf(call: Call): number {
  return Number(new URL(call.url, 'http://x').searchParams.get('offset'))
}

/** A chunk route that accepts whatever continues the upload, like the agent does. */
function acceptingChunks(): Handler {
  return (call) => json({ received: offsetOf(call) + (call.init.body as Blob).size })
}

function chunkCalls(): Call[] {
  return calls.filter((c) => c.method === 'PUT')
}

beforeEach(() => {
  calls = []
  routes = {
    create: () => json({ uploadId: UPLOAD_ID, chunkSize: 4, maxBytes: 1 << 30 }, 201),
    chunk: acceptingChunks(),
    commit: () => json({ jobId: JOB_ID, destDir: '.', name: 'site', kind: 'folder', size: 8 }, 202),
    remove: () => json({ aborted: true }),
    job: () => json({ job_id: JOB_ID, status: 'done', error: null, progress: { phase: 'done', path: 'site' } }),
  }
  global.fetch = vi.fn((input: string | URL | Request, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input.toString()
    const call = { url, method: init.method ?? 'GET', init }
    calls.push(call)
    const route = call.method === 'POST' && url.endsWith('/upload-sessions') ? routes.create
      : call.method === 'PUT' ? routes.chunk
        : url.includes('/commit') ? routes.commit
          : call.method === 'DELETE' ? routes.remove
            : routes.job
    return new Promise<Response>((resolve, reject) => {
      const signal = init.signal
      const abort = () => reject(new DOMException('The operation was aborted.', 'AbortError'))
      if (signal?.aborted) return abort()
      signal?.addEventListener('abort', abort)
      Promise.resolve(route(call)).then(resolve, reject)
    })
  }) as unknown as typeof fetch
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

function options(blob: Blob, extra: Partial<UploadBlobOptions> = {}): UploadBlobOptions {
  return { projectId: 'p1', destDir: 'uploads', name: 'site', kind: 'folder', blob, onConflict: 'keep_both', ...extra }
}

/** Observe a promise's outcome without leaving a rejection unhandled while timers advance. */
function track<T>(p: Promise<T>) {
  const state: { value?: T; error?: unknown; done: boolean } = { done: false }
  p.then((value) => { state.value = value; state.done = true }, (error) => { state.error = error; state.done = true })
  return state
}

describe('uploadBlob', () => {
  test('chunks at exact boundaries', async () => {
    const result = await uploadBlob(options(new Blob(['abcdefgh'])))

    expect(result).toEqual({ jobId: JOB_ID, uploadId: UPLOAD_ID })
    const create = calls[0]
    expect(create.url).toBe('/api/agent/workspace/upload-sessions')
    expect(JSON.parse(create.init.body as string)).toEqual({
      projectId: 'p1', destDir: 'uploads', name: 'site', size: 8, kind: 'folder', onConflict: 'keep_both',
    })
    expect(chunkCalls().map(offsetOf)).toEqual([0, 4])
    expect(chunkCalls().map((c) => (c.init.body as Blob).size)).toEqual([4, 4])
    expect(await (chunkCalls()[1].init.body as Blob).text()).toBe('efgh')
    expect(chunkCalls()[0].url).toBe(`/api/agent/workspace/upload-sessions/${UPLOAD_ID}/chunk?projectId=p1&offset=0`)
    expect((chunkCalls()[0].init.headers as Record<string, string>)['Content-Type']).toBe('application/octet-stream')
    const commit = calls[calls.length - 1]
    expect(commit.url).toBe(`/api/agent/workspace/upload-sessions/${UPLOAD_ID}/commit`)
    expect(JSON.parse(commit.init.body as string)).toEqual({ projectId: 'p1' })

    calls = []
    await uploadBlob(options(new Blob(['abcdefghi'])))
    expect(chunkCalls().map(offsetOf)).toEqual([0, 4, 8])
    expect(chunkCalls().map((c) => (c.init.body as Blob).size)).toEqual([4, 4, 1])
  })

  test('retries a 5xx chunk', async () => {
    vi.useFakeTimers()
    let failures = 1
    routes.chunk = (call) => (failures-- > 0 ? json({ error: 'Bad gateway' }, 502) : acceptingChunks()(call))

    const ok = track(uploadBlob(options(new Blob(['abcdefgh']))))
    await vi.advanceTimersByTimeAsync(499)
    expect(chunkCalls()).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(1)
    await vi.waitFor(() => expect(ok.done).toBe(true))
    expect(ok.value).toEqual({ jobId: JOB_ID, uploadId: UPLOAD_ID })
    expect(chunkCalls().map(offsetOf)).toEqual([0, 0, 4])

    // Three retries (0.5, 1, 2 s) and the fourth failure ends the upload with the server's answer.
    calls = []
    routes.chunk = () => json({ error: 'Failed to upload a chunk', code: 'agent_unreachable' }, 503)
    const failed = track(uploadBlob(options(new Blob(['abcd']))))
    await vi.advanceTimersByTimeAsync(3500)
    expect(failed.done).toBe(true)
    expect(chunkCalls()).toHaveLength(4)
    expect(failed.error).toBeInstanceOf(ApiError)
    expect((failed.error as ApiError).code).toBe('agent_unreachable')
    // The half-sent session is not left behind on the server.
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(1)
  })

  test('adopts expectedOffset on 409', async () => {
    let first = true
    routes.chunk = (call) => {
      if (first) {
        first = false
        return json({ error: 'The chunk does not continue the upload where it stands.', code: 'offset_mismatch', expectedOffset: 8 }, 409)
      }
      return acceptingChunks()(call)
    }

    const result = await uploadBlob(options(new Blob(['abcdefghijkl'])))

    expect(result.jobId).toBe(JOB_ID)
    expect(chunkCalls().map(offsetOf)).toEqual([0, 8])
    expect(await (chunkCalls()[1].init.body as Blob).text()).toBe('ijkl')
  })

  test('abort deletes the session', async () => {
    routes.chunk = () => new Promise<Response>(() => {})
    const controller = new AbortController()

    const upload = track(uploadBlob(options(new Blob(['abcdefgh']), { signal: controller.signal })))
    await vi.waitFor(() => expect(chunkCalls()).toHaveLength(1))
    controller.abort()
    await vi.waitFor(() => expect(upload.done).toBe(true))

    expect((upload.error as Error).name).toBe('AbortError')
    const deletes = calls.filter((c) => c.method === 'DELETE')
    expect(deletes).toHaveLength(1)
    expect(deletes[0].url).toBe(`/api/agent/workspace/upload-sessions/${UPLOAD_ID}?projectId=p1`)
    expect(deletes[0].init.keepalive).toBe(true)
    expect(calls.some((c) => c.url.includes('/commit'))).toBe(false)
  })

  test('an abort during create deletes the session once the create answers', async () => {
    // The server may have created the session already: the client must learn
    // its id to delete it, so the create itself is never aborted.
    let answerCreate: (r: Response) => void = () => {}
    routes.create = () => new Promise<Response>((resolve) => { answerCreate = resolve })
    const controller = new AbortController()

    const upload = track(uploadBlob(options(new Blob(['abcdefgh']), { signal: controller.signal })))
    await vi.waitFor(() => expect(calls.filter((c) => c.method === 'POST')).toHaveLength(1))
    controller.abort()
    await vi.waitFor(() => expect(upload.done).toBe(true))
    expect((upload.error as Error).name).toBe('AbortError')
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0)

    answerCreate(json({ uploadId: UPLOAD_ID, chunkSize: 4, maxBytes: 1 << 30 }, 201))
    await vi.waitFor(() => expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(1))
    expect(calls.filter((c) => c.method === 'DELETE')[0].url)
      .toBe(`/api/agent/workspace/upload-sessions/${UPLOAD_ID}?projectId=p1`)
    expect(chunkCalls()).toHaveLength(0)
  })

  test('reports progress', async () => {
    const onProgress = vi.fn()
    await uploadBlob(options(new Blob(['abcdefghij']), { onProgress }))

    expect(onProgress.mock.calls.map(([p]) => [p.sentBytes, p.totalBytes])).toEqual([
      [0, 10], [4, 10], [8, 10], [10, 10],
    ])
  })

  test('a 429 chunk is retried after Retry-After without spending an attempt', async () => {
    vi.useFakeTimers()
    const answers = [
      () => new Response('<html>429</html>', { status: 429, headers: { 'Retry-After': '3' } }),
      () => json({ error: 'down' }, 503),
      () => json({ error: 'down' }, 503),
      () => json({ error: 'down' }, 503),
    ]
    routes.chunk = (call) => (answers.shift() ?? acceptingChunks())(call)
    const onWaiting = vi.fn()

    const upload = track(uploadBlob(options(new Blob(['abcd']), { onWaiting })))
    await vi.advanceTimersByTimeAsync(2999)
    expect(chunkCalls()).toHaveLength(1)
    expect(onWaiting).toHaveBeenLastCalledWith(true)
    await vi.advanceTimersByTimeAsync(1)
    expect(chunkCalls()).toHaveLength(2)
    expect(onWaiting).toHaveBeenLastCalledWith(false)
    // Three 5xx retries are still available after the 429.
    await vi.advanceTimersByTimeAsync(500 + 1000 + 2000)
    await vi.waitFor(() => expect(upload.done).toBe(true))
    expect(upload.error).toBeUndefined()
    expect(chunkCalls()).toHaveLength(5)
  })

  test('a 429 without Retry-After backs off and recovers', async () => {
    vi.useFakeTimers()
    let createRefusals = 3
    const realCreate = routes.create
    routes.create = (call) => (createRefusals-- > 0 ? new Response('', { status: 429 }) : realCreate(call))
    let commitRefusals = 1
    const realCommit = routes.commit
    routes.commit = (call) => (commitRefusals-- > 0
      ? json({ error: 'Too many uploads and imports are running on the server. Retry shortly.', code: 'too_many_jobs' }, 429)
      : realCommit(call))
    const creates = () => calls.filter((c) => c.url.endsWith('/upload-sessions')).length
    const onWaiting = vi.fn()

    const upload = track(uploadBlob(options(new Blob(['abcd']), { onWaiting })))
    await vi.advanceTimersByTimeAsync(999)
    expect(creates()).toBe(1)
    await vi.advanceTimersByTimeAsync(1)
    expect(creates()).toBe(2)
    await vi.advanceTimersByTimeAsync(1999)
    expect(creates()).toBe(2)
    await vi.advanceTimersByTimeAsync(1)
    expect(creates()).toBe(3)
    await vi.advanceTimersByTimeAsync(4000)
    expect(creates()).toBe(4)
    // The commit's own 429 waits a second and goes through.
    await vi.advanceTimersByTimeAsync(1000)
    await vi.waitFor(() => expect(upload.done).toBe(true))
    expect(upload.value).toEqual({ jobId: JOB_ID, uploadId: UPLOAD_ID })
    expect(calls.filter((c) => c.url.includes('/commit'))).toHaveLength(2)
    expect(onWaiting.mock.calls.map(([w]) => w)).toEqual([true, false, true, false])
  })

  test('two minutes of 429 fails with the rate-limit message', async () => {
    vi.useFakeTimers()
    routes.chunk = () => new Response('<html>Too Many Requests</html>', { status: 429 })
    const onWaiting = vi.fn()

    const upload = track(uploadBlob(options(new Blob(['abcd']), { onWaiting })))
    await vi.advanceTimersByTimeAsync(119_000)
    expect(upload.done).toBe(false)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(upload.done).toBe(true)

    const err = upload.error as ApiError
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(429)
    expect(err.code).toBe('rate_limited')
    expect(err.message).toMatch(/rate-limiting/)
    expect(onWaiting).toHaveBeenLastCalledWith(false)
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(1)
  })

  test('a swept session ends as cancelled with the reset reason', async () => {
    const swept = () => json({
      error: 'The upload session does not exist (the workspace was reset or the agent restarted).',
      code: 'session_not_found', upstreamStatus: 404,
    }, 404)
    routes.chunk = swept

    const onChunk = await uploadBlob(options(new Blob(['abcdefgh']))).catch((e) => e)
    expect(onChunk).toBeInstanceOf(TransferCancelledError)
    expect(onChunk.reason).toBe(SESSION_SWEPT_REASON)
    expect(SESSION_SWEPT_REASON).toBe('the workspace was reset or the agent restarted')

    routes.chunk = acceptingChunks()
    routes.commit = swept
    const onCommit = await uploadBlob(options(new Blob(['abcd']))).catch((e) => e)
    expect(onCommit).toBeInstanceOf(TransferCancelledError)
    expect(onCommit.reason).toBe(SESSION_SWEPT_REASON)
    // The session is gone already: nothing to delete.
    expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(0)
  })
})

describe('waitForJob', () => {
  const running: WorkspaceJob = {
    job_id: JOB_ID, status: 'running', error: null, tool_name: 'workspace_upload',
    progress: { phase: 'extracting', files: 3, bytes: 300, totalBytes: 900 },
  }

  test('waitForJob resolves on each terminal status', async () => {
    vi.useFakeTimers()
    for (const status of ['done', 'failed', 'cancelled', 'interrupted'] as const) {
      calls = []
      const terminal: WorkspaceJob = {
        ...running, status, error: status === 'failed' ? 'unsafe_path' : null,
        progress: status === 'done' ? { phase: 'done', path: 'uploads/site-2' } : running.progress,
      }
      const answers = [running, terminal]
      routes.job = () => json(answers.shift() ?? terminal)
      const onProgress = vi.fn()

      const wait = track(waitForJob('p1', JOB_ID, { onProgress }))
      await vi.advanceTimersByTimeAsync(999)
      expect(wait.done).toBe(false)
      await vi.advanceTimersByTimeAsync(1)
      await vi.waitFor(() => expect(wait.done).toBe(true))

      expect(wait.value).toEqual(terminal)
      expect(onProgress.mock.calls.map(([j]) => j.status)).toEqual(['running', status])
      expect(calls[0].url).toBe(`/api/agent/workspace/jobs/${JOB_ID}?projectId=p1`)
      expect(calls).toHaveLength(2)
    }
  })

  test('a 429 on a job poll keeps polling', async () => {
    vi.useFakeTimers()
    const answers = [
      () => new Response('', { status: 429 }),
      () => json(running),
      () => json({ ...running, status: 'done', progress: { phase: 'done', path: 'site' } }),
    ]
    routes.job = () => answers.shift()!()
    const onWaiting = vi.fn()

    const wait = track(waitForJob('p1', JOB_ID, { onWaiting }))
    await vi.advanceTimersByTimeAsync(1000)
    expect(calls).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(1000)
    await vi.waitFor(() => expect(wait.done).toBe(true))

    expect((wait.value as WorkspaceJob).status).toBe('done')
    expect(onWaiting.mock.calls.map(([w]) => w)).toEqual([true, false])
  })
})
