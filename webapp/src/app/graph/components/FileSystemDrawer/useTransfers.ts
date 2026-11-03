'use client'

/**
 * Transfers into the workspace, for every project at once: queued → uploading →
 * processing → done | failed | cancelled. Two parts that do not depend on each
 * other: sending bytes (uploadBlob, at most MAX_SENDING at a time) and
 * following the job that places them (waitForJob). A transfer that already has
 * a job, such as a URL import, enters at the second part through addJob.
 *
 * Lives as long as the component that calls it. Unmounting aborts the
 * transfers still sending bytes (their sessions are deleted) and stops
 * following the others, whose jobs keep running on the server.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { errorMessage, fetchJson } from '@/lib/apiError'
import {
  isAbortError, sweepAbandonedUploads, TransferCancelledError, uploadBlob, waitForJob,
  type ConflictPolicy, type UploadKind, type WorkspaceJob,
} from '@/lib/workspaceUpload/uploadSession'
import { jobFailureMessage } from './transferMessages'

export const MAX_SENDING = 2

export type TransferKind = UploadKind | 'import'
export type TransferStatus = 'queued' | 'uploading' | 'processing' | 'done' | 'failed' | 'cancelled'

export interface Transfer {
  id: string
  projectId: string
  kind: TransferKind
  name: string
  destDir: string
  status: TransferStatus
  sentBytes: number
  totalBytes: number
  jobId?: string
  /** The job's progress phase while processing (queued, resolving, downloading, extracting, placing). */
  phase?: string
  files?: number
  bytes?: number
  jobTotalBytes?: number
  /** The server answers 429 and the transfer waits to retry. */
  waiting: boolean
  savedPath?: string
  error?: string
  cancelReason?: string
}

export interface UploadRequest {
  projectId: string
  kind: UploadKind
  name: string
  destDir: string
  blob: Blob
  onConflict?: ConflictPolicy
}

export interface JobRequest {
  projectId: string
  kind: TransferKind
  name: string
  destDir: string
  jobId: string
}

export interface TransfersApi {
  /** Every project's transfers, oldest first; filter by projectId to show one project's. */
  transfers: readonly Transfer[]
  addUpload: (request: UploadRequest) => string
  addJob: (request: JobRequest) => string
  /** Rejects when the server refuses to cancel a job that is processing. */
  cancel: (id: string) => Promise<void>
  dismiss: (id: string) => void
}

export function isActive(status: TransferStatus): boolean {
  return status === 'queued' || status === 'uploading' || status === 'processing'
}

function isSending(status: TransferStatus): boolean {
  return status === 'queued' || status === 'uploading'
}

function joinPath(dir: string, name: string): string {
  return dir === '.' || dir === '' ? name : `${dir}/${name}`
}

interface Runtime {
  request?: UploadRequest
  upload?: AbortController
  poll?: AbortController
}

interface Engine {
  attach: () => void
  dispose: () => void
  abortSending: () => void
  addUpload: TransfersApi['addUpload']
  addJob: TransfersApi['addJob']
  cancel: TransfersApi['cancel']
  dismiss: TransfersApi['dismiss']
}

function createEngine(publish: (list: Transfer[]) => void, onDone: (t: Transfer) => void): Engine {
  const store = new Map<string, Transfer>()
  const runtime = new Map<string, Runtime>()
  const queue: string[] = []
  const sending = new Set<string>()
  let alive = true
  let seq = 0

  const emit = () => {
    if (alive) publish(Array.from(store.values()))
  }

  const patch = (id: string, change: Partial<Transfer>): Transfer | undefined => {
    const current = store.get(id)
    if (!current) return undefined
    const next = { ...current, ...change }
    store.set(id, next)
    emit()
    return next
  }

  const finish = (id: string, err: unknown) => {
    if (!alive) return
    if (isAbortError(err)) patch(id, { status: 'cancelled', waiting: false })
    else if (err instanceof TransferCancelledError) patch(id, { status: 'cancelled', waiting: false, cancelReason: err.reason })
    else patch(id, { status: 'failed', waiting: false, error: errorMessage(err, 'The transfer failed') })
  }

  const settle = (id: string, job: WorkspaceJob) => {
    const t = store.get(id)
    if (!t) return
    if (job.status === 'done') {
      const done = patch(id, { status: 'done', waiting: false, savedPath: job.progress?.path || joinPath(t.destDir, t.name) })
      if (done) onDone(done)
    } else if (job.status === 'cancelled') {
      patch(id, { status: 'cancelled', waiting: false })
    } else {
      patch(id, { status: 'failed', waiting: false, error: jobFailureMessage(job.status === 'interrupted' ? 'interrupted' : job.error) })
    }
  }

  const follow = async (id: string, projectId: string, jobId: string) => {
    const rt = runtime.get(id)
    if (!rt) return
    const ctrl = new AbortController()
    rt.poll = ctrl
    try {
      const job = await waitForJob(projectId, jobId, {
        signal: ctrl.signal,
        onWaiting: (waiting) => patch(id, { waiting }),
        onProgress: (j) => patch(id, {
          phase: j.progress?.phase,
          files: j.progress?.files,
          bytes: j.progress?.bytes,
          jobTotalBytes: j.progress?.totalBytes,
        }),
      })
      if (alive) settle(id, job)
    } catch (err) {
      finish(id, err)
    } finally {
      rt.poll = undefined
    }
  }

  const send = async (id: string, rt: Runtime, request: UploadRequest) => {
    const ctrl = new AbortController()
    rt.upload = ctrl
    patch(id, { status: 'uploading' })
    let jobId: string
    try {
      ({ jobId } = await uploadBlob({
        projectId: request.projectId,
        destDir: request.destDir,
        name: request.name,
        kind: request.kind,
        blob: request.blob,
        onConflict: request.onConflict ?? 'keep_both',
        signal: ctrl.signal,
        onProgress: ({ sentBytes, totalBytes }) => patch(id, { sentBytes, totalBytes }),
        onWaiting: (waiting) => patch(id, { waiting }),
      }))
    } catch (err) {
      finish(id, err)
      return
    } finally {
      rt.upload = undefined
      sending.delete(id)
      pump()
    }
    if (!alive) return
    patch(id, { status: 'processing', jobId, waiting: false, phase: 'queued' })
    await follow(id, request.projectId, jobId)
  }

  function pump() {
    while (alive && sending.size < MAX_SENDING && queue.length > 0) {
      const id = queue.shift()!
      const rt = runtime.get(id)
      const request = rt?.request
      if (!rt || !request) continue
      // The Blob may be a whole folder's tar; keep no reference once it is sent.
      rt.request = undefined
      sending.add(id)
      void send(id, rt, request)
    }
  }

  const nextId = () => `transfer-${++seq}`

  return {
    attach() {
      alive = true
      // Sessions an earlier page of this tab could not delete as it closed.
      sweepAbandonedUploads()
    },

    dispose() {
      alive = false
      queue.length = 0
      for (const rt of runtime.values()) {
        rt.upload?.abort()
        rt.poll?.abort()
      }
    },

    abortSending() {
      for (const id of queue.splice(0)) {
        runtime.get(id)!.request = undefined
        patch(id, { status: 'cancelled' })
      }
      for (const id of sending) runtime.get(id)?.upload?.abort()
    },

    addUpload(request) {
      const id = nextId()
      store.set(id, {
        id, projectId: request.projectId, kind: request.kind, name: request.name, destDir: request.destDir,
        status: 'queued', sentBytes: 0, totalBytes: request.blob.size, waiting: false,
      })
      runtime.set(id, { request })
      queue.push(id)
      emit()
      pump()
      return id
    },

    addJob(request) {
      const id = nextId()
      store.set(id, {
        id, projectId: request.projectId, kind: request.kind, name: request.name, destDir: request.destDir,
        status: 'processing', jobId: request.jobId, phase: 'queued', sentBytes: 0, totalBytes: 0, waiting: false,
      })
      runtime.set(id, {})
      emit()
      void follow(id, request.projectId, request.jobId)
      return id
    },

    async cancel(id) {
      const t = store.get(id)
      const rt = runtime.get(id)
      if (!t || !rt) return
      if (t.status === 'queued') {
        const at = queue.indexOf(id)
        if (at >= 0) queue.splice(at, 1)
        rt.request = undefined
        patch(id, { status: 'cancelled' })
      } else if (t.status === 'uploading') {
        rt.upload?.abort()
      } else if (t.status === 'processing' && t.jobId) {
        // The job answers cancelled on its next poll.
        await fetchJson(
          `/api/agent/workspace/jobs/${encodeURIComponent(t.jobId)}/cancel?projectId=${encodeURIComponent(t.projectId)}`,
          { method: 'POST' },
          'Could not cancel the transfer',
        )
      }
    },

    dismiss(id) {
      const t = store.get(id)
      if (!t || isActive(t.status)) return
      store.delete(id)
      runtime.delete(id)
      emit()
    },
  }
}

export function useTransfers({ onDone }: { onDone?: (t: Transfer) => void } = {}): TransfersApi {
  const [transfers, setTransfers] = useState<Transfer[]>([])
  const onDoneRef = useRef(onDone)
  useEffect(() => {
    onDoneRef.current = onDone
  })

  const [engine] = useState(() => createEngine(setTransfers, (t) => onDoneRef.current?.(t)))

  useEffect(() => {
    engine.attach()
    return () => engine.dispose()
  }, [engine])

  // The browser's own leave-page prompt, only while leaving would lose bytes.
  // pagehide then drops the sessions those uploads opened.
  const sendingNow = transfers.some((t) => isSending(t.status))
  useEffect(() => {
    if (!sendingNow) return
    const onBeforeUnload = (ev: BeforeUnloadEvent) => {
      ev.preventDefault()
      ev.returnValue = ''
    }
    const onPageHide = () => engine.abortSending()
    window.addEventListener('beforeunload', onBeforeUnload)
    window.addEventListener('pagehide', onPageHide)
    return () => {
      window.removeEventListener('beforeunload', onBeforeUnload)
      window.removeEventListener('pagehide', onPageHide)
    }
  }, [sendingNow, engine])

  return useMemo(() => ({
    transfers,
    addUpload: engine.addUpload,
    addJob: engine.addJob,
    cancel: engine.cancel,
    dismiss: engine.dismiss,
  }), [transfers, engine])
}
