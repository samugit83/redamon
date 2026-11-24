import { useCallback, useEffect, useRef, useState } from 'react'
import { SANDBOX_STATUS_REASONS, SANDBOX_STATUS_STATES, type SandboxStatusPayload } from '@/lib/sandbox/contract'

/**
 * The run's Kali sandbox in the chat drawer (the agent's `sandbox_status` frame,
 * sent only, never saved). `starting` shows a status line in place of the loading
 * word, `ready` clears it, and `unavailable` shows the modal once per run. A frame
 * counts only while a run is in flight. Retry sends the query that started the run
 * again, under the text the chat showed for it, and only once that run is over:
 * while it goes on (the model answers the failed tool), Retry just closes.
 */
export const SANDBOX_STARTING_WORD = 'Starting your Kali sandbox…'
export const SANDBOX_RETRY_NOT_SENT =
  'Not connected to the agent: your message was not sent again. Wait for the connection to come back, then send it again.'

const STATES: ReadonlySet<string> = new Set(SANDBOX_STATUS_STATES)
const REASONS: ReadonlySet<string> = new Set(SANDBOX_STATUS_REASONS)

export function sandboxStatusFromPayload(payload: unknown): SandboxStatusPayload | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null
  const p = payload as Record<string, unknown>
  if (typeof p.state !== 'string' || !STATES.has(p.state)) return null
  const out: SandboxStatusPayload = { state: p.state as SandboxStatusPayload['state'] }
  if (typeof p.reason === 'string' && REASONS.has(p.reason)) out.reason = p.reason as SandboxStatusPayload['reason']
  if (typeof p.detail === 'string') out.detail = p.detail
  if (p.limit && typeof p.limit === 'object') out.limit = p.limit as SandboxStatusPayload['limit']
  return out
}

export interface SandboxStatusOptions {
  isLoading: boolean
  sessionId: unknown
  projectId: unknown
  /** Opens the modal (useSandboxUnavailable) and resolves with the person's choice. */
  showUnavailable: (payload: SandboxStatusPayload) => Promise<'retry' | 'close'>
  /** Whether no run is in flight: read when a frame arrives and when the person presses Retry. */
  runEnded: () => boolean
  /** Sends the run's query again, as a new run, shown in the chat as `shown`. */
  resend: (query: string, shown: string) => void
}

export function useSandboxStatus(opts: SandboxStatusOptions) {
  const { isLoading, sessionId, projectId } = opts
  const [sandboxWord, setSandboxWord] = useState<string | null>(null)
  // The socket handler captures its callbacks once: everything they read lives in refs.
  const optsRef = useRef(opts)
  optsRef.current = opts
  const scopeRef = useRef({ sessionId, projectId })
  const runRef = useRef(0)
  const shownRunRef = useRef<number | null>(null)
  const queryRef = useRef<{ query: string; shown: string } | null>(null)

  // A run can stop loading with no frame after `starting` (a dropped socket), so
  // the line never outlives the loading state, its session or its project.
  useEffect(() => { if (!isLoading) setSandboxWord(null) }, [isLoading])
  useEffect(() => {
    scopeRef.current = { sessionId, projectId }
    setSandboxWord(null)
    runRef.current += 1
    queryRef.current = null
  }, [sessionId, projectId])

  /**
   * A query starts a run, with the text the chat shows for it (a chat skill's
   * context is sent, not shown); a resume starts one that keeps both.
   */
  const noteRunStart = useCallback((query?: string | null, shown?: string | null) => {
    runRef.current += 1
    setSandboxWord(null)
    if (typeof query === 'string') queryRef.current = { query, shown: shown ?? query }
  }, [])

  const onSandboxStatus = useCallback((payload: unknown) => {
    const status = sandboxStatusFromPayload(payload)
    // A frame with no run in flight (it ended, or never started in this tab) is late or
    // stray: it neither shows a line the next run would inherit nor offers a re-send.
    if (!status || optsRef.current.runEnded()) return
    if (status.state === 'starting') { setSandboxWord(SANDBOX_STARTING_WORD); return }
    setSandboxWord(null)
    if (status.state !== 'unavailable') return

    const run = runRef.current
    if (shownRunRef.current === run) return
    shownRunRef.current = run
    const scope = scopeRef.current
    const sent = queryRef.current
    void optsRef.current.showUnavailable(status).then((answer) => {
      if (answer !== 'retry' || status.reason === 'refused' || !sent) return
      if (scopeRef.current !== scope || runRef.current !== run) return
      if (!optsRef.current.runEnded()) return
      optsRef.current.resend(sent.query, sent.shown)
    })
  }, [])

  return { sandboxWord, onSandboxStatus, noteRunStart }
}
