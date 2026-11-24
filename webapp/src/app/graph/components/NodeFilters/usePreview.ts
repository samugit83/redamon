'use client'

/**
 * Preview the draft rules against the active version's live graph, as the
 * operator types.
 *
 * Debounced (600 ms), and a new preview aborts the one in flight. A 429 means
 * the project's previous preview is still running: the last counts stay on
 * screen, marked stale, and the request is retried shortly. A 503 or a
 * timeout makes the preview "unavailable" (Save still works).
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { NodeFilterDoc, NodeFilterMode } from '@/lib/nodeFilters/model'

export interface PreviewSample { key: string; name: string; host: string; guards: string[] }

export interface PreviewKindStats {
  active: boolean
  scanned: number
  would_mute: number
  to_mute: number
  to_unmute: number
  to_restamp: number
  guarded: number
  exempt: number
  operator_muted: number
  missing: Record<string, number>
  rules: Record<string, { name: string; matched: number; samples: PreviewSample[] }>
}

export interface PreviewResult {
  ok: boolean
  partial: boolean
  error?: string
  kinds: Record<string, PreviewKindStats>
  totals: Record<string, number>
  related?: { hosts: string[]; cves: string[] }
  relatedRemediations?: number | null
  validation?: string[]
}

/** `updating`: the counts on screen are for rules that have since changed. */
export type PreviewState = 'idle' | 'loading' | 'ready' | 'updating' | 'busy' | 'unavailable'

export const PREVIEW_DEBOUNCE_MS = 600
const BUSY_RETRY_MS = 1500

export async function fetchPreview(
  projectId: string, mode: NodeFilterMode, rules: NodeFilterDoc,
  opts: { signal?: AbortSignal; withRemediations?: boolean } = {},
): Promise<{ status: number; body: PreviewResult & { error?: string } }> {
  const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/node-filters/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, rules, ...(opts.withRemediations ? { withRemediations: true } : {}) }),
    signal: opts.signal,
  })
  const body = await res.json().catch(() => ({ error: 'invalid response' }))
  return { status: res.status, body }
}

export function usePreview(projectId: string | null, mode: NodeFilterMode, rules: NodeFilterDoc, enabled = true) {
  const [result, setResult] = useState<PreviewResult | null>(null)
  const [state, setState] = useState<PreviewState>('idle')
  const [message, setMessage] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)
  const abortRef = useRef<AbortController | null>(null)

  const retry = useCallback(() => setNonce(n => n + 1), [])

  // At once, not after the debounce: from this moment the counts on screen
  // describe rules the operator has already changed.
  const [requested, setRequested] = useState({ projectId, mode, rules, enabled, nonce })
  if (requested.projectId !== projectId || requested.mode !== mode || requested.rules !== rules
      || requested.enabled !== enabled || requested.nonce !== nonce) {
    setRequested({ projectId, mode, rules, enabled, nonce })
    if (projectId && enabled) setState(prev => (prev === 'ready' ? 'updating' : prev))
  }

  useEffect(() => {
    if (!projectId || !enabled) return
    const timer = setTimeout(async () => {
      abortRef.current?.abort()
      const controller = new AbortController()
      abortRef.current = controller
      setState(prev => (prev === 'ready' || prev === 'updating' || prev === 'busy' ? prev : 'loading'))
      try {
        const { status, body } = await fetchPreview(projectId, mode, rules, { signal: controller.signal })
        if (controller.signal.aborted) return
        if (status === 429) {
          setState('busy')
          setTimeout(() => setNonce(n => n + 1), BUSY_RETRY_MS)
          return
        }
        if (status === 400) {
          setState('ready')
          setMessage(body.error ?? 'The rules are not readable.')
          return
        }
        if (status !== 200) {
          setState('unavailable')
          setMessage(body.error ?? `Preview failed (${status})`)
          return
        }
        setResult(body)
        setMessage(null)
        setState('ready')
      } catch (e) {
        if ((e as { name?: string })?.name === 'AbortError') return
        setState('unavailable')
        setMessage(e instanceof Error ? e.message : 'Preview failed')
      }
    }, PREVIEW_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [projectId, mode, rules, enabled, nonce])

  useEffect(() => () => abortRef.current?.abort(), [])

  return { result, state, message, retry }
}
