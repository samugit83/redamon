'use client'

import { useState, useEffect, useCallback } from 'react'

/**
 * Preflight for any settings panel whose "Test" button is really a proxy to the
 * agent container (LLM providers, MCP servers).
 *
 * Why: the agent is the process that actually dials the operator's endpoint. If
 * it is down, the test fails before RedAmon ever leaves its own network, and the
 * error lands under the field the operator just typed - which reads as "your URL
 * is wrong" (issue #184). Knowing the agent is offline BEFORE the click is what
 * stops the misdiagnosis; the route-level message is only the fallback.
 *
 * `unknown` while the first probe is in flight: callers must not disable Test on
 * `unknown`, or a slow probe would block a working setup.
 */
export type AgentHealthStatus = 'unknown' | 'online' | 'offline'

export interface AgentHealth {
  status: AgentHealthStatus
  /** Operator-facing reason from the API route when offline. */
  error: string | null
  /** Re-probe (e.g. after the operator restarts the container). */
  refresh: () => void
}

export function useAgentHealth(): AgentHealth {
  const [status, setStatus] = useState<AgentHealthStatus>('unknown')
  const [error, setError] = useState<string | null>(null)
  const [nonce, setNonce] = useState(0)

  useEffect(() => {
    // `cancelled` covers unmount too: React runs this effect's cleanup on the
    // way out, so a probe that resolves afterwards sets no state.
    let cancelled = false

    const probe = async () => {
      try {
        const resp = await fetch('/api/agent/health')
        if (cancelled) return
        if (resp.ok) {
          setStatus('online')
          setError(null)
          return
        }
        const body = await resp.json().catch(() => ({}))
        if (cancelled) return
        setStatus('offline')
        setError(
          typeof body?.error === 'string'
            ? body.error
            : `The RedAmon agent service is not responding (HTTP ${resp.status}).`,
        )
      } catch {
        // A failure of the browser -> webapp hop, not webapp -> agent. Report it
        // as offline too: either way no test can succeed right now.
        if (cancelled) return
        setStatus('offline')
        setError('Could not reach the RedAmon webapp to check the agent service.')
      }
    }

    probe()
    return () => { cancelled = true }
  }, [nonce])

  const refresh = useCallback(() => {
    setStatus('unknown')
    setError(null)
    setNonce(n => n + 1)
  }, [])

  return { status, error, refresh }
}
