'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { SESSION_ROUTE_STATUS } from '@/lib/sandbox/contract'

/**
 * PAUSE ALL is a safety control, so it must be pressable whenever the viewer's own Kali sandbox
 * runs: a `kali_exec` job, a terminal process or a leftover handler keeps it busy with no chat or
 * scan on this page. The server picks whose sandbox and which view (the act_as one under act-as).
 */
const POLL_MS = 30_000

export function sandboxIsRunning(body: unknown): boolean {
  const instances = body && typeof body === 'object' ? (body as { instances?: unknown }).instances : null
  if (!Array.isArray(instances)) return false
  return instances.some((i) => !!i && typeof i === 'object'
    && ['running', 'starting'].includes(String((i as { state?: unknown }).state)))
}

/** Whether the viewer's own sandbox runs; false when it cannot be read (refused, failed). */
export function useOwnSandboxRunning(enabled: boolean): { running: boolean; refresh: () => void } {
  const [running, setRunning] = useState(false)
  const [wasEnabled, setWasEnabled] = useState(enabled)
  if (wasEnabled !== enabled) {
    setWasEnabled(enabled)
    if (!enabled) setRunning(false)
  }
  const live = useRef(true)

  const read = useCallback(async () => {
    try {
      const res = await fetch(SESSION_ROUTE_STATUS, { cache: 'no-store' })
      const next = res.ok ? sandboxIsRunning(await res.json()) : false
      if (live.current) setRunning(next)
    } catch {
      if (live.current) setRunning(false)
    }
  }, [])

  useEffect(() => {
    live.current = true
    if (!enabled) return () => { live.current = false }
    // eslint-disable-next-line react-hooks/set-state-in-effect -- the poll's fetch: read() sets state only once its request resolves
    void read()
    const timer = setInterval(() => { void read() }, POLL_MS)
    return () => {
      live.current = false
      clearInterval(timer)
    }
  }, [enabled, read])

  const refresh = useCallback(() => { void read() }, [read])
  return { running, refresh }
}
