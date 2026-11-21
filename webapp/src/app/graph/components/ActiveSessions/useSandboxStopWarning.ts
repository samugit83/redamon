'use client'

import { useEffect, useState } from 'react'
import { HOLD_MAX_NO_USE_S, HOLD_WARN_BEFORE_S, SESSION_ROUTE_STATUS } from '@/lib/sandbox/contract'

/** The warning moves by the minute at most, and only while the Sessions panel is open. */
const POLL_MS = 60_000

/** Hours without use after which a sandbox held only by live sessions warns (7 with the contract's timings). */
export const WARN_AFTER_HOURS = (HOLD_MAX_NO_USE_S - HOLD_WARN_BEFORE_S) / 3600

/** `HH:MM` in the viewer's local time. */
export function stopTimeLabel(stopAtEpochS: number): string {
  const d = new Date(stopAtEpochS * 1000)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

export function stopWarningText(stopAtEpochS: number): string {
  return `Your Kali sandbox stops at ${stopTimeLabel(stopAtEpochS)} because it has not been used for ${WARN_AFTER_HOURS} hours; use it to keep it running`
}

/**
 * When the signed-in person's own Kali sandbox will stop, once it warns (group 1, OQ-G1-9 A: the
 * sandbox's person only; GET /api/agent/sandbox/status decides whose sandbox from the session). Null
 * when it does not warn, in shared mode, or when the status cannot be read: the banner is a hint and
 * never an error of the panel.
 */
export function useSandboxStopWarning(enabled: boolean): number | null {
  const [stopAt, setStopAt] = useState<number | null>(null)

  useEffect(() => {
    if (!enabled) {
      setStopAt(null)
      return
    }
    let live = true
    const read = async () => {
      let next: number | null = null
      try {
        const res = await fetch(SESSION_ROUTE_STATUS, { cache: 'no-store' })
        if (res.ok) {
          const body = await res.json() as { instances?: Array<{ warn?: unknown; stop_at?: unknown }> }
          const warning = (Array.isArray(body.instances) ? body.instances : [])
            .find(i => i?.warn === true && typeof i.stop_at === 'number')
          next = warning ? (warning.stop_at as number) : null
        }
      } catch {
        next = null
      }
      if (live) setStopAt(next)
    }
    void read()
    const timer = setInterval(() => { void read() }, POLL_MS)
    return () => {
      live = false
      clearInterval(timer)
    }
  }, [enabled])

  return stopAt
}
