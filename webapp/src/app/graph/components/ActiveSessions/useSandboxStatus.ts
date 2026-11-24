'use client'

import { useEffect, useState } from 'react'
import { readOwnSandboxStatus, type OwnSandboxStatus } from '@/lib/sandbox/ownSandboxStatus'

/** The warning moves by the minute at most, and only while the Sessions panel is open. */
const POLL_MS = 60_000

const NOTHING: OwnSandboxStatus = { stopAt: null, reversePort: null }

/**
 * The signed-in person's own Kali sandbox for the Sessions panel (group 1, OQ-G1-9 A; FU-24): when it
 * stops once it warns, and its reverse-shell port. GET /api/agent/sandbox/status decides whose
 * sandbox from the session. Nothing when disabled or when the status cannot be read: the lines are
 * hints and never an error of the panel.
 */
export function useSandboxStatus(enabled: boolean): OwnSandboxStatus {
  const [status, setStatus] = useState<OwnSandboxStatus>(NOTHING)

  useEffect(() => {
    if (!enabled) {
      setStatus(NOTHING)
      return
    }
    let live = true
    const read = async () => {
      const next = await readOwnSandboxStatus()
      if (live) setStatus(next ?? NOTHING)
    }
    void read()
    const timer = setInterval(() => { void read() }, POLL_MS)
    return () => {
      live = false
      clearInterval(timer)
    }
  }, [enabled])

  return status
}
