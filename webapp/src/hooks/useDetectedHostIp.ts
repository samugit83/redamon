'use client'

import { useState, useEffect } from 'react'

/**
 * Fetches the Docker host's LAN IP (detected by redamon.sh, served by the agent)
 * so the project settings UI can suggest it as the reverse-shell LHOST (issue #180).
 *
 * Mode-independent by design: it is NOT sourced from /defaults (which is fetched
 * create-mode only and collapses into the saved form data). It refetches whenever
 * `enabled` flips true (e.g. a settings modal opening), so the value is as fresh as
 * the last `./redamon.sh up` — a container cannot read the host's live LAN IP, so
 * the value is bound to a stack restart. Returns '' on any failure; the caller then
 * shows no suggestion.
 */
export function useDetectedHostIp(enabled: boolean = true): string {
  const [detectedHostIp, setDetectedHostIp] = useState('')

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    fetch('/api/agent/host-ip', { cache: 'no-store' })
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (!cancelled && data && typeof data.detectedHostIp === 'string') {
          setDetectedHostIp(data.detectedHostIp)
        }
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [enabled])

  return detectedHostIp
}
