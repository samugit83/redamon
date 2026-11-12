'use client'

import { useEffect, useState } from 'react'
import { useCan } from '@/hooks/useCan'
import { fetchJson, errorMessage } from '@/lib/apiError'

/**
 * Read-only per-project TrafficMind capture-routing status for the /traffic page
 * top bar. It shows whether capture routing is on for the current project, but
 * does NOT change it: enabling/disabling capture is done in the TrafficMind
 * settings (platform:traffic_capture), so this is display-only. When disabled it
 * tells anyone without that permission to ask an administrator.
 */
export function TrafficCaptureStatus({
  projectId,
  projectName,
}: {
  projectId: string
  projectName?: string | null
}) {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  // A failed read is not "Disabled": that told the operator to ask an admin to
  // enable a capture that may well be on.
  const [loadError, setLoadError] = useState<string | null>(null)
  const canManageCapture = useCan('platform:traffic_capture')

  useEffect(() => {
    let cancelled = false
    setEnabled(null)
    setLoadError(null)
    if (!projectId) return
    fetchJson<{ captureProxyEnabled?: boolean }>(`/api/projects/${projectId}`, undefined, 'Capture status unavailable')
      .then((p) => { if (!cancelled) setEnabled(!!p.captureProxyEnabled) })
      .catch((err) => { if (!cancelled) setLoadError(errorMessage(err, 'Capture status unavailable')) })
    return () => { cancelled = true }
  }, [projectId])

  if (loadError) {
    return (
      <span style={{ fontSize: 13, color: 'var(--text-tertiary)' }} role="status">{loadError}</span>
    )
  }
  if (enabled === null) return null

  const on = enabled
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, flexWrap: 'wrap' }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: on ? 'var(--success, #30a46c)' : 'var(--danger, #e5484d)', flexShrink: 0 }} />
        Traffic capture{projectName ? <> for <strong style={{ color: 'var(--text-primary)' }}>{projectName}</strong></> : null}:{' '}
        <strong style={{ color: on ? 'var(--success, #30a46c)' : 'var(--danger, #e5484d)' }}>{on ? 'Enabled' : 'Disabled'}</strong>
      </span>
      {!on && !canManageCapture && (
        <span style={{ color: 'var(--text-tertiary)' }}>
          Ask an administrator to enable it.
        </span>
      )}
    </div>
  )
}
