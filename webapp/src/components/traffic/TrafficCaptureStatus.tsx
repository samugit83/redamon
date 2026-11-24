'use client'

import { useCan } from '@/hooks/useCan'
import { useCaptureRouting } from './useCaptureRouting'

/**
 * Per-project TrafficMind capture-routing status for the /traffic page top bar: whether capture
 * routing is on for the current project. Whoever may change the capture (platform:traffic_capture,
 * the same people the settings matrix is shown to) also gets an Enable / Disable button beside it,
 * which writes exactly what that project's switch in the matrix writes (useCaptureRouting). Anyone
 * else reads the status only, and is told to ask an administrator when it is off.
 */
export function TrafficCaptureStatus({
  projectId,
  projectName,
}: {
  projectId: string
  projectName?: string | null
}) {
  const canManageCapture = useCan('platform:traffic_capture')
  const { enabled, loadError, saving, setCapture } = useCaptureRouting({ projectId, projectName })

  // A failed read is not "Disabled": that told the operator to ask an admin to enable a capture
  // that may well be on.
  if (loadError) {
    return (
      <span style={{ fontSize: 13, color: 'var(--text-tertiary)' }} role="status">{loadError}</span>
    )
  }
  if (enabled === null) return null

  const on = enabled
  const target = projectName ? ` for ${projectName}` : ''
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, flexWrap: 'wrap' }}>
      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: on ? 'var(--success, #30a46c)' : 'var(--danger, #e5484d)', flexShrink: 0 }} />
        Traffic capture{projectName ? <> for <strong style={{ color: 'var(--text-primary)' }}>{projectName}</strong></> : null}:{' '}
        <strong style={{ color: on ? 'var(--success, #30a46c)' : 'var(--danger, #e5484d)' }}>{on ? 'Enabled' : 'Disabled'}</strong>
      </span>
      {canManageCapture ? (
        <button
          type="button"
          className={on ? 'secondaryButton' : 'primaryButton'}
          disabled={saving}
          aria-label={`${on ? 'Disable' : 'Enable'} traffic capture${target}`}
          title={`${on ? 'Stop routing' : 'Route'} this project's traffic through the capture proxy, from its next session`}
          onClick={() => setCapture(!on)}
        >
          {on ? 'Disable' : 'Enable'}
        </button>
      ) : !on && (
        <span style={{ color: 'var(--text-tertiary)' }}>
          Ask an administrator to enable it.
        </span>
      )}
    </div>
  )
}
