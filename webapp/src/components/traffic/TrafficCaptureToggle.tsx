'use client'

import { Toggle } from '@/components/ui'
import { useCaptureRouting } from './useCaptureRouting'

/**
 * Per-project TrafficMind capture-routing toggle, used by the settings matrix.
 *
 * Reads and writes the project's `captureProxyEnabled` flag through useCaptureRouting (PUT
 * /api/projects/[id]) - the change applies immediately and takes effect on the project's next
 * session. Shows the current project name next to the switch so the operator always knows which
 * project they are toggling.
 *
 * `initialEnabled` lets a parent that already knows the value (e.g. the settings matrix) skip the
 * self-fetch; when omitted the component fetches it once. The save sends the row's `updatedAt` as it
 * was read (`initialVersion`, or the self-fetch's): a value someone else changed since is refused,
 * and the toggle then shows the row as it is now (step 5.2).
 */
export function TrafficCaptureToggle({
  projectId,
  projectName,
  initialEnabled,
  initialVersion,
  showName = true,
  size = 'default',
}: {
  projectId: string
  projectName?: string | null
  initialEnabled?: boolean
  /** The row's `updatedAt` when `initialEnabled` was read with it. */
  initialVersion?: string | null
  showName?: boolean
  size?: 'small' | 'default' | 'large'
}) {
  const { enabled, saving, setCapture } = useCaptureRouting({ projectId, projectName, initialEnabled, initialVersion })

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      {showName && (
        <span style={{ fontSize: 13, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
          Enable traffic capture for{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{projectName || 'this project'}</strong>
        </span>
      )}
      <Toggle
        checked={!!enabled}
        onChange={setCapture}
        disabled={enabled === null || saving}
        size={size}
        aria-label={`Toggle traffic capture${projectName ? ` for ${projectName}` : ''}`}
      />
    </div>
  )
}
