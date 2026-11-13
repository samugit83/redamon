'use client'

import { useEffect, useRef, useState } from 'react'
import { Toggle, useToast } from '@/components/ui'
import { errorMessage } from '@/lib/apiError'
import { versionOf } from '@/lib/projectVersion'
import { STALE_FIELD_NOTICE, reloadProjectRow, saveProjectFields } from '@/lib/projectFieldSave'

/**
 * Per-project TrafficMind capture-routing toggle.
 *
 * Reads and writes the project's `captureProxyEnabled` flag directly (PUT
 * /api/projects/[id]) - the change applies immediately and takes effect on the
 * project's next session. Shows the current project name next to the switch so
 * the operator always knows which project they are toggling.
 *
 * `initialEnabled` lets a parent that already knows the value (e.g. the settings
 * matrix) skip the self-fetch; when omitted the component fetches it once.
 * The save sends the row's `updatedAt` as it was read (`initialVersion`, or the
 * self-fetch's): a value someone else changed since is refused, and the toggle
 * then shows the row as it is now (step 5.2).
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
  const [enabled, setEnabled] = useState<boolean | null>(
    initialEnabled === undefined ? null : initialEnabled
  )
  const [saving, setSaving] = useState(false)
  const versionRef = useRef<string | null>(versionOf(initialVersion))
  const toast = useToast()

  useEffect(() => {
    if (initialEnabled !== undefined) {
      setEnabled(initialEnabled)
      versionRef.current = versionOf(initialVersion)
      return
    }
    let cancelled = false
    setEnabled(null)
    if (!projectId) return
    fetch(`/api/projects/${projectId}`)
      .then((r) => (r.ok ? r.json() : null))
      .then((p) => {
        if (cancelled || !p) return
        setEnabled(!!p.captureProxyEnabled)
        versionRef.current = versionOf(p.updatedAt)
      })
      .catch(() => { if (!cancelled) setEnabled(false) })
    return () => { cancelled = true }
  }, [projectId, initialEnabled, initialVersion])

  async function onToggle(next: boolean) {
    if (saving || !projectId) return
    const prev = enabled
    setEnabled(next)
    setSaving(true)
    try {
      const saved = await saveProjectFields(projectId, { captureProxyEnabled: next }, versionRef.current, 'Failed to update traffic capture setting')
      if (!saved.ok) {
        toast.warning(STALE_FIELD_NOTICE)
        const row = await reloadProjectRow(projectId)
        setEnabled(row ? !!row.captureProxyEnabled : prev ?? false)
        if (row) versionRef.current = versionOf(row.updatedAt)
        return
      }
      versionRef.current = saved.version ?? versionRef.current
      toast.success(`Traffic capture ${next ? 'enabled' : 'disabled'}${projectName ? ` for ${projectName}` : ''}`)
    } catch (err) {
      setEnabled(prev ?? false)
      toast.error(errorMessage(err, 'Failed to update traffic capture setting'))
    } finally {
      setSaving(false)
    }
  }

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
        onChange={onToggle}
        disabled={enabled === null || saving}
        size={size}
        aria-label={`Toggle traffic capture${projectName ? ` for ${projectName}` : ''}`}
      />
    </div>
  )
}
