'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { useToast } from '@/components/ui'
import { errorMessage, fetchJson } from '@/lib/apiError'
import { versionOf } from '@/lib/projectVersion'
import { STALE_FIELD_NOTICE, reloadProjectRow, saveProjectFields } from '@/lib/projectFieldSave'

const READ_FAILED = 'Capture status unavailable'
const SAVE_FAILED = 'Failed to update traffic capture setting'

/**
 * One project's TrafficMind capture routing (`captureProxyEnabled`), read and written the one way:
 * a single-field PUT /api/projects/[id] carrying the row's `updatedAt` as it was read, so a value
 * someone else changed meanwhile is refused and shown as it is now (step 5.2). The settings matrix's
 * switches and the TrafficMind page's Enable/Disable button both go through here, so they have the
 * same effect, the same toasts and the same stale-row handling.
 *
 * `initialEnabled` (with `initialVersion`) lets a caller that already read the row skip the read.
 * A failed read leaves `enabled` null and says why in `loadError`: it is never shown as "off".
 */
export function useCaptureRouting({ projectId, projectName, initialEnabled, initialVersion }: {
  projectId: string
  projectName?: string | null
  initialEnabled?: boolean
  initialVersion?: string | null
}) {
  const toast = useToast()
  const [enabled, setEnabled] = useState<boolean | null>(initialEnabled === undefined ? null : initialEnabled)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const versionRef = useRef<string | null>(versionOf(initialVersion))

  useEffect(() => {
    setLoadError(null)
    if (initialEnabled !== undefined) {
      setEnabled(initialEnabled)
      versionRef.current = versionOf(initialVersion)
      return
    }
    let cancelled = false
    setEnabled(null)
    if (!projectId) return
    fetchJson<{ captureProxyEnabled?: boolean; updatedAt?: string | null }>(`/api/projects/${projectId}`, undefined, READ_FAILED)
      .then((p) => {
        if (cancelled) return
        setEnabled(!!p.captureProxyEnabled)
        versionRef.current = versionOf(p.updatedAt)
      })
      .catch((err) => { if (!cancelled) setLoadError(errorMessage(err, READ_FAILED)) })
    return () => { cancelled = true }
  }, [projectId, initialEnabled, initialVersion])

  const setCapture = useCallback(async (next: boolean) => {
    if (saving || !projectId) return
    const prev = enabled
    setEnabled(next)
    setSaving(true)
    try {
      const saved = await saveProjectFields(projectId, { captureProxyEnabled: next }, versionRef.current, SAVE_FAILED)
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
      toast.error(errorMessage(err, SAVE_FAILED))
    } finally {
      setSaving(false)
    }
  }, [saving, projectId, projectName, enabled, toast])

  return { enabled, loadError, saving, setCapture }
}
