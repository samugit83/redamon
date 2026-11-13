import { useState, useRef, useCallback, useEffect } from 'react'
import type { Project } from '@prisma/client'
import { useToast } from '@/components/ui'
import { readApiError, toApiError } from '@/lib/apiError'
import { postUserSkillsChanged, useUserSkillsChanged } from '@/lib/userSkillsChannel'
import { versionOf } from '@/lib/projectVersion'
import { STALE_FIELD_NOTICE, isStaleSave } from '@/lib/projectFieldSave'

export type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

const SAVE_DEBOUNCE_MS = 500

type ToggleMaps = { builtIn?: Record<string, boolean>; user?: Record<string, boolean> }
const mapOf = (v: unknown): Record<string, boolean> => (v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, boolean> : {})

/** `fresh` with the toggles `local` changed relative to `base` laid over it. */
export function mergeOwnToggles(base: unknown, local: unknown, fresh: unknown): ToggleMaps {
  const b = (base ?? {}) as ToggleMaps
  const l = (local ?? {}) as ToggleMaps
  const f = (fresh ?? {}) as ToggleMaps
  const mine = (key: 'builtIn' | 'user') =>
    Object.fromEntries(Object.entries(mapOf(l[key])).filter(([id, on]) => mapOf(b[key])[id] !== on))
  return { ...f, builtIn: { ...mapOf(f.builtIn), ...mine('builtIn') }, user: { ...mapOf(f.user), ...mine('user') } }
}

/**
 * The chat drawer's settings modals edit the project with a debounced auto-save that sends
 * ONLY the fields changed since the modal opened (or since the last save that landed).
 * A whole-row PUT would overwrite whatever another writer changed meanwhile, such as a new
 * skill version switched on from a review window. Each save also sends the row's `updatedAt`
 * as the modal last read it (step 5.2): a field someone else changed since is refused (409),
 * and the modal then reloads the row and says so. A save the server refuses otherwise says so
 * in a toast instead of vanishing.
 *
 * `attackSkillConfig` is one field holding every toggle, so a toggle sends the whole map. When a
 * skill version is saved elsewhere (it may switch toggles, and says so on the user-skills
 * channel), the open window takes the server's map, with the toggles it changed itself and has
 * not saved yet laid over it, so its pending save keeps both sides.
 */
export function useSettingsModal(projectId: string) {
  const toast = useToast()
  const [showSettingsDropdown, setShowSettingsDropdown] = useState(false)
  const [settingsModal, setSettingsModal] = useState<'agent' | 'toolmatrix' | 'attack' | null>(null)
  const [projectFormData, setProjectFormData] = useState<ProjectFormData | null>(null)
  // The project could not be read: the modal says so instead of spinning forever.
  const [projectLoadError, setProjectLoadError] = useState<string | null>(null)
  const settingsDropdownRef = useRef<HTMLDivElement>(null)
  const pendingSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const latestFormDataRef = useRef(projectFormData)
  latestFormDataRef.current = projectFormData
  const dirtyRef = useRef<Set<keyof ProjectFormData>>(new Set())
  const toastRef = useRef(toast)
  toastRef.current = toast
  // The toggle map as the server last had it, so a change from elsewhere can be told from this
  // window's own unsaved toggles.
  const skillBaseRef = useRef<unknown>(null)
  // The row's updatedAt as this modal last read or saved it; null sends no version (as before).
  const versionRef = useRef<string | null>(null)
  const [reloadToken, setReloadToken] = useState(0)

  // Close settings dropdown on outside click
  useEffect(() => {
    if (!showSettingsDropdown) return
    const handler = (e: MouseEvent) => {
      if (settingsDropdownRef.current && !settingsDropdownRef.current.contains(e.target as Node)) {
        setShowSettingsDropdown(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showSettingsDropdown])

  const save = useCallback(() => {
    const data = latestFormDataRef.current
    const keys = [...dirtyRef.current]
    if (!data || !projectId || keys.length === 0) return
    const patch = Object.fromEntries(keys.map(k => [k, data[k]]))
    // A key changed again while this request is in flight is marked dirty again by
    // updateProjectField, so it is never lost by being cleared here.
    for (const k of keys) dirtyRef.current.delete(k)
    fetch(`/api/projects/${projectId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(versionRef.current ? { ...patch, updatedAt: versionRef.current } : patch),
    })
      .then(async res => {
        if (res.ok) {
          const row = await res.json().catch(() => null)
          versionRef.current = versionOf(row?.updatedAt) ?? versionRef.current
          if ('attackSkillConfig' in patch) {
            if (!dirtyRef.current.has('attackSkillConfig')) skillBaseRef.current = patch.attackSkillConfig
            // Other windows of this project (the project form, another drawer) take the toggles.
            postUserSkillsChanged({ projectId })
          }
          return
        }
        const body = await res.json().catch(() => null)
        if (isStaleSave(res.status, body)) {
          // Someone else changed the row: this window takes it as it is now (its unsaved fields go).
          toastRef.current.warning(STALE_FIELD_NOTICE)
          dirtyRef.current = new Set()
          setReloadToken(t => t + 1)
          return
        }
        for (const k of keys) dirtyRef.current.add(k)
        toastRef.current.error(
          typeof body?.error === 'string' ? `Settings not saved: ${body.error}` : `Settings not saved (HTTP ${res.status}).`,
        )
      })
      .catch(() => {
        for (const k of keys) dirtyRef.current.add(k)
        toastRef.current.error('Settings not saved: the server could not be reached.')
      })
  }, [projectId])

  const flushPendingSave = useCallback(() => {
    if (pendingSaveRef.current) {
      clearTimeout(pendingSaveRef.current)
      pendingSaveRef.current = null
      save()
    }
  }, [save])

  // Fetch project data when modal opens; clear stale data on switch
  useEffect(() => {
    if (!settingsModal || !projectId) {
      flushPendingSave()
      setProjectFormData(null)
      setProjectLoadError(null)
      return
    }
    flushPendingSave()
    setProjectFormData(null)
    setProjectLoadError(null)
    dirtyRef.current = new Set()
    let cancelled = false
    const failed = 'Could not load the project settings'
    fetch(`/api/projects/${projectId}`)
      .then(async res => {
        if (!res.ok) throw await readApiError(res, failed)
        return res.json()
      })
      .then(data => {
        if (!cancelled && data) {
          const { id, userId: _u, createdAt, updatedAt, user, ...formData } = data
          skillBaseRef.current = formData.attackSkillConfig
          versionRef.current = versionOf(updatedAt)
          setProjectFormData(formData)
        }
      })
      .catch(err => {
        if (!cancelled) setProjectLoadError(toApiError(err, failed).message)
      })
    return () => { cancelled = true }
  }, [settingsModal, projectId, flushPendingSave, reloadToken])

  useUserSkillsChanged(async (change) => {
    if (!projectId || !latestFormDataRef.current || (change.projectId && change.projectId !== projectId)) return
    try {
      const res = await fetch(`/api/projects/${projectId}`)
      if (!res.ok || !latestFormDataRef.current) return
      const row = await res.json()
      const next = mergeOwnToggles(skillBaseRef.current, latestFormDataRef.current.attackSkillConfig, row.attackSkillConfig)
      skillBaseRef.current = row.attackSkillConfig
      // The merged map holds both sides' toggles, and the modal sends only the fields it changed, so
      // it may take this row's version: its next save overwrites nothing it did not change.
      versionRef.current = versionOf(row.updatedAt) ?? versionRef.current
      // The ref too: a save already debounced reads it, and must send the merged map.
      latestFormDataRef.current = { ...latestFormDataRef.current, attackSkillConfig: next as ProjectFormData['attackSkillConfig'] }
      setProjectFormData(prev => (prev ? { ...prev, attackSkillConfig: next as ProjectFormData['attackSkillConfig'] } : prev))
    } catch {
      // Nothing to refresh from; the next toggle still sends only what changed.
    }
  })

  const updateProjectField = useCallback(<K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    setProjectFormData(prev => {
      if (!prev) return prev
      return { ...prev, [field]: value }
    })
    dirtyRef.current.add(field)
    if (pendingSaveRef.current) clearTimeout(pendingSaveRef.current)
    pendingSaveRef.current = setTimeout(() => {
      pendingSaveRef.current = null
      save()
    }, SAVE_DEBOUNCE_MS)
  }, [save])

  return {
    showSettingsDropdown,
    setShowSettingsDropdown,
    settingsModal,
    setSettingsModal,
    projectFormData,
    updateProjectField,
    settingsDropdownRef,
    projectLoadError,
  }
}
