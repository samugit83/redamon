import { useState, useRef, useCallback, useEffect } from 'react'
import type { Project } from '@prisma/client'

export type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

export function useSettingsModal(projectId: string) {
  const [showSettingsDropdown, setShowSettingsDropdown] = useState(false)
  const [settingsModal, setSettingsModal] = useState<'agent' | 'toolmatrix' | 'attack' | null>(null)
  const [projectFormData, setProjectFormData] = useState<ProjectFormData | null>(null)
  const settingsDropdownRef = useRef<HTMLDivElement>(null)
  const pendingSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const latestFormDataRef = useRef(projectFormData)
  latestFormDataRef.current = projectFormData

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

  const flushPendingSave = useCallback(() => {
    if (pendingSaveRef.current) {
      clearTimeout(pendingSaveRef.current)
      pendingSaveRef.current = null
      const data = latestFormDataRef.current
      if (data && projectId) {
        fetch(`/api/projects/${projectId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
        }).catch(() => {})
      }
    }
  }, [projectId])

  // Fetch project data when modal opens; clear stale data on switch
  useEffect(() => {
    if (!settingsModal || !projectId) {
      flushPendingSave()
      setProjectFormData(null)
      return
    }
    flushPendingSave()
    setProjectFormData(null)
    let cancelled = false
    fetch(`/api/projects/${projectId}`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (!cancelled && data) {
          const { id, userId: _u, createdAt, updatedAt, user, ...formData } = data
          setProjectFormData(formData)
        }
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [settingsModal, projectId, flushPendingSave])

  const updateProjectField = useCallback(<K extends keyof ProjectFormData>(
    field: K,
    value: ProjectFormData[K]
  ) => {
    setProjectFormData(prev => {
      if (!prev) return prev
      return { ...prev, [field]: value }
    })
    if (pendingSaveRef.current) clearTimeout(pendingSaveRef.current)
    pendingSaveRef.current = setTimeout(() => {
      const data = latestFormDataRef.current
      if (!data || !projectId) return
      fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }).catch(() => {})
    }, 500)
  }, [projectId])

  return {
    showSettingsDropdown,
    setShowSettingsDropdown,
    settingsModal,
    setSettingsModal,
    projectFormData,
    updateProjectField,
    settingsDropdownRef,
  }
}
