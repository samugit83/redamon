'use client'

import { useState, useEffect, useCallback } from 'react'
import { X, Trash2, Loader2, FolderOpen } from 'lucide-react'
import { createPortal } from 'react-dom'
import { useToast } from '@/components/ui'
import styles from './UserPresetDrawer.module.css'

interface PresetListItem {
  id: string
  name: string
  description: string
  createdAt: string
}

interface UserPresetDrawerProps {
  isOpen: boolean
  onClose: () => void
  onLoad: (settings: Record<string, unknown>) => void
  userId: string | null | undefined
}

export function UserPresetDrawer({ isOpen, onClose, onLoad, userId }: UserPresetDrawerProps) {
  const toast = useToast()
  const [presets, setPresets] = useState<PresetListItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [loadingPresetId, setLoadingPresetId] = useState<string | null>(null)
  const [deletingPresetId, setDeletingPresetId] = useState<string | null>(null)
  const [defaults, setDefaults] = useState<Record<string, unknown> | null>(null)

  // Fetch presets + defaults when drawer opens
  useEffect(() => {
    if (!isOpen || !userId) return

    setIsLoading(true)
    Promise.all([
      fetch(`/api/presets?userId=${userId}`).then(r => r.ok ? r.json() : []),
      defaults ? Promise.resolve(defaults) : fetch('/api/projects/defaults').then(r => r.ok ? r.json() : {}),
    ])
      .then(([presetList, fetchedDefaults]) => {
        setPresets(presetList)
        if (!defaults) setDefaults(fetchedDefaults)
      })
      .catch(() => {
        toast.error('Failed to load presets')
      })
      .finally(() => setIsLoading(false))
  }, [isOpen, userId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Close on Escape
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown)
      document.body.style.overflow = 'hidden'
      return () => {
        document.removeEventListener('keydown', handleKeyDown)
        document.body.style.overflow = ''
      }
    }
  }, [isOpen, handleKeyDown])

  const handleLoad = async (preset: PresetListItem) => {
    setLoadingPresetId(preset.id)
    try {
      const res = await fetch(`/api/presets/${preset.id}`)
      if (!res.ok) throw new Error('Failed to fetch preset')

      const fullPreset = await res.json()
      const presetSettings = fullPreset.settings as Record<string, unknown>

      // Merge: defaults fill missing fields, preset overrides what it has
      const merged = { ...(defaults || {}), ...presetSettings }

      onLoad(merged)
      toast.success(`Preset "${preset.name}" loaded`, 'Preset Loaded')
      onClose()
    } catch {
      toast.error('Failed to load preset')
    } finally {
      setLoadingPresetId(null)
    }
  }

  const handleDelete = async (preset: PresetListItem) => {
    if (!confirm(`Delete preset "${preset.name}"?`)) return

    setDeletingPresetId(preset.id)
    try {
      const res = await fetch(`/api/presets/${preset.id}?userId=${userId}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete preset')

      setPresets(prev => prev.filter(p => p.id !== preset.id))
      toast.success(`Preset "${preset.name}" deleted`, 'Preset Deleted')
    } catch {
      toast.error('Failed to delete preset')
    } finally {
      setDeletingPresetId(null)
    }
  }

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr)
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
  }

  if (!isOpen) return null

  const drawer = (
    <>
      <div className={styles.drawerOverlay} onClick={onClose} />

      <div className={styles.drawer} onClick={(e) => e.stopPropagation()}>
        <div className={styles.drawerHeader}>
          <h2 className={styles.drawerTitle}>My Presets</h2>
          <button
            type="button"
            className={styles.drawerClose}
            onClick={onClose}
            aria-label="Close drawer"
          >
            <X size={14} />
          </button>
        </div>

        <div className={styles.drawerBody}>
          {isLoading ? (
            <div className={styles.loading}>
              <Loader2 size={20} className={styles.spinner} />
            </div>
          ) : presets.length === 0 ? (
            <div className={styles.emptyState}>
              <FolderOpen size={32} className={styles.emptyIcon} />
              <p>No saved presets yet.</p>
              <p>Use &quot;Save as Preset&quot; to create one.</p>
            </div>
          ) : (
            presets.map(preset => (
              <div key={preset.id} className={styles.card}>
                <h3 className={styles.cardName}>{preset.name}</h3>
                {preset.description && (
                  <p className={styles.cardDescription}>{preset.description}</p>
                )}
                <span className={styles.cardDate}>{formatDate(preset.createdAt)}</span>
                <div className={styles.cardActions}>
                  <button
                    type="button"
                    className={styles.deleteButton}
                    onClick={() => handleDelete(preset)}
                    disabled={deletingPresetId === preset.id}
                    aria-label="Delete preset"
                  >
                    <Trash2 size={12} />
                  </button>
                  <button
                    type="button"
                    className={styles.loadButton}
                    onClick={() => handleLoad(preset)}
                    disabled={loadingPresetId === preset.id}
                  >
                    {loadingPresetId === preset.id ? (
                      <>
                        <Loader2 size={12} className={styles.spinner} />
                        Loading...
                      </>
                    ) : (
                      'Load'
                    )}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  )

  if (typeof document !== 'undefined') {
    return createPortal(drawer, document.body)
  }

  return null
}
