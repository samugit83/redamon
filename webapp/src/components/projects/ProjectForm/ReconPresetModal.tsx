'use client'

import { useState, useEffect, useCallback } from 'react'
import { X, Check, Info, Trash2, Loader2, FolderOpen, Sparkles } from 'lucide-react'
import { icons } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { createPortal } from 'react-dom'
import { Modal } from '@/components/ui/Modal/Modal'
import { useToast } from '@/components/ui'
import { RECON_PRESETS, type ReconPreset } from '@/lib/recon-presets'
import { GeneratePresetModal } from './GeneratePresetModal'
import styles from './ReconPresetModal.module.css'

interface PresetListItem {
  id: string
  name: string
  description: string
  createdAt: string
}

interface ReconPresetDrawerProps {
  isOpen: boolean
  onClose: () => void
  onSelect: (preset: ReconPreset) => void
  onLoadUserPreset: (settings: Record<string, unknown>) => void
  currentPresetId?: string
  userId: string | null | undefined
  model: string
}

function PresetIcon({ name, size = 20 }: { name: string; size?: number }) {
  const Icon = icons[name as keyof typeof icons] as LucideIcon | undefined
  if (!Icon) return null
  return <Icon size={size} />
}

function renderDescription(text: string) {
  const parts = text.split(/^### /gm).filter(Boolean)
  return parts.map((part, i) => {
    const lines = part.split('\n')
    const title = lines[0]
    const body = lines.slice(1).join('\n').trim()
    return (
      <div key={i} className={styles.detailSection}>
        <h4>{title}</h4>
        {body.split('\n').map((line, j) => {
          const trimmed = line.trim()
          if (trimmed.startsWith('- ')) {
            return <div key={j} className={styles.detailLineBullet}>{trimmed}</div>
          }
          if (!trimmed) return <br key={j} />
          return <div key={j} className={styles.detailLine}>{trimmed}</div>
        })}
      </div>
    )
  })
}

function formatDate(dateStr: string) {
  const d = new Date(dateStr)
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function ReconPresetModal({
  isOpen,
  onClose,
  onSelect,
  onLoadUserPreset,
  currentPresetId,
  userId,
  model,
}: ReconPresetDrawerProps) {
  const toast = useToast()
  const [detailPreset, setDetailPreset] = useState<ReconPreset | null>(null)
  const [activeView, setActiveView] = useState<'builtin' | 'user'>('builtin')

  // --- My Presets state ---
  const [userPresets, setUserPresets] = useState<PresetListItem[]>([])
  const [isLoadingPresets, setIsLoadingPresets] = useState(false)
  const [defaults, setDefaults] = useState<Record<string, unknown> | null>(null)
  const [loadingPresetId, setLoadingPresetId] = useState<string | null>(null)
  const [deletingPresetId, setDeletingPresetId] = useState<string | null>(null)

  // --- Generate modal ---
  const [isGenerateModalOpen, setIsGenerateModalOpen] = useState(false)

  // Fetch user presets when switching to "user" view
  useEffect(() => {
    if (!isOpen || activeView !== 'user' || !userId) return

    setIsLoadingPresets(true)
    Promise.all([
      fetch(`/api/presets?userId=${userId}`).then((r) => (r.ok ? r.json() : [])),
      defaults
        ? Promise.resolve(defaults)
        : fetch('/api/projects/defaults').then((r) => (r.ok ? r.json() : {})),
    ])
      .then(([presetList, fetchedDefaults]) => {
        setUserPresets(presetList)
        if (!defaults) setDefaults(fetchedDefaults)
      })
      .catch(() => toast.error('Failed to load presets'))
      .finally(() => setIsLoadingPresets(false))
  }, [isOpen, activeView, userId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Close on Escape
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (isGenerateModalOpen) return // let GeneratePresetModal handle it
        if (detailPreset) {
          setDetailPreset(null)
        } else {
          onClose()
        }
      }
    },
    [detailPreset, onClose, isGenerateModalOpen],
  )

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

  // --- User preset actions ---
  const handleLoadUserPreset = async (preset: PresetListItem) => {
    setLoadingPresetId(preset.id)
    try {
      const res = await fetch(`/api/presets/${preset.id}`)
      if (!res.ok) throw new Error('Failed to fetch preset')

      const fullPreset = await res.json()
      const presetSettings = fullPreset.settings as Record<string, unknown>

      // Merge: defaults fill missing fields, preset overrides what it has
      const merged = { ...(defaults || {}), ...presetSettings }

      onLoadUserPreset(merged)
      toast.success(`Preset "${preset.name}" loaded`, 'Preset Loaded')
      onClose()
    } catch {
      toast.error('Failed to load preset')
    } finally {
      setLoadingPresetId(null)
    }
  }

  const handleDeleteUserPreset = async (preset: PresetListItem) => {
    if (!confirm(`Delete preset "${preset.name}"?`)) return

    setDeletingPresetId(preset.id)
    try {
      const res = await fetch(`/api/presets/${preset.id}?userId=${userId}`, {
        method: 'DELETE',
      })
      if (!res.ok) throw new Error('Failed to delete preset')

      setUserPresets((prev) => prev.filter((p) => p.id !== preset.id))
      toast.success(`Preset "${preset.name}" deleted`, 'Preset Deleted')
    } catch {
      toast.error('Failed to delete preset')
    } finally {
      setDeletingPresetId(null)
    }
  }

  const handlePresetSaved = () => {
    // Refresh user presets list after a new one is saved
    if (userId) {
      fetch(`/api/presets?userId=${userId}`)
        .then((r) => (r.ok ? r.json() : []))
        .then(setUserPresets)
        .catch(() => {})
    }
  }

  if (!isOpen) return null

  const drawer = (
    <>
      {/* Overlay */}
      <div className={styles.drawerOverlay} />

      {/* Drawer */}
      <div className={styles.drawer} onClick={(e) => e.stopPropagation()}>
        <div className={styles.drawerHeader}>
          <h2 className={styles.drawerTitle}>Recon Presets</h2>
          <button
            type="button"
            className={styles.drawerClose}
            onClick={onClose}
            aria-label="Close drawer"
          >
            <X size={14} />
          </button>
        </div>

        {/* Toggle bar */}
        <div className={styles.toggleBar}>
          <button
            type="button"
            className={`${styles.toggleButton} ${activeView === 'builtin' ? styles.toggleButtonActive : ''}`}
            onClick={() => setActiveView('builtin')}
          >
            Built-in Recon Presets
          </button>
          <button
            type="button"
            className={`${styles.toggleButton} ${activeView === 'user' ? styles.toggleButtonActive : ''}`}
            onClick={() => setActiveView('user')}
          >
            My Recon Presets (AI Generated)
          </button>
        </div>

        {/* Built-in presets view */}
        {activeView === 'builtin' && (
          <div className={styles.drawerBody}>
            {RECON_PRESETS.map((preset) => {
              const isApplied = preset.id === currentPresetId

              return (
                <div
                  key={preset.id}
                  className={`${styles.card} ${isApplied ? styles.cardSelected : ''}`}
                >
                  {preset.image && (
                    <img src={preset.image} alt="" className={styles.cardImage} />
                  )}
                  <div className={styles.cardHeader}>
                    <div className={styles.cardIcon}>
                      <PresetIcon name={preset.icon} />
                    </div>
                    <h3 className={styles.cardTitle}>{preset.name}</h3>
                  </div>

                  <p className={styles.cardDescription}>{preset.shortDescription}</p>

                  <div className={styles.cardActions}>
                    <button
                      type="button"
                      className={styles.showMoreButton}
                      onClick={() => setDetailPreset(preset)}
                    >
                      <Info size={12} />
                      Show more
                    </button>

                    <button
                      type="button"
                      className={`${styles.selectButton} ${isApplied ? styles.selectButtonApplied : ''}`}
                      onClick={() => !isApplied && onSelect(preset)}
                      disabled={isApplied}
                    >
                      {isApplied ? (
                        <>
                          <Check size={12} />
                          Applied
                        </>
                      ) : (
                        'Select'
                      )}
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* My Presets view */}
        {activeView === 'user' && (
          <div className={styles.userBody}>
            {/* Generate with AI button */}
            <button
              type="button"
              className={styles.generateButton}
              onClick={() => setIsGenerateModalOpen(true)}
            >
              <Sparkles size={16} />
              Generate with AI
            </button>

            {isLoadingPresets ? (
              <div className={styles.emptyState}>
                <Loader2 size={20} className={styles.spinner} />
              </div>
            ) : userPresets.length === 0 ? (
              <div className={styles.emptyState}>
                <FolderOpen size={32} className={styles.emptyIcon} />
                <p>No presets yet.</p>
                <p>Generate one with AI or use &quot;Save as Preset&quot; from the form.</p>
              </div>
            ) : (
              <div className={styles.userGrid}>
                {userPresets.map((preset) => (
                  <div key={preset.id} className={styles.userCard}>
                    <h3 className={styles.userCardName}>{preset.name}</h3>
                    {preset.description && (
                      <p className={styles.userCardDescription}>{preset.description}</p>
                    )}
                    <span className={styles.userCardDate}>{formatDate(preset.createdAt)}</span>
                    <div className={styles.cardActions}>
                      <button
                        type="button"
                        className={styles.deleteButton}
                        onClick={() => handleDeleteUserPreset(preset)}
                        disabled={deletingPresetId === preset.id}
                        aria-label="Delete preset"
                      >
                        <Trash2 size={12} />
                      </button>
                      <button
                        type="button"
                        className={styles.selectButton}
                        onClick={() => handleLoadUserPreset(preset)}
                        disabled={loadingPresetId === preset.id}
                      >
                        {loadingPresetId === preset.id ? (
                          <>
                            <Loader2 size={12} className={styles.spinner} />
                            Loading...
                          </>
                        ) : (
                          'Select'
                        )}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Detail modal (centered, scrollable) */}
      {detailPreset && (
        <Modal
          isOpen={true}
          onClose={() => setDetailPreset(null)}
          title={detailPreset.name}
          size="large"
          closeOnOverlayClick={false}
          closeOnEscape={false}
        >
          <div className={styles.detailBody}>
            {renderDescription(detailPreset.fullDescription)}
          </div>
        </Modal>
      )}

      {/* Generate preset modal */}
      <GeneratePresetModal
        isOpen={isGenerateModalOpen}
        onClose={() => setIsGenerateModalOpen(false)}
        onSaved={handlePresetSaved}
        userId={userId}
        model={model}
      />
    </>
  )

  if (typeof document !== 'undefined') {
    return createPortal(drawer, document.body)
  }

  return null
}
