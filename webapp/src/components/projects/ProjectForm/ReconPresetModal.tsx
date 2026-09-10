'use client'

import { useState, useEffect, useCallback } from 'react'
import { X, Check, Info, Trash2, Loader2, FolderOpen, Sparkles } from 'lucide-react'
import { icons } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { createPortal } from 'react-dom'
import { Modal } from '@/components/ui/Modal/Modal'
import { useToast, WikiInfoButton } from '@/components/ui'
import { RECON_PRESETS, type ReconPreset } from '@/lib/recon-presets'
import { matchesTargetFilter, type TargetFilter } from '@/lib/recon-presets/targeting'
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

const TARGET_FILTERS: Array<{ id: TargetFilter; label: string; hint: string }> = [
  { id: 'all', label: 'All', hint: 'Every built-in preset' },
  { id: 'domain', label: 'Domain', hint: 'Presets that scan a public domain / subdomains' },
  { id: 'ip', label: 'External IP', hint: 'Presets that scan public IPs or CIDR ranges' },
  { id: 'internal', label: 'Local network', hint: 'Presets for a private/internal network or Active Directory' },
]

// Small, theme-safe classification chips shown on every preset card so the target
// type is visible at a glance without opening "Show more".
function Chip({ text, tone }: { text: string; tone: 'blue' | 'purple' | 'amber' | 'gray' }) {
  const palette: Record<string, { bg: string; fg: string; border: string }> = {
    blue: { bg: 'rgba(96, 165, 250, 0.14)', fg: '#60a5fa', border: 'rgba(96, 165, 250, 0.4)' },
    purple: { bg: 'rgba(167, 139, 250, 0.14)', fg: '#a78bfa', border: 'rgba(167, 139, 250, 0.4)' },
    amber: { bg: 'rgba(251, 146, 60, 0.14)', fg: '#fb923c', border: 'rgba(251, 146, 60, 0.45)' },
    gray: { bg: 'rgba(148, 163, 184, 0.14)', fg: '#94a3b8', border: 'rgba(148, 163, 184, 0.4)' },
  }
  const c = palette[tone]
  return (
    <span
      style={{
        display: 'inline-block',
        fontSize: '10px',
        fontWeight: 600,
        lineHeight: 1.4,
        padding: '1px 7px',
        borderRadius: '999px',
        background: c.bg,
        color: c.fg,
        border: `1px solid ${c.border}`,
        whiteSpace: 'nowrap',
      }}
    >
      {text}
    </span>
  )
}

function PresetChips({ preset }: { preset: ReconPreset }) {
  const profileChip =
    preset.targetProfile === 'ip'
      ? { text: 'IP / network', tone: 'purple' as const }
      : preset.targetProfile === 'both'
        ? { text: 'Domain or IP', tone: 'gray' as const }
        : { text: 'Domain', tone: 'blue' as const }
  const envChip =
    preset.environment === 'internal'
      ? { text: 'Local network', tone: 'amber' as const }
      : preset.environment === 'external'
        ? { text: 'External', tone: 'gray' as const }
        : null // 'either' adds no signal beyond the profile chip
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginBottom: '6px' }}>
      <Chip text={profileChip.text} tone={profileChip.tone} />
      {envChip && <Chip text={envChip.text} tone={envChip.tone} />}
    </div>
  )
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
  // Filter built-in presets by the kind of target they suit. Answers the common
  // "which preset do I pick for a local/IP test?" question that a flat list hides.
  const [targetFilter, setTargetFilter] = useState<TargetFilter>('all')

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
          <h2 className={styles.drawerTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            Recon Presets
            <WikiInfoButton target="ReconPreset" title="Open Recon Presets wiki page" />
          </h2>
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

        {/* Target-type filter: lets a user narrow to the presets that suit a
            domain, a public IP range, or an internal/local network. */}
        {activeView === 'builtin' && (
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '6px',
              padding: '8px 16px 0',
            }}
          >
            {TARGET_FILTERS.map((f) => {
              const active = targetFilter === f.id
              return (
                <button
                  key={f.id}
                  type="button"
                  title={f.hint}
                  onClick={() => setTargetFilter(f.id)}
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    padding: '4px 12px',
                    borderRadius: '999px',
                    cursor: 'pointer',
                    border: `1px solid ${active ? 'rgba(96, 165, 250, 0.6)' : 'var(--border-subtle, #333)'}`,
                    background: active ? 'rgba(96, 165, 250, 0.16)' : 'transparent',
                    color: active ? '#60a5fa' : 'var(--text-secondary, #aaa)',
                  }}
                >
                  {f.label}
                </button>
              )
            })}
          </div>
        )}

        {/* Built-in presets view */}
        {activeView === 'builtin' && (
          <div className={styles.drawerBody}>
            {RECON_PRESETS.filter((preset) => matchesTargetFilter(preset, targetFilter)).map((preset) => {
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

                  <PresetChips preset={preset} />

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
