'use client'

import { useState, useEffect, useCallback } from 'react'
import { X, Check, Info, Trash2, Loader2, FolderOpen, Sparkles } from 'lucide-react'
import { icons } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { createPortal } from 'react-dom'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { fetchJson, readApiError, toApiError } from '@/lib/apiError'
import { RECON_PRESETS, type ReconPreset } from '@/lib/recon-presets'
import { IP_PRESETS_RELYING_ON_HOSTNAMES, matchesTargetFilter, type TargetFilter } from '@/lib/recon-presets/targeting'
import { ipHostnameModeOf } from '@/lib/scopeGroups'
import { GeneratePresetModal } from './GeneratePresetModal'
import styles from './ReconPresetModal.module.css'
import provenanceStyles from './presetProvenance.module.css'
import {
  PRESET_FILTER_THRESHOLD,
  filterPresetsByName,
  mcpEditedLabel,
  type PresetProvenance,
} from './presetProvenance'

interface PresetListItem extends PresetProvenance {
  id: string
  name: string
  description: string
  createdAt: string
}

interface ReconPresetDrawerProps {
  isOpen: boolean
  onClose: () => void
  /** Confirms, applies and (in edit mode) saves. Settles once that is done or declined. */
  onSelect: (preset: ReconPreset) => Promise<void>
  onLoadUserPreset: (preset: { id: string; name: string }) => Promise<void>
  currentPresetId?: string
  userId: string | null | undefined
  /** The form's own target mode and hostname mode (create mode included). */
  hostnamePolicy?: { ipMode?: boolean | null; ipHostnameMode?: string | null }
}

/**
 * D-17: a preset never sets "Hostnames on target IPs", so a built-in IP preset
 * designed around the names found on the target IPs finds none on an IP-only
 * project. Said where the preset is picked; MCP apply_recon_preset says the same.
 */
export function presetHostnameNote(
  presetId: string, policy: ReconPresetDrawerProps['hostnamePolicy'],
): string | null {
  if (policy?.ipMode !== true || ipHostnameModeOf(policy.ipHostnameMode) !== 'ip_only') return null
  if (!IP_PRESETS_RELYING_ON_HOSTNAMES.has(presetId)) return null
  return 'This preset expects hostnames found on the target IPs, but this project\'s Hostnames on target IPs ' +
    'is "IP only", so none is looked up. A preset never changes that mode: set it on the Target tab.'
}

function HostnameNote({ text }: { text: string }) {
  return (
    <p role="note" data-testid="preset-hostname-note"
       style={{ margin: '6px 0 0', fontSize: 'var(--text-xs)', lineHeight: 1.5, color: 'var(--form-warning)' }}>
      {text}
    </p>
  )
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
  hostnamePolicy,
}: ReconPresetDrawerProps) {
  const toast = useToast()
  const { dangerConfirm } = useAlertModal()
  const [detailPreset, setDetailPreset] = useState<ReconPreset | null>(null)
  const [activeView, setActiveView] = useState<'builtin' | 'user'>('builtin')
  // Filter built-in presets by the kind of target they suit. Answers the common
  // "which preset do I pick for a local/IP test?" question that a flat list hides.
  const [targetFilter, setTargetFilter] = useState<TargetFilter>('all')

  // --- My Presets state ---
  const [userPresets, setUserPresets] = useState<PresetListItem[]>([])
  const [isLoadingPresets, setIsLoadingPresets] = useState(false)
  const [presetsError, setPresetsError] = useState<string | null>(null)
  // The preset (built-in or user) whose load is in progress, confirmation included.
  const [loadingPresetId, setLoadingPresetId] = useState<string | null>(null)
  const [deletingPresetId, setDeletingPresetId] = useState<string | null>(null)
  const [nameFilter, setNameFilter] = useState('')

  // --- Generate modal ---
  const [isGenerateModalOpen, setIsGenerateModalOpen] = useState(false)

  // A failed read says so in place of the list: an empty list would read as "no presets".
  const loadUserPresets = () =>
    fetchJson<PresetListItem[]>(`/api/presets?userId=${userId}`, undefined, 'Failed to load presets')
      .then((list) => {
        setUserPresets(list)
        setPresetsError(null)
      })
      .catch((err) => setPresetsError(toApiError(err, 'Failed to load presets').message))

  // Fetch user presets when switching to "user" view
  useEffect(() => {
    if (!isOpen || activeView !== 'user' || !userId) return

    setIsLoadingPresets(true)
    loadUserPresets().finally(() => setIsLoadingPresets(false))
  }, [isOpen, activeView, userId]) // eslint-disable-line react-hooks/exhaustive-deps

  // Close on Escape
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (isGenerateModalOpen) return // let GeneratePresetModal handle it
        // A load in progress owns the confirmation dialog, whose own Escape
        // cancels it. Closing the drawer too would lose the user's place.
        if (loadingPresetId) return
        if (detailPreset) {
          setDetailPreset(null)
        } else {
          onClose()
        }
      }
    },
    [detailPreset, onClose, isGenerateModalOpen, loadingPresetId],
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

  const runLoad = async (id: string, load: () => Promise<void>) => {
    setLoadingPresetId(id)
    try {
      await load()
    } finally {
      setLoadingPresetId(null)
    }
  }

  // --- User preset actions ---
  const handleDeleteUserPreset = async (preset: PresetListItem) => {
    const confirmed = await dangerConfirm(`Delete preset "${preset.name}"?`, 'Delete Preset', {
      confirmLabel: 'Delete',
    })
    if (!confirmed) return

    setDeletingPresetId(preset.id)
    try {
      const res = await fetch(`/api/presets/${preset.id}?userId=${userId}`, {
        method: 'DELETE',
      })
      if (!res.ok) throw await readApiError(res, 'Failed to delete preset')

      setUserPresets((prev) => prev.filter((p) => p.id !== preset.id))
      toast.success(`Preset "${preset.name}" deleted`, 'Preset Deleted')
    } catch (err) {
      toast.error(toApiError(err, 'Failed to delete preset').message)
    } finally {
      setDeletingPresetId(null)
    }
  }

  const handlePresetSaved = () => {
    if (userId) void loadUserPresets()
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
                  {(() => {
                    const note = presetHostnameNote(preset.id, hostnamePolicy)
                    return note && <HostnameNote text={note} />
                  })()}

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
                      onClick={() => !isApplied && runLoad(preset.id, () => onSelect(preset))}
                      disabled={isApplied || loadingPresetId !== null}
                    >
                      {isApplied ? (
                        <>
                          <Check size={12} />
                          Applied
                        </>
                      ) : loadingPresetId === preset.id ? (
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
            ) : presetsError ? (
              <div className={styles.emptyState} role="alert">
                <p>{presetsError}</p>
              </div>
            ) : userPresets.length === 0 ? (
              <div className={styles.emptyState}>
                <FolderOpen size={32} className={styles.emptyIcon} />
                <p>No presets yet.</p>
                <p>Generate one with AI or use &quot;Save as Preset&quot; from the form.</p>
              </div>
            ) : (
              <>
              {userPresets.length > PRESET_FILTER_THRESHOLD && (
                <input
                  type="search"
                  className={`textInput ${provenanceStyles.filter}`}
                  placeholder="Filter by name"
                  aria-label="Filter presets by name"
                  value={nameFilter}
                  onChange={(e) => setNameFilter(e.target.value)}
                />
              )}
              <div className={styles.userGrid}>
                {filterPresetsByName(userPresets, nameFilter).map((preset) => (
                  <div key={preset.id} className={styles.userCard}>
                    <h3 className={styles.userCardName}>{preset.name}</h3>
                    {mcpEditedLabel(preset) && (
                      <span className={provenanceStyles.mcpBadge}>{mcpEditedLabel(preset)}</span>
                    )}
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
                        onClick={() => runLoad(preset.id, () => onLoadUserPreset({ id: preset.id, name: preset.name }))}
                        disabled={loadingPresetId !== null}
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
              </>
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
            {(() => {
              const note = presetHostnameNote(detailPreset.id, hostnamePolicy)
              return note && <HostnameNote text={note} />
            })()}
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
      />
    </>
  )

  if (typeof document !== 'undefined') {
    return createPortal(drawer, document.body)
  }

  return null
}
