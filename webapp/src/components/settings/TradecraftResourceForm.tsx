'use client'

import { useState, useEffect, useMemo, useId } from 'react'
import { Loader2, Eye, EyeOff, Search } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import { useFeatureModelGate } from '@/components/shared/FeatureModelGate'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { readApiError, toApiError } from '@/lib/apiError'
import styles from './Settings.module.css'
import { ALL_PRESETS, ALPHABETICAL_PRESETS, FEATURED_PRESETS } from '@/lib/tradecraft/presets'
import type { TradecraftPreset } from '@/lib/tradecraft/presets'

export interface TradecraftResource {
  id?: string
  name: string
  slug?: string
  url: string
  enabled?: boolean
  resourceType?: string
  summary?: string
  githubTokenOverride?: string
  cacheTtlSec?: number
  llmModel?: string
  lastVerifiedAt?: string | null
  lastRefreshedAt?: string | null
  lastError?: string
}

const PRESET_GROUP_LABEL = {
  padding: '4px 8px', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em',
  color: 'var(--text-secondary)',
} as const

const SECTION_PICKER_PROMPT =
  'Optional. This model picks which page of a long resource the agent reads; without one, '
  + 'pages are picked by text match. Cancel saves the resource either way.'

// Asked at most once per page load: the section picker is optional, and a
// person who declined it should not be asked again on every save.
let sectionPickerDeclined = false

export function TradecraftResourceForm({
  userId,
  resource,
  onSave,
  onCancel,
  onDirtyChange,
}: {
  userId: string
  resource: TradecraftResource | null
  onSave: () => void
  onCancel: () => void
  /** Reports unsaved-changes state to the parent (drives the tab-switch guard). */
  onDirtyChange?: (dirty: boolean) => void
}) {
  const isEdit = !!resource?.id
  const [name, setName] = useState(resource?.name || '')
  const [url, setUrl] = useState(resource?.url || '')
  const [githubToken, setGithubToken] = useState(resource?.githubTokenOverride || '')
  const [cacheTtl, setCacheTtl] = useState<number>(resource?.cacheTtlSec ?? 0)
  const [enabled, setEnabled] = useState(resource?.enabled ?? true)
  const [llmModel, setLlmModel] = useState(resource?.llmModel || '')
  const [showToken, setShowToken] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [presetSearch, setPresetSearch] = useState('')
  // The actions live in the modal's fixed footer, outside the <form>.
  const formId = useId()
  const { ensureFeatureModel } = useFeatureModelGate()

  // Dirty tracking over the editable fields. Baseline captured from `resource`
  // in the reset effect below (empty for add, resource values for edit).
  const currentValues = useMemo(
    () => ({ name, url, githubToken, cacheTtl, enabled, llmModel }),
    [name, url, githubToken, cacheTtl, enabled, llmModel],
  )
  const { isDirty, setBaseline } = useDirtyState(currentValues)
  // Local-only: the parent /settings page owns the global sidebar/beforeunload
  // guard via onDirtyChange (avoids a duplicate confirm).
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const [filteredFeatured, filteredPresets] = useMemo(() => {
    const q = presetSearch.trim().toLowerCase()
    const matches = (p: TradecraftPreset) => !q
      || p.name.toLowerCase().includes(q)
      || p.description.toLowerCase().includes(q)
      || p.type.toLowerCase().includes(q)
    return [FEATURED_PRESETS.filter(matches), ALPHABETICAL_PRESETS.filter(matches)]
  }, [presetSearch])

  useEffect(() => {
    const next = {
      name: resource?.name || '',
      url: resource?.url || '',
      githubToken: resource?.githubTokenOverride || '',
      cacheTtl: resource?.cacheTtlSec ?? 0,
      enabled: resource?.enabled ?? true,
      llmModel: resource?.llmModel || '',
    }
    setName(next.name)
    setUrl(next.url)
    setGithubToken(next.githubToken)
    setCacheTtl(next.cacheTtl)
    setEnabled(next.enabled)
    setLlmModel(next.llmModel)
    // Adopt these loaded values as the dirty baseline (add = empty, edit = resource).
    setBaseline(next)
  }, [resource, setBaseline])

  const handleQuickAdd = (preset: TradecraftPreset) => {
    setName(preset.name)
    setUrl(preset.url)
  }

  const renderPreset = (p: TradecraftPreset) => (
    <div
      key={p.key}
      style={{
        display: 'grid',
        gridTemplateColumns: '160px 100px 1fr',
        gap: '8px',
        alignItems: 'center',
        padding: '6px 8px',
        borderRadius: '4px',
        cursor: 'pointer',
      }}
      onClick={() => handleQuickAdd(p)}
      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover, rgba(0,0,0,0.04))')}
      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
    >
      <button
        type="button"
        className="secondaryButton"
        style={{
          padding: '4px 8px',
          fontSize: '12px',
          width: '100%',
          textAlign: 'left',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
        }}
        onClick={(e) => { e.stopPropagation(); handleQuickAdd(p) }}
        title={`Add ${p.name} (${p.url})`}
      >
        {p.name}
      </button>
      <span style={{
        fontSize: '10px',
        color: 'var(--text-secondary)',
        padding: '2px 6px',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        textAlign: 'center',
        fontFamily: 'monospace',
        whiteSpace: 'nowrap',
      }}>
        {p.type}
      </span>
      <span style={{
        fontSize: '11px',
        color: 'var(--text-secondary)',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }} title={p.description}>
        {p.description}
      </span>
    </div>
  )

  const submit = async () => {
    if (!name.trim() || !url.trim()) {
      setError('Name and URL are required')
      return
    }
    if (!llmModel.trim()) {
      setError('Pick an LLM model. The resource only becomes usable once a model is selected.')
      return
    }
    // The section picker is the user's own model, separate from this
    // resource's. Its answer does not gate the save.
    if (!sectionPickerDeclined) {
      const picked = await ensureFeatureModel('tradecraft_section_picker', { message: SECTION_PICKER_PROMPT })
      if (!picked) sectionPickerDeclined = true
    }
    setSubmitting(true)
    setError('')
    try {
      const body: Record<string, unknown> = {
        name: name.trim(),
        url: url.trim(),
        enabled,
        cacheTtlSec: Number(cacheTtl) || 0,
        llmModel: llmModel.trim(),
      }
      // Type is always auto-detected at verify time; no manual override.
      // Only send the token override when the user typed something real
      // (not the masked placeholder, not empty for an existing resource).
      if (githubToken && !githubToken.startsWith('••••')) {
        body.githubTokenOverride = githubToken
      }
      const path = isEdit
        ? `/api/users/${userId}/tradecraft-resources/${resource!.id}`
        : `/api/users/${userId}/tradecraft-resources`
      const method = isEdit ? 'PUT' : 'POST'
      const resp = await fetch(path, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!resp.ok) throw await readApiError(resp, isEdit ? 'Failed to update the resource' : 'Failed to add the resource')
      setBaseline(currentValues)
      onSave()
    } catch (e: unknown) {
      setError(toApiError(e, isEdit ? 'Failed to update the resource' : 'Failed to add the resource').message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal
      isOpen={true}
      onClose={() => guardedNavigate(onCancel)}
      title={isEdit ? 'Edit Tradecraft Resource' : 'Add Tradecraft Resource'}
      size="default"
      closeOnOverlayClick={false}
      closeOnEscape={true}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onCancel)} disabled={submitting}>
            Cancel
          </button>
          <button type="submit" form={formId} className="primaryButton" disabled={submitting || !isDirty}>
            {submitting && <Loader2 size={14} className={styles.spin} />}
            {isEdit ? 'Save changes' : 'Add Resource'}
          </button>
        </>
      }
    >
      {/*
        Wrapping in a real <form> so submit-on-Enter works and so we can lock
        autoComplete off at the form level. The dummy hidden username
        + readonly password trick blocks Chrome / 1Password from
        offering site-credentials in the GitHub Token field - without it,
        the password manager treats this form as a login page and pollutes
        the token field with a saved password from an unrelated site.
      */}
      <form
        id={formId}
        onSubmit={(e) => { e.preventDefault(); submit() }}
        autoComplete="off"
        style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}
      >
        <input type="text" name="username" autoComplete="username"
               style={{ display: 'none' }} aria-hidden="true" tabIndex={-1} readOnly />
        <input type="password" name="password" autoComplete="new-password"
               style={{ display: 'none' }} aria-hidden="true" tabIndex={-1} readOnly />

        {!isEdit && (
          <div className="formGroup">
            <label className="formLabel" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>
                Quick Add  <span style={{ fontWeight: 400, color: 'var(--text-secondary)', fontSize: '11px' }}>
                  · {filteredFeatured.length + filteredPresets.length} of {ALL_PRESETS.length} resources
                </span>
              </span>
            </label>
            <div style={{ position: 'relative', marginBottom: '6px' }}>
              <Search
                size={12}
                style={{
                  position: 'absolute', left: '8px', top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-secondary)',
                  pointerEvents: 'none',
                }}
              />
              <input
                type="text"
                className="textInput"
                value={presetSearch}
                onChange={e => setPresetSearch(e.target.value)}
                placeholder="search by name, type (e.g. mkdocs-wiki), or description keyword"
                autoComplete="off"
                spellCheck={false}
                style={{ paddingLeft: '26px', fontSize: '12px' }}
                onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setPresetSearch('') } }}
              />
            </div>
            <div
              role="listbox"
              aria-label="Curated tradecraft resources"
              style={{
                maxHeight: '280px',
                overflowY: 'auto',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '4px',
                background: 'var(--bg-secondary, transparent)',
              }}
            >
              {filteredFeatured.length + filteredPresets.length === 0 && (
                <div style={{ padding: '12px', fontSize: '12px', color: 'var(--text-secondary)', textAlign: 'center' }}>
                  No resources match &quot;{presetSearch}&quot;
                </div>
              )}
              {filteredFeatured.length > 0 && (
                <div role="group" aria-label="Featured">
                  <div style={PRESET_GROUP_LABEL}>Featured</div>
                  {filteredFeatured.map(renderPreset)}
                </div>
              )}
              {filteredPresets.length > 0 && (
                <div role="group" aria-label="All resources">
                  {filteredFeatured.length > 0 && <div style={PRESET_GROUP_LABEL}>All resources</div>}
                  {filteredPresets.map(renderPreset)}
                </div>
              )}
            </div>
          </div>
        )}

        <div className="formGroup">
          <label className="formLabel formLabelRequired">Name</label>
          <input
            className="textInput"
            name="tc-resource-name"
            autoComplete="off"
            data-1p-ignore="true"
            data-lpignore="true"
            spellCheck={false}
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="HackTricks"
          />
        </div>

        <div className="formGroup">
          <label className="formLabel formLabelRequired">URL</label>
          <input
            className="textInput"
            type="url"
            name="tc-resource-url"
            autoComplete="off"
            data-1p-ignore="true"
            data-lpignore="true"
            spellCheck={false}
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://book.hacktricks.wiki"
          />
        </div>

        <div className="formGroup">
          <label className="formLabel">GitHub Token Override (optional)</label>
          <div className={styles.secretInputWrapper}>
            <input
              className="textInput"
              type={showToken ? 'text' : 'password'}
              name="tc-resource-gh-token"
              autoComplete="new-password"
              data-1p-ignore="true"
              data-lpignore="true"
              spellCheck={false}
              value={githubToken}
              onChange={e => setGithubToken(e.target.value)}
              placeholder="leave blank to use the user-level GitHub token"
            />
            <button
              type="button"
              className={styles.secretToggle}
              onClick={() => setShowToken(s => !s)}
              tabIndex={-1}
              aria-label="toggle visibility"
            >
              {showToken ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </div>

        <div className="formGroup">
          <label className="formLabel">Cache TTL seconds (0 = type default)</label>
          <input
            className="textInput"
            type="number"
            name="tc-resource-cache-ttl"
            autoComplete="off"
            min={0}
            value={cacheTtl}
            onChange={e => setCacheTtl(Number(e.target.value))}
          />
        </div>

        <div className="formGroup">
          <label className="formLabel formLabelRequired">LLM Model</label>
          <ModelPicker
            userId={userId}
            value={llmModel}
            onChange={setLlmModel}
            placeholder="pick the model used to crawl + summarize this resource"
            filter={excludeLoop}
          />
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'block', marginTop: '4px' }}>
            Required. Used at verify time (crawl decisions + summary) and at agent runtime. The
            resource is unusable until a model is selected. Pick a small/cheap model - this task
            doesn&apos;t need your main reasoning model.
          </span>
        </div>

        <label className={styles.checkboxLabel}>
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
          <span>Enabled (the agent only sees enabled resources)</span>
        </label>

        {error && <div className={styles.testError}>{error}</div>}
      </form>
    </Modal>
  )
}
