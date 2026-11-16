'use client'

import { useEffect, useId, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { toApiError } from '@/lib/apiError'
import { tradecraftClient, type ResourceInput, type ResourceView, type SavedResource } from '@/lib/tradecraft/client'
import css from '../tradecraft.module.css'

/** R-198: the model ingests; the agent's run uses its own model. */
export const MODEL_HELP = 'Used to ingest this resource: crawl decisions, page triage and the summary. It is not used while the agent runs.'
/** §4.5 "What Live costs without a cache". */
export const LIVE_NOTE = 'Read from the site at every read, nothing kept: a read takes seconds, and the resource cannot answer while its site is down.'
/** OQ-23's default wording (manual checkpoint MC-2 is pending for the owner's text). */
export const STORED_NOTE = "Stored keeps a copy of each page in your RedAmon database. Respect the site's terms of use."
const STORED_WHY = 'Reads take milliseconds and keep working when the site is down or the network has no internet.'

interface Fields {
  name: string
  url: string
  llmModel: string
  enabled: boolean
  storageMode: 'live' | 'stored'
  githubToken: string
}

/** The basic 2.0 resource form (§6.4): Name, URL, model, Enabled, Live or Stored, GitHub token. No cache lifetime. */
export function ResourceFormV2({ userId, resource, onSaved, onCancel, onDirtyChange }: {
  userId: string
  resource: ResourceView | null
  onSaved: (saved: SavedResource) => void
  onCancel: () => void
  onDirtyChange?: (dirty: boolean) => void
}) {
  const isEdit = !!resource
  const formId = useId()
  const initial = useMemo<Fields>(() => ({
    name: resource?.name ?? '',
    url: resource?.url ?? '',
    llmModel: resource?.llmModel ?? '',
    enabled: resource?.enabled ?? true,
    storageMode: resource?.storageMode === 'stored' ? 'stored' : 'live',
    githubToken: '',
  }), [resource])
  const [f, setF] = useState<Fields>(initial)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const { isDirty, setBaseline } = useDirtyState(f)
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { setF(initial); setBaseline(initial) }, [initial, setBaseline])
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const set = <K extends keyof Fields>(key: K, value: Fields[K]) => setF(prev => ({ ...prev, [key]: value }))
  const urlChanged = isEdit && f.url.trim() !== resource!.url

  const submit = async () => {
    if (!f.name.trim() || !f.url.trim()) return setError('Name and URL are required')
    if (!f.llmModel.trim()) return setError('Pick the model that ingests this resource')
    setSubmitting(true)
    setError('')
    const input: ResourceInput = {
      name: f.name.trim(), url: f.url.trim(), llmModel: f.llmModel.trim(), enabled: f.enabled, storageMode: f.storageMode,
      ...(f.githubToken.trim() ? { githubTokenOverride: f.githubToken.trim() } : {}),
    }
    try {
      const saved = isEdit ? await tradecraftClient.update(userId, resource!.id, input) : await tradecraftClient.create(userId, input)
      setBaseline(f)
      onSaved(saved)
    } catch (e) {
      setError(toApiError(e, isEdit ? "Couldn't save the resource" : "Couldn't add the resource").message)
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
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onCancel)} disabled={submitting}>Cancel</button>
          <button type="submit" form={formId} className="primaryButton" disabled={submitting || (isEdit && !isDirty)}>
            {submitting && <Loader2 size={14} className={css.spin} />}
            {isEdit ? (urlChanged ? 'Save & re-ingest' : 'Save changes') : 'Add & ingest'}
          </button>
        </>
      }
    >
      <form id={formId} onSubmit={e => { e.preventDefault(); submit() }} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        <div className="formGroup">
          <label className="formLabel formLabelRequired" htmlFor={`${formId}-name`}>Name</label>
          <input id={`${formId}-name`} className="textInput" value={f.name} onChange={e => set('name', e.target.value)} placeholder="HackTricks" />
        </div>
        <div className="formGroup">
          <label className="formLabel formLabelRequired" htmlFor={`${formId}-url`}>URL</label>
          <input id={`${formId}-url`} className="textInput" value={f.url} onChange={e => set('url', e.target.value)} placeholder="https://book.hacktricks.wiki" />
          {urlChanged && <span className={css.hint}>Saving a new URL ingests the resource again.</span>}
        </div>
        <div className="formGroup">
          <label className="formLabel formLabelRequired">LLM model</label>
          <ModelPicker userId={userId} value={f.llmModel} onChange={v => set('llmModel', v)} placeholder="pick the model that ingests this resource" filter={excludeLoop} />
          <span className={css.hint}>{MODEL_HELP}</span>
        </div>
        <fieldset className={css.storageChoice} aria-label="Content storage">
          <legend className="formLabel">Content storage</legend>
          <label className={css.storageOption}>
            <input type="radio" name={`${formId}-storage`} value="live" checked={f.storageMode === 'live'} onChange={() => set('storageMode', 'live')} />
            <span><strong>Live</strong>. <span className={css.hint}>{LIVE_NOTE}</span></span>
          </label>
          <label className={css.storageOption}>
            <input type="radio" name={`${formId}-storage`} value="stored" checked={f.storageMode === 'stored'} onChange={() => set('storageMode', 'stored')} />
            <span><strong>Stored</strong>. <span className={css.hint}>{STORED_WHY} {STORED_NOTE}</span></span>
          </label>
          {isEdit && resource!.storageMode === 'stored' && f.storageMode === 'live' && (
            <span className={css.hint} role="note">Saving deletes the stored pages now.</span>
          )}
        </fieldset>
        <div className="formGroup">
          <label className="formLabel" htmlFor={`${formId}-token`}>GitHub token override</label>
          <input
            id={`${formId}-token`} className="textInput" type="password" autoComplete="new-password" value={f.githubToken}
            onChange={e => set('githubToken', e.target.value)}
            placeholder={resource?.githubTokenOverride === 'set' ? 'A token is set: type a new one to replace it' : 'optional: ghp_…'}
          />
        </div>
        <label className={css.storageOption}>
          <input type="checkbox" checked={f.enabled} onChange={e => set('enabled', e.target.checked)} />
          <span>Enabled (the agent sees enabled resources only)</span>
        </label>
        {error && <div className={css.failure} role="alert">{error}</div>}
      </form>
    </Modal>
  )
}
