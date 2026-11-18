'use client'

import { useCallback, useEffect, useId, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { excludeLoop } from '@/lib/agentInTheLoop'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { toApiError } from '@/lib/apiError'
import type { CheckUrlResult } from '@/lib/tradecraft/agentContract'
import {
  tradecraftClient, type IngestionSettingsView, type ResourceInput, type ResourceView, type SavedResource,
} from '@/lib/tradecraft/client'
import { focusFromStored, focusPayload, newResourceFocus, type Focus } from '@/lib/tradecraft/focus'
import { presetSettings, type TradecraftPreset } from '@/lib/tradecraft/presets'
import { isValidValue, settingDef, specDefaults, type SettingValue } from '@/lib/tradecraft/settingsSpec'
import { slugify } from '@/lib/tradecraft/slug'
import { defaultStorageMode, forcedStorageMode } from '@/lib/tradecraft/storageModes'
import { draftError, parseDraft } from '../dialog/draft'
import { useEnabledImpactConfirm } from '../EnabledImpactAlert'
import { AccessSection, accessDraftOf, accessError, credentialsPayload, type AccessDraft } from './AccessSection'
import { useLibrarianGate } from '../LibrarianModel'
import { MapView } from '../MapView'
import { CheckUrlButton } from './CheckUrlButton'
import { ContentSection } from './ContentSection'
import { CveSection } from './CveSection'
import { DocsSection } from './DocsSection'
import { FetchingSection } from './FetchingSection'
import { FocusSection, type FocusPreviewSource } from './FocusSection'
import { GithubSection } from './GithubSection'
import type { FormContext } from './OverrideList'
import { PdfSection } from './PdfSection'
import { PresetPicker } from './PresetPicker'
import { RefreshingSection } from './RefreshingSection'
import { SiteTypeSection } from './SiteTypeSection'
import { SummarySection } from './SummarySection'
import { WebsiteSection } from './WebsiteSection'
import { WikiSection } from './WikiSection'
import { typeSectionOf } from './sections'
import css from '../tradecraft.module.css'
import fcss from './form.module.css'

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
  slug: string
  forcedType: string
  presetKey: string
}

interface Draft {
  fields: Fields
  overrides: Record<string, unknown>
  focus: Focus
  /** The GitHub token override and the site login (§6.6). */
  access: AccessDraft
}

const PREVIEW_TITLE_MAX = 300

type ListOverride = { mode: string; items?: unknown[]; text?: unknown }

/** The inline error of one override as the form holds it, or ''. */
export function overrideError(key: string, raw: unknown): string {
  const def = settingDef(key)
  if (!def) return 'Not a setting'
  if (def.listMode) {
    const o = raw as ListOverride
    const inner = def.type === 'list' ? (o?.items ?? []).map(x => String(x).trim()).filter(Boolean) : o?.text
    return isValidValue(def, inner) ? '' : `Must be ${def.type === 'list' ? `at most ${def.maxItems} items` : `at most ${def.maxLength} characters`}`
  }
  return draftError(def, raw)
}

/** The overrides as the server takes them: numbers parsed, list items trimmed. */
export function overridesPayload(overrides: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, raw] of Object.entries(overrides)) {
    const def = settingDef(key)
    if (!def) continue
    if (def.listMode && def.type === 'list') {
      const o = raw as ListOverride
      out[key] = { mode: o.mode, items: (o.items ?? []).map(x => String(x).trim()).filter(Boolean) }
    } else if (def.listMode) {
      out[key] = { mode: (raw as ListOverride).mode, text: (raw as ListOverride).text }
    } else {
      out[key] = parseDraft(def, raw)
    }
  }
  return out
}

/**
 * Pre-fills from Check URL what the type's fields would otherwise leave to a guess (§6.3): the CVE
 * pattern it found, when none is set. Branches, folders and sitemaps are offered as suggestions.
 */
export function prefillFromCheck(result: CheckUrlResult, overrides: Record<string, unknown>): Record<string, unknown> {
  if (!result.ok) return overrides
  const next = { ...overrides }
  if (result.cve_pattern && !Object.hasOwn(next, 'type.cve.pathPatterns')) next['type.cve.pathPatterns'] = [result.cve_pattern]
  return next
}

/**
 * The Add / Edit Resource form (§6.2): the basics always visible (Quick add, Name, Resource ID,
 * URL with Check URL, model, Enabled, storage with its recommendation), then one collapsed section
 * per stage with its status, the type's own section only for its type. `settings` is the account's
 * ingestion settings (the inherited values, the default model and storage); without them the
 * spec's defaults show.
 */
export function ResourceFormV2({ userId, resource, settings = null, onSaved, onCancel, onDirtyChange }: {
  userId: string
  resource: ResourceView | null
  settings?: IngestionSettingsView | null
  onSaved: (saved: SavedResource) => void
  onCancel: () => void
  onDirtyChange?: (dirty: boolean) => void
}) {
  const isEdit = !!resource
  const formId = useId()
  const accountValues = useMemo<Record<string, SettingValue>>(() => settings?.values ?? specDefaults('ingestion'), [settings])
  const initial = useMemo<Draft>(() => {
    const forcedType = resource?.forcedType ?? ''
    return {
      fields: {
        name: resource?.name ?? '',
        url: resource?.url ?? '',
        llmModel: resource?.llmModel ?? (typeof accountValues['summary.defaultModel'] === 'string' ? accountValues['summary.defaultModel'] as string : ''),
        enabled: resource?.enabled ?? true,
        storageMode: resource
          ? (resource.storageMode === 'stored' ? 'stored' : 'live')
          : defaultStorageMode(accountValues['storage.defaultMode'], forcedType),
        slug: resource?.slug ?? '',
        forcedType,
        presetKey: '',
      },
      overrides: structuredClone(resource?.overrides ?? {}),
      // A saved resource keeps its focus (none is Everything); a new one starts on the account's defaults (§4.8).
      focus: resource ? focusFromStored(resource.focus) : newResourceFocus(accountValues),
      access: accessDraftOf(resource?.credentials),
    }
  }, [resource, accountValues])
  const [draft, setDraft] = useState<Draft>(initial)
  const [slugEdited, setSlugEdited] = useState(false)
  const [storageTouched, setStorageTouched] = useState(false)
  const [check, setCheck] = useState<CheckUrlResult | null>(null)
  const [checkRun, setCheckRun] = useState(0)
  const [current, setCurrent] = useState<ResourceView | null>(resource)
  const [submitting, setSubmitting] = useState(false)
  const [mapOpen, setMapOpen] = useState(false)
  const [error, setError] = useState('')
  const confirmEnabled = useEnabledImpactConfirm(userId)
  const librarianGate = useLibrarianGate()
  const { isDirty, setBaseline } = useDirtyState(draft)
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { setDraft(initial); setBaseline(initial) }, [initial, setBaseline])
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])
  useEffect(() => { setCurrent(resource) }, [resource])

  const f = draft.fields
  const set = <K extends keyof Fields>(key: K, value: Fields[K]) => setDraft(prev => ({ ...prev, fields: { ...prev.fields, [key]: value } }))
  const setOverride = useCallback((key: string, value: unknown) => setDraft(prev => {
    const overrides = { ...prev.overrides }
    if (value === undefined) delete overrides[key]
    else overrides[key] = value
    return { ...prev, overrides }
  }), [])
  const urlChanged = isEdit && f.url.trim() !== resource!.url
  const detectedType = check?.ok ? check.detected_type : (resource?.resourceType ?? '')
  const effectiveType = f.forcedType || detectedType
  const forcedMode = forcedStorageMode(f.forcedType || (check?.ok ? check.detected_type : ''))
  const storageMode = forcedMode ?? f.storageMode
  const errors = useMemo(() => {
    const out: Record<string, string> = {}
    for (const [k, raw] of Object.entries(draft.overrides)) {
      const msg = overrideError(k, raw)
      if (msg) out[k] = msg
    }
    return out
  }, [draft.overrides])
  const ctx: FormContext = { userId, inherited: accountValues, overrides: draft.overrides, setOverride, errors }

  const onName = (name: string) => setDraft(prev => ({
    ...prev,
    fields: { ...prev.fields, name, ...(!isEdit && !slugEdited ? { slug: name.trim() ? slugify(name) : '' } : {}) },
  }))
  const onUrl = (url: string) => {
    set('url', url)
    setCheck(null)
  }
  const onPreset = (preset: TradecraftPreset) => {
    const carried = presetSettings(preset)
    setDraft(prev => ({
      fields: {
        ...prev.fields, name: preset.name, url: preset.url, presetKey: preset.key, forcedType: carried.forcedType ?? '',
        ...(!slugEdited ? { slug: slugify(preset.name) } : {}),
      },
      overrides: carried.overrides ?? {},
      focus: prev.focus,
      access: prev.access,
    }))
    setCheck(null)
    // §6.3: Check URL runs by itself when a preset is picked.
    setCheckRun(n => n + 1)
  }
  const onCheck = (result: CheckUrlResult | null) => {
    setCheck(result)
    if (!result?.ok) return
    setDraft(prev => {
      const fields = { ...prev.fields }
      if (!isEdit && !storageTouched && accountValues['storage.defaultMode'] === 'recommended') fields.storageMode = result.recommended_storage
      return { ...prev, fields, overrides: prefillFromCheck(result, prev.overrides) }
    })
  }

  const token = draft.access.githubToken.trim()
  const credentials = credentialsPayload(initial.access, draft.access)
  // Check URL reads with the login being typed; a saved resource's stored one is the route's.
  const checkAccess = {
    ...(token ? { githubTokenOverride: token } : {}),
    ...(credentials !== undefined && !accessError(draft.access) ? { credentials } : {}),
  }
  const checkInput = isEdit && !urlChanged
    ? { resourceId: resource!.id, forcedType: f.forcedType, overrides: overridesPayload(draft.overrides), ...checkAccess }
    : { url: f.url.trim(), forcedType: f.forcedType, overrides: overridesPayload(draft.overrides), ...checkAccess }

  const submit = async (reingest: boolean) => {
    if (!f.name.trim() || !f.url.trim()) return setError('Name and URL are required')
    if (!f.llmModel.trim()) return setError('Pick the model that ingests this resource')
    if (Object.keys(errors).length > 0) return setError('Some settings are out of range: see the marked fields')
    const loginError = accessError(draft.access)
    if (loginError) return setError(`Access: ${loginError}`)
    // Enabled is the global switch: every project follows, after the alert (§3.4, R-140).
    if (isEdit && f.enabled !== resource!.enabled && !(await confirmEnabled(resource!, f.enabled))) return
    setSubmitting(true)
    setError('')
    const overrides = overridesPayload(draft.overrides)
    // A CVE archive has no page list to focus: its hidden section sends no focus.
    const focus = effectiveType === 'cve-poc-db' ? {} : focusPayload(draft.focus)
    const input: ResourceInput = {
      name: f.name.trim(), url: f.url.trim(), llmModel: f.llmModel.trim(), enabled: f.enabled, storageMode,
      ...(token ? { githubTokenOverride: token } : {}),
      ...(credentials !== undefined && (isEdit || credentials !== null) ? { credentials } : {}),
      ...(isEdit
        ? { forcedType: f.forcedType, overrides, focus }
        : {
            ...(Object.keys(focus).length ? { focus } : {}),
            ...(slugEdited && f.slug ? { slug: f.slug } : {}),
            ...(f.forcedType ? { forcedType: f.forcedType } : {}),
            ...(Object.keys(overrides).length ? { overrides } : {}),
            ...(f.presetKey ? { presetKey: f.presetKey } : {}),
          }),
    }
    try {
      const saved = isEdit
        ? await tradecraftClient.update(userId, resource!.id, input, librarianGate)
        : await tradecraftClient.create(userId, input, librarianGate)
      setBaseline(draft)
      // A new URL is ingested by the save itself; otherwise Save & re-ingest asks for a refresh.
      if (isEdit && reingest && !urlChanged) {
        const { job } = await tradecraftClient.refresh(userId, resource!.id)
        return onSaved({ ...saved, job })
      }
      onSaved(saved)
    } catch (e) {
      setError(toApiError(e, isEdit ? "Couldn't save the resource" : "Couldn't add the resource").message)
    } finally {
      setSubmitting(false)
    }
  }

  const typeSection = typeSectionOf(effectiveType)
  // The answer reaches the browser unparsed: a field the agent left out is missing, not defaulted.
  const indexCount = check?.ok && typeof check.index?.count === 'number' ? check.index.count : null
  const entryCount = indexCount ?? (isEdit && !urlChanged ? resource!.entryCount : null)
  const sample = check?.ok && Array.isArray(check.sample_entries) ? check.sample_entries : []
  // The preview samples the saved map, else the entries Check URL found; the form's model judges them.
  let focusPreview: FocusPreviewSource = null
  if (isEdit && !urlChanged && resource!.entryCount > 0) {
    focusPreview = { resourceId: resource!.id, ...(f.llmModel.trim() ? { llmModel: f.llmModel.trim() } : {}) }
  } else if (sample.length > 0 && f.llmModel.trim()) {
    focusPreview = { entries: sample.map(e => ({ url: e.url, title: (e.title ?? '').slice(0, PREVIEW_TITLE_MAX) })), llmModel: f.llmModel.trim() }
  }
  const maxContentChecks = Number(draft.overrides['focus.maxContentChecks'] ?? accountValues['focus.maxContentChecks']) || 0
  const sitemapFound = check?.ok && check.index?.kind === 'sitemap' && check.index.url ? check.index.url : null
  const docsIndexFound = check?.ok && check.index?.kind === 'searchindex' && check.index.url ? check.index.url : null
  const busy = submitting

  return (
    <Modal
      isOpen={true}
      onClose={() => guardedNavigate(onCancel)}
      title={isEdit ? 'Edit Tradecraft Resource' : 'Add Tradecraft Resource'}
      size="large"
      closeOnOverlayClick={false}
      footer={
        <>
          <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onCancel)} disabled={busy}>Cancel</button>
          {isEdit && !urlChanged && (
            <button type="submit" form={formId} className="secondaryButton" disabled={busy || !isDirty}>
              {busy && <Loader2 size={14} className={css.spin} />} Save
            </button>
          )}
          {isEdit ? (
            <button type="button" className="primaryButton" disabled={busy} onClick={() => submit(true)}>
              {busy && <Loader2 size={14} className={css.spin} />} Save &amp; re-ingest
            </button>
          ) : (
            <button type="submit" form={formId} className="primaryButton" disabled={busy}>
              {busy && <Loader2 size={14} className={css.spin} />} Add &amp; ingest
            </button>
          )}
        </>
      }
    >
      <form id={formId} className={fcss.form} onSubmit={e => { e.preventDefault(); submit(false) }} autoComplete="off">
        {!isEdit && <PresetPicker onPick={onPreset} />}
        <div className={fcss.twoCol}>
          <div className="formGroup">
            <label className="formLabel formLabelRequired" htmlFor={`${formId}-name`}>Name</label>
            <input id={`${formId}-name`} className="textInput" value={f.name} onChange={e => onName(e.target.value)} placeholder="HackTricks" />
          </div>
          <div className="formGroup">
            <label className="formLabel" htmlFor={`${formId}-slug`}>Resource ID</label>
            {isEdit ? (
              <input id={`${formId}-slug`} className="textInput" value={f.slug} readOnly aria-readonly="true" />
            ) : (
              <input
                id={`${formId}-slug`} className="textInput" value={f.slug} placeholder="made from the name"
                onChange={e => { setSlugEdited(true); set('slug', e.target.value.toLowerCase()) }}
              />
            )}
            <span className="formHint">
              {isEdit ? 'The agent names the resource and its pages with it: it cannot change.' : 'Lowercase letters, digits and dashes; it cannot change once added.'}
            </span>
          </div>
        </div>
        <div className="formGroup">
          <label className="formLabel formLabelRequired" htmlFor={`${formId}-url`}>URL</label>
          <CheckUrlButton
            userId={userId} input={checkInput} disabled={!f.url.trim()} runToken={checkRun} onResult={onCheck}
            field={<input id={`${formId}-url`} className="textInput" value={f.url} onChange={e => onUrl(e.target.value)} placeholder="https://book.hacktricks.wiki" />}
          />
          {urlChanged && <span className="formHint">Saving a new URL ingests the resource again.</span>}
          {/* §6.10: the Map view opens from the card or from this form, on the saved map. */}
          {isEdit && (
            <div>
              <button type="button" className="secondaryButton" onClick={() => setMapOpen(true)}>Map of the saved pages</button>
            </div>
          )}
        </div>
        <div className="formGroup">
          <label className="formLabel formLabelRequired">LLM model</label>
          <ModelPicker userId={userId} value={f.llmModel} onChange={v => set('llmModel', v)} placeholder="pick the model that ingests this resource" filter={excludeLoop} />
          <span className="formHint">{MODEL_HELP}</span>
        </div>
        <fieldset className={fcss.choiceGroup} aria-label="Content storage">
          <legend className="formLabel">Content storage</legend>
          <div className={fcss.choices}>
            <label className={fcss.choice}>
              <input
                type="radio" className="radio" name={`${formId}-storage`} value="live" checked={storageMode === 'live'} disabled={!!forcedMode}
                onChange={() => { setStorageTouched(true); set('storageMode', 'live') }}
              />
              <span className={fcss.choiceBody}>
                <span className={fcss.choiceTitle}>Live</span>
                <span className={fcss.choiceDesc}>{LIVE_NOTE}</span>
              </span>
            </label>
            <label className={fcss.choice}>
              <input
                type="radio" className="radio" name={`${formId}-storage`} value="stored" checked={storageMode === 'stored'} disabled={!!forcedMode}
                onChange={() => { setStorageTouched(true); set('storageMode', 'stored') }}
              />
              <span className={fcss.choiceBody}>
                <span className={fcss.choiceTitle}>Stored</span>
                <span className={fcss.choiceDesc}>{STORED_WHY} {STORED_NOTE}</span>
              </span>
            </label>
          </div>
          {forcedMode && <span className={`formHint ${fcss.groupNote}`}>{forcedMode === 'stored' ? 'A PDF is always Stored.' : 'A CVE archive is always Live.'}</span>}
          {!forcedMode && check?.ok && (
            <span className={`formHint ${fcss.groupNote}`}>{check.recommended_storage === 'stored' ? 'Stored' : 'Live'} recommended for this site.</span>
          )}
          {isEdit && resource!.storageMode === 'stored' && storageMode === 'live' && (
            <span className={`formHint ${fcss.groupNote}`} role="note">Saving deletes the stored pages now.</span>
          )}
        </fieldset>
        <label className={fcss.checkLine}>
          <input type="checkbox" className="checkbox" checked={f.enabled} onChange={e => set('enabled', e.target.checked)} />
          <span>Enabled <span className={fcss.muted}>(the agent sees enabled resources only)</span></span>
        </label>

        <div className={fcss.sections}>
          <SiteTypeSection ctx={ctx} forcedType={f.forcedType} detectedType={detectedType} onForcedType={t => set('forcedType', t)} />
          <FocusSection
            userId={userId} focus={draft.focus} onChange={focus => setDraft(prev => ({ ...prev, focus }))} siteType={effectiveType}
            alwaysSkip={typeof accountValues['focus.alwaysSkip'] === 'string' ? accountValues['focus.alwaysSkip'] as string : ''}
            maxContentChecks={maxContentChecks} entryCount={entryCount} preview={focusPreview}
          />
          {typeSection === 'github' && <GithubSection ctx={ctx} github={check?.ok ? check.github : null} />}
          {typeSection === 'cve' && <CveSection ctx={ctx} foundPattern={check?.ok ? check.cve_pattern : null} />}
          {(typeSection === 'wiki' || typeSection === 'gitbook') && <WikiSection ctx={ctx} variant={typeSection} sitemapFound={sitemapFound} />}
          {typeSection === 'docs' && <DocsSection ctx={ctx} indexFound={docsIndexFound} />}
          {typeSection === 'pdf' && <PdfSection ctx={ctx} pages={check?.ok ? check.pdf_pages : null} />}
          {typeSection === 'website' && <WebsiteSection ctx={ctx} sitemapFound={sitemapFound} />}
          {!typeSection && <span className="formHint">Pick a type, or run Check URL, to see the options of the site&apos;s type.</span>}
          <AccessSection
            draft={draft.access} onChange={access => setDraft(prev => ({ ...prev, access }))}
            tokenSet={resource?.githubTokenOverride === 'set'}
          />
          <FetchingSection ctx={ctx} hasLogin={credentials === undefined ? (resource?.hasLogin ?? false) : credentials !== null} />
          <ContentSection ctx={ctx} />
          <SummarySection ctx={ctx} resource={current} onResource={setCurrent} onJob={() => undefined} />
          <RefreshingSection ctx={ctx} />
        </div>
        {error && <div className={fcss.checkFailed} role="alert">{error}</div>}
      </form>
      {mapOpen && resource && <MapView userId={userId} resource={resource} onClose={() => setMapOpen(false)} />}
    </Modal>
  )
}
