'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { ApiError, toApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import { estimateSearch, searchEstimateText } from '@/lib/tradecraft/estimate'
import { SECTIONS, SETTINGS, settingDef } from '@/lib/tradecraft/settingsSpec'
import { tradecraftClient, type ResourceView, type SearchSettingsView, type SynonymPair } from '@/lib/tradecraft/client'
import { draftError, parseDraft, sameValue, type Draft } from './dialog/draft'
import { SectionFields, SettingsSection } from './dialog/SettingsSection'
import { LibrarianModelLine, useLibrarianModel } from './LibrarianModel'
import tc from './tradecraft.module.css'
import css from './dialog/dialog.module.css'

/** The sections of Configure search (Q11), in order. */
export const SEARCH_SECTIONS = ['librarian', 'search', 'reading', 'prompt', 'hints'] as const
export const APPLIES_TEXT = 'Applies from the next message to the agent; nothing is re-ingested.'
export const FETCH_NOTE = 'Downloads use the fetching settings of Configure ingestion.'
const MAX_PAIRS = 200
const LOAD_FAILED = "Couldn't load your search settings"
const SAVE_FAILED = "Couldn't save your search settings"

/** Q11 "Settings that work fully only on Stored resources say so." */
export const STORED_NOTES: Readonly<Record<string, string>> = {
  librarian: 'On Stored resources the librarian checks the stored copy and searches inside it; a Live page is downloaded while it checks it.',
  reading: 'Stored resources are read section by section; a Live page is downloaded at each read.',
}

const USED_WHEN: Readonly<Record<string, [string, unknown, string]>> = {
  'librarian.maxModelCalls': ['librarian.use', 'agent', 'Used only when Librarian use is "Agent decides".'],
  'librarian.maxPages': ['librarian.use', 'agent', 'Used only when Librarian use is "Agent decides".'],
  'librarian.timeLimitSec': ['librarian.use', 'agent', 'Used only when Librarian use is "Agent decides".'],
  'librarian.questionsPerRun': ['librarian.use', 'agent', 'Used only when Librarian use is "Agent decides".'],
  'hints.perRun': ['hints.enabled', true, 'Used only when Hints is on.'],
}

const SECTION_KEYS: Readonly<Record<string, string[]>> = Object.fromEntries(SEARCH_SECTIONS.map(sec => [
  sec, SETTINGS.filter(s => s.scope === 'search' && s.level !== 'resource' && s.section === sec).map(s => s.key),
]))
const DIALOG_KEYS: readonly string[] = Object.values(SECTION_KEYS).flat()

/** One pair per line, `PATT = PayloadsAllTheThings`; blank lines are skipped. */
export function parseSynonymLines(text: string): { pairs: SynonymPair[]; error: string } {
  const pairs: SynonymPair[] = []
  const lines = text.split('\n')
  for (const [i, line] of lines.entries()) {
    if (!line.trim()) continue
    const at = line.indexOf('=')
    const term = at < 0 ? '' : line.slice(0, at).trim()
    const expansion = at < 0 ? '' : line.slice(at + 1).trim()
    if (!term || !expansion) return { pairs, error: `Line ${i + 1}: write a pair as "PATT = PayloadsAllTheThings"` }
    pairs.push({ term, expansion })
  }
  if (pairs.length > MAX_PAIRS) return { pairs, error: `At most ${MAX_PAIRS} pairs (${pairs.length} now)` }
  return { pairs, error: '' }
}

const synonymLines = (pairs: SynonymPair[]) => pairs.map(p => `${p.term} = ${p.expansion}`).join('\n')

type Status = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; text: string } | { kind: 'denied'; text: string } | { kind: 'off' }
type Priority = 'high' | 'normal' | 'low'
interface DialogDraft { values: Draft; synonyms: string; priorities: Record<string, Priority> }

const asPriority = (p: string): Priority => (p === 'high' || p === 'low' ? p : 'normal')

/**
 * Configure search (Q11): the query-side settings, at user level only, one section per table of
 * Q11 with its fields, defaults, ranges and changed markers; the librarian model (the
 * Models-by-feature value, changed through the gate); my synonyms; each resource's priority; the
 * live estimate; Reset to defaults, Cancel, Save. No "Save & refresh all": nothing is re-ingested.
 */
export function ConfigureSearchDialog({ userId, onClose, onSaved, onDirtyChange }: {
  userId: string
  onClose: () => void
  onSaved: () => void
  onDirtyChange?: (dirty: boolean) => void
}) {
  const [status, setStatus] = useState<Status>({ kind: 'loading' })
  const [view, setView] = useState<SearchSettingsView | null>(null)
  const [resources, setResources] = useState<ResourceView[]>([])
  const [draft, setDraft] = useState<DialogDraft>({ values: {}, synonyms: '', priorities: {} })
  const [section, setSection] = useState<string>(SEARCH_SECTIONS[0])
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [saveError, setSaveError] = useState('')
  const [saving, setSaving] = useState(false)
  const librarian = useLibrarianModel(userId)
  const { isDirty, setBaseline } = useDirtyState(draft)
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const adopt = useCallback((next: SearchSettingsView, list: ResourceView[]) => {
    const d: DialogDraft = {
      values: Object.fromEntries(DIALOG_KEYS.filter(k => k in next.values).map(k => [k, next.values[k]])),
      synonyms: synonymLines(next.synonyms),
      priorities: Object.fromEntries(list.map(r => [r.id, asPriority(r.priority)])),
    }
    setView(next)
    setResources(list)
    setDraft(d)
    setBaseline(d)
  }, [setBaseline])

  const load = useCallback(async () => {
    setStatus({ kind: 'loading' })
    try {
      const [res, list] = await Promise.all([tradecraftClient.getSettings(userId), tradecraftClient.list(userId)])
      if (!res.v2Enabled || !res.search) return setStatus({ kind: 'off' })
      adopt(res.search, list)
      setStatus({ kind: 'ready' })
    } catch (e) {
      if (e instanceof ApiError && e.code === 'tradecraft_v2_off') return setStatus({ kind: 'off' })
      const denied = e instanceof ApiError && (e.status === 401 || e.status === 403)
      setStatus({ kind: denied ? 'denied' : 'error', text: failureText(LOAD_FAILED, e) })
    }
  }, [userId, adopt])
  useEffect(() => { load() }, [load])

  const localErrors = useMemo(() => {
    const out: Record<string, string> = {}
    for (const [k, raw] of Object.entries(draft.values)) {
      const msg = draftError(settingDef(k)!, raw)
      if (msg) out[k] = msg
    }
    const syn = parseSynonymLines(draft.synonyms)
    if (syn.error) out.synonyms = syn.error
    return out
  }, [draft])
  const errors = useMemo(() => ({ ...serverErrors, ...localErrors }), [serverErrors, localErrors])
  const parsedValues = useMemo(() => {
    const out: Record<string, unknown> = { ...(view?.values ?? {}) }
    for (const [k, raw] of Object.entries(draft.values)) if (!localErrors[k]) out[k] = parseDraft(settingDef(k)!, raw)
    return out
  }, [draft, view, localErrors])
  const estimate = searchEstimateText(estimateSearch(parsedValues))

  const change = (key: string, value: unknown) => {
    setDraft(prev => ({ ...prev, values: { ...prev.values, [key]: value } }))
    setServerErrors(prev => { if (!(key in prev)) return prev; const next = { ...prev }; delete next[key]; return next })
  }
  const resetKeys = (keys: string[]) => setDraft(prev => {
    const values = { ...prev.values }
    for (const k of keys) if (k in values) values[k] = view!.defaults[k]
    return { ...prev, values }
  })
  const resetAll = () => {
    resetKeys(DIALOG_KEYS as string[])
    setDraft(prev => ({ ...prev, priorities: Object.fromEntries(resources.map(r => [r.id, 'normal' as Priority])) }))
    setServerErrors({})
  }

  const save = async () => {
    if (!view) return
    const changed: Record<string, unknown> = {}
    for (const [k, raw] of Object.entries(draft.values)) {
      const value = parseDraft(settingDef(k)!, raw)
      if (!sameValue(value, view.values[k])) changed[k] = value
    }
    const pairs = parseSynonymLines(draft.synonyms).pairs
    if (!sameValue(pairs, view.synonyms)) changed.synonyms = pairs
    const moved = resources.filter(r => draft.priorities[r.id] !== asPriority(r.priority))
    setSaving(true)
    setSaveError('')
    try {
      let next = view
      if (Object.keys(changed).length > 0) next = (await tradecraftClient.saveSearch(userId, changed)).search
      // A priority is a field of its resource (Q11 "for each resource"), saved on it.
      for (const r of moved) await tradecraftClient.update(userId, r.id, { priority: draft.priorities[r.id] })
      adopt(next, resources.map(r => ({ ...r, priority: draft.priorities[r.id] ?? r.priority })))
      onSaved()
    } catch (e) {
      const err = toApiError(e, SAVE_FAILED)
      const list = Array.isArray(err.body?.errors) ? err.body!.errors as { key: string; message: string }[] : []
      const onFields = Object.fromEntries(list.filter(x => x.key in draft.values || x.key === 'synonyms').map(x => [x.key, x.message]))
      setServerErrors(onFields)
      const first = Object.keys(onFields)[0]
      if (first) setSection(first === 'synonyms' ? 'search' : settingDef(first)!.section)
      else setSaveError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const inactive = (key: string) => {
    const rule = USED_WHEN[key]
    return rule && draft.values[rule[0]] !== rule[1] ? rule[2] : undefined
  }
  const sectionLabel = (id: string) => SECTIONS.find(s => s.id === id)!.label
  const sectionChanged = (id: string) => SECTION_KEYS[id].some(k => k in draft.values && !sameValue(parseDraft(settingDef(k)!, draft.values[k]), view!.defaults[k]))
  const sectionInvalid = (id: string) => SECTION_KEYS[id].some(k => errors[k]) || (id === 'search' && !!errors.synonyms)
  const hasErrors = Object.keys(errors).length > 0
  const fieldProps = { draft: draft.values, errors, inactive, userId, onChange: change }
  const defs = SECTION_KEYS[section].filter(k => k in draft.values).map(k => settingDef(k)!)

  return (
    <Modal
      isOpen={true}
      onClose={() => guardedNavigate(onClose)}
      title="Configure search"
      size="large"
      closeOnOverlayClick={false}
      footer={status.kind === 'ready' ? (
        <div className={css.footer}>
          <button type="button" className="secondaryButton" onClick={resetAll} disabled={saving}>Reset to defaults</button>
          {saveError && <span className={tc.failure} role="alert">{saveError}</span>}
          <span className={css.footerSpacer} />
          <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onClose)} disabled={saving}>Cancel</button>
          <button type="button" className="primaryButton" onClick={save} disabled={saving || !isDirty || hasErrors}>
            {saving && <Loader2 size={14} className={tc.spin} />} Save
          </button>
        </div>
      ) : (
        <button type="button" className="secondaryButton" onClick={onClose}>Close</button>
      )}
    >
      {status.kind === 'loading' && <div className={tc.state}>Loading your settings…</div>}
      {status.kind === 'off' && <div className={tc.state} role="alert">Tradecraft 2.0 is off for this account: turn it on to configure search.</div>}
      {status.kind === 'denied' && <div className={tc.state} role="alert">You cannot change these settings: {status.text}.</div>}
      {status.kind === 'error' && (
        <div className={tc.state} role="alert">
          {status.text}.{' '}<button type="button" className="textButton" onClick={load}>Retry</button>
        </div>
      )}
      {status.kind === 'ready' && view && (
        <>
          <div className={css.top}>
            <span>{APPLIES_TEXT} {FETCH_NOTE}</span>
            <span className={css.estimate} data-testid="search-estimate">{estimate}</span>
          </div>
          <div className={css.layout}>
            <nav className={css.nav} aria-label="Search settings">
              {SEARCH_SECTIONS.map(id => (
                <button key={id} type="button" className={css.navItem} aria-current={section === id} onClick={() => setSection(id)}>
                  <span>{sectionLabel(id)}</span>
                  {sectionInvalid(id)
                    ? <span className={css.markerError} title="A value is not allowed">!</span>
                    : sectionChanged(id) && <span className={css.marker} title="Changed from the defaults">●</span>}
                </button>
              ))}
            </nav>
            <SettingsSection label={sectionLabel(section)} onReset={() => resetKeys(SECTION_KEYS[section])}>
              {section === 'librarian' && <LibrarianModelLine state={librarian.state} onChoose={librarian.choose} />}
              <SectionFields defs={defs} {...fieldProps} />
              {section === 'search' && (
                <>
                  <div className={css.field} data-setting="synonyms">
                    <div className={css.fieldHead}><label htmlFor="tc-synonyms">My synonyms</label></div>
                    <textarea
                      id="tc-synonyms" className="textarea" rows={4} value={draft.synonyms} placeholder="PATT = PayloadsAllTheThings"
                      onChange={e => {
                        const synonyms = e.target.value
                        setDraft(prev => ({ ...prev, synonyms }))
                        setServerErrors(prev => { if (!('synonyms' in prev)) return prev; const next = { ...prev }; delete next.synonyms; return next })
                      }}
                    />
                    <div className={css.fieldMeta}>Your own pairs, one per line; each works both ways. Up to {MAX_PAIRS} pairs.</div>
                    {errors.synonyms && <div className={css.fieldError} role="alert">{errors.synonyms}</div>}
                  </div>
                  <div className={css.field} data-setting="priority">
                    <div className={css.fieldHead}><span>Resource priority</span></div>
                    {resources.length === 0 && <div className={css.fieldMeta}>No resources yet.</div>}
                    {resources.map(r => (
                      <label key={r.id} className={css.inline}>
                        <select
                          aria-label={`Priority of ${r.name}`} value={draft.priorities[r.id] ?? 'normal'}
                          onChange={e => {
                            const p = e.target.value as Priority
                            setDraft(prev => ({ ...prev, priorities: { ...prev.priorities, [r.id]: p } }))
                          }}
                        >
                          <option value="high">High</option>
                          <option value="normal">Normal</option>
                          <option value="low">Low</option>
                        </select>
                        <span>{r.name}</span>
                      </label>
                    ))}
                    <div className={css.fieldMeta}>Ranks one resource&apos;s pages higher or lower. Default: Normal.</div>
                  </div>
                </>
              )}
              {STORED_NOTES[section] && <div className={css.fieldMeta} role="note">{STORED_NOTES[section]}</div>}
            </SettingsSection>
          </div>
        </>
      )}
    </Modal>
  )
}
