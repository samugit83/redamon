'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { ApiError, toApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import { estimateText, estimateWebsite } from '@/lib/tradecraft/estimate'
import { SECTIONS, SETTINGS, settingDef, type SettingDef } from '@/lib/tradecraft/settingsSpec'
import { tradecraftClient, type IngestionSettingsView, type UserRecipe } from '@/lib/tradecraft/client'
import { draftError, parseDraft, sameValue, type Draft } from './dialog/draft'
import { SectionFields, SettingsSection } from './dialog/SettingsSection'
import { KnownTypesFields } from './dialog/KnownTypesSection'
import { FocusDefaultsFields } from './dialog/FocusDefaultsSection'
import tc from './tradecraft.module.css'
import css from './dialog/dialog.module.css'

/** The sections of Configure ingestion (§3.2), in order (§4.1-§4.8). */
export const DIALOG_SECTIONS = ['fetching', 'detection', 'knownTypes', 'crawl', 'storage', 'summary', 'refreshing', 'focus'] as const
/** Settings whose feature is not built yet: real page titles arrive with phase 6. */
export const HIDDEN_KEYS: ReadonlySet<string> = new Set(['knownTypes.realTitles', 'knownTypes.maxTitleFetches'])
export const APPLIES_TEXT = 'Applies to all your resources the next time each one is added or refreshed.'
const LOAD_FAILED = "Couldn't load your ingestion settings"
const SAVE_FAILED = "Couldn't save your ingestion settings"

/** A setting used only when another one has a given value: [the other key, that value, the words]. */
const USED_WHEN: Readonly<Record<string, [string, string, string]>> = {
  'crawl.ignoreStopUntilPages': ['crawl.onLlmStop', 'ignoreUntil', 'Used only when "When the LLM says stop" is "Ignore until N pages".'],
  'crawl.queryStringsPerPath': ['crawl.queryStrings', 'keepN', 'Used only when "Links with a query string" is "Keep up to N per path".'],
  'knownTypes.preferredLanguage': ['knownTypes.language', 'preferred', 'Used only when Language is "Preferred language".'],
}

type Status =
  | { kind: 'loading' }
  | { kind: 'ready' }
  | { kind: 'error'; text: string }
  | { kind: 'denied'; text: string }
  | { kind: 'off' }

/** The account-level settings of each section, in spec order. */
const SECTION_KEYS: Readonly<Record<string, string[]>> = Object.fromEntries(DIALOG_SECTIONS.map(sec => [
  sec,
  SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource' && s.section === sec && !HIDDEN_KEYS.has(s.key)).map(s => s.key),
]))
const DIALOG_KEYS: readonly string[] = Object.values(SECTION_KEYS).flat()

function sectionDefs(section: string): SettingDef[] {
  return SECTION_KEYS[section].map(k => settingDef(k)!)
}

/**
 * Configure ingestion (§3.2): every account-level ingestion setting of the spec, one section
 * per stage, each field with its default, its range and a changed marker, a reset per section
 * and for all, the live estimate, inline validation and the server's refusal on its field.
 * Resets change the draft only: nothing is written before Save.
 */
export function ConfigureIngestionDialog({ userId, onClose, onSaved, onDirtyChange }: {
  userId: string
  onClose: () => void
  onSaved: (view: IngestionSettingsView) => void
  onDirtyChange?: (dirty: boolean) => void
}) {
  const [status, setStatus] = useState<Status>({ kind: 'loading' })
  const [view, setView] = useState<IngestionSettingsView | null>(null)
  const [recipes, setRecipes] = useState<UserRecipe[]>([])
  const [draft, setDraft] = useState<Draft>({})
  const [section, setSection] = useState<string>(DIALOG_SECTIONS[0])
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({})
  const [saveError, setSaveError] = useState('')
  const [saving, setSaving] = useState(false)
  const { isDirty, setBaseline } = useDirtyState(draft)
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const adopt = useCallback((next: IngestionSettingsView) => {
    const values: Draft = Object.fromEntries(DIALOG_KEYS.filter(k => k in next.values).map(k => [k, next.values[k]]))
    setView(next)
    setDraft(values)
    setBaseline(values)
  }, [setBaseline])

  const load = useCallback(async () => {
    setStatus({ kind: 'loading' })
    try {
      const res = await tradecraftClient.getSettings(userId)
      if (!res.v2Enabled || !res.ingestion) return setStatus({ kind: 'off' })
      adopt(res.ingestion)
      setRecipes(res.recipes ?? [])
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
    for (const [k, raw] of Object.entries(draft)) {
      const msg = draftError(settingDef(k)!, raw)
      if (msg) out[k] = msg
    }
    return out
  }, [draft])
  const errors = useMemo(() => ({ ...serverErrors, ...localErrors }), [serverErrors, localErrors])

  const parsedValues = useMemo(() => {
    const out: Record<string, unknown> = { ...(view?.values ?? {}) }
    for (const [k, raw] of Object.entries(draft)) if (!localErrors[k]) out[k] = parseDraft(settingDef(k)!, raw)
    return out
  }, [draft, view, localErrors])
  const estimate = estimateText(estimateWebsite(parsedValues))

  const change = (key: string, value: unknown) => {
    setDraft(prev => ({ ...prev, [key]: value }))
    setServerErrors(prev => { if (!(key in prev)) return prev; const next = { ...prev }; delete next[key]; return next })
  }

  const resetKeys = (keys: string[]) => {
    setDraft(prev => {
      const next = { ...prev }
      for (const k of keys) if (k in next) next[k] = view!.defaults[k]
      return next
    })
    setServerErrors({})
  }

  const save = async () => {
    if (!view) return
    const changed: Record<string, unknown> = {}
    for (const [k, raw] of Object.entries(draft)) {
      const value = parseDraft(settingDef(k)!, raw)
      if (!sameValue(value, view.values[k])) changed[k] = value
    }
    setSaving(true)
    setSaveError('')
    try {
      const res = await tradecraftClient.saveSettings(userId, changed)
      adopt(res.ingestion)
      onSaved(res.ingestion)
    } catch (e) {
      const err = toApiError(e, SAVE_FAILED)
      const list = Array.isArray(err.body?.errors) ? err.body!.errors as { key: string; message: string }[] : []
      const onFields = Object.fromEntries(list.filter(x => x.key in draft).map(x => [x.key, x.message]))
      setServerErrors(onFields)
      const first = Object.keys(onFields)[0]
      if (first) setSection(settingDef(first)!.section)
      else setSaveError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const inactive = (key: string) => {
    const rule = USED_WHEN[key]
    return rule && draft[rule[0]] !== rule[1] ? rule[2] : undefined
  }
  const sectionLabel = (id: string) => SECTIONS.find(s => s.id === id)!.label
  const sectionChanged = (id: string) => SECTION_KEYS[id].some(k => k in draft && !sameValue(parseDraft(settingDef(k)!, draft[k]), view!.defaults[k]))
  const sectionInvalid = (id: string) => SECTION_KEYS[id].some(k => errors[k])
  const hasErrors = Object.keys(errors).length > 0
  const fieldProps = { draft, errors, inactive, userId, onChange: change }

  return (
    <Modal
      isOpen={true}
      onClose={() => guardedNavigate(onClose)}
      title="Configure ingestion"
      size="large"
      closeOnOverlayClick={false}
      footer={status.kind === 'ready' ? (
        <div className={css.footer}>
          <button type="button" className="secondaryButton" onClick={() => resetKeys(Object.keys(draft))} disabled={saving}>Reset to defaults</button>
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
      {status.kind === 'off' && <div className={tc.state} role="alert">Tradecraft 2.0 is off for this account: turn it on to configure ingestion.</div>}
      {status.kind === 'denied' && <div className={tc.state} role="alert">You cannot change these settings: {status.text}.</div>}
      {status.kind === 'error' && (
        <div className={tc.state} role="alert">
          {status.text}.{' '}<button type="button" className="textButton" onClick={load}>Retry</button>
        </div>
      )}
      {status.kind === 'ready' && view && (
        <>
          <div className={css.top}>
            <span>{APPLIES_TEXT}</span>
            <span className={css.estimate} data-testid="ingestion-estimate">{estimate.headline}</span>
            <span>{estimate.stop}</span>
          </div>
          <div className={css.layout}>
            <nav className={css.nav} aria-label="Ingestion stages">
              {DIALOG_SECTIONS.map(id => (
                <button key={id} type="button" className={css.navItem} aria-current={section === id} onClick={() => setSection(id)}>
                  <span>{sectionLabel(id)}</span>
                  {sectionInvalid(id)
                    ? <span className={css.markerError} title="A value is not allowed">!</span>
                    : sectionChanged(id) && <span className={css.marker} title="Changed from the defaults">●</span>}
                </button>
              ))}
            </nav>
            <SettingsSection label={sectionLabel(section)} onReset={() => resetKeys(SECTION_KEYS[section])}>
              {section === 'knownTypes' && <KnownTypesFields defs={sectionDefs(section).filter(d => d.key in draft)} {...fieldProps} />}
              {section === 'focus' && (
                <FocusDefaultsFields defs={sectionDefs(section).filter(d => d.key in draft)} {...fieldProps} recipes={recipes} onRecipes={setRecipes} />
              )}
              {section !== 'knownTypes' && section !== 'focus' && <SectionFields defs={sectionDefs(section).filter(d => d.key in draft)} {...fieldProps} />}
            </SettingsSection>
          </div>
        </>
      )}
    </Modal>
  )
}
