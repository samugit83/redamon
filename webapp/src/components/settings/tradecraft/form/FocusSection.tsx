'use client'

import { useEffect, useId, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { toApiError } from '@/lib/apiError'
import type { PreviewResult } from '@/lib/tradecraft/agentContract'
import { tradecraftClient, type FocusPreviewInput, type UserRecipe } from '@/lib/tradecraft/client'
import {
  FOCUS_TEXT_MAX, RECIPE_NAME_MAX, applyRecipe, clampFocusText, focusCost, focusCostText, focusPayload, previewSummary,
  setChips, userSkillIdOf, userSkillTopic, type Focus, type FocusMode, type FocusStrictness,
} from '@/lib/tradecraft/focus'
import { KINDS, RECIPES, TOPICS } from '@/lib/tradecraft/vocab'
import { FormSection } from './FormSection'
import css from '../tradecraft.module.css'
import fcss from './form.module.css'

/** Tag only suits wikis and repositories (§6.14 "Focused or Tag only"): one ingestion serves every focus. */
export const TAG_ONLY_NOTE = 'Tag only drops nothing: every page is tagged from the full lists, and content checks add a one-line description.'
const MODE_LABELS: Readonly<Record<FocusMode, string>> = { everything: 'Everything', focused: 'Focused', tagOnly: 'Tag only' }
const MODE_HINTS: Readonly<Record<FocusMode, string>> = {
  everything: 'No filtering: every page the site lists is kept, as before.',
  focused: 'Pages outside the focus are dropped (they stay visible in the Map view, with the reason).',
  tagOnly: 'Nothing is dropped; every page is tagged.',
}
const STRICTNESS: readonly [FocusStrictness, string, string][] = [
  ['loose', 'Loose', 'keep anything related'],
  ['balanced', 'Balanced', 'keep clear and likely matches'],
  ['strict', 'Strict', 'keep only clear matches'],
]

/** What the preview samples: the saved resource's map, or the entries Check URL found; null before either. */
export type FocusPreviewSource =
  | { resourceId: string; llmModel?: string }
  | { entries: { url: string; title: string }[]; llmModel: string }
  | null

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? '' : 's'}`

/** The section header's one-line status (§6.2). */
export function focusStatus(f: Focus): string {
  if (f.mode === 'everything') return MODE_LABELS.everything
  const parts = [
    ...(f.topics.length ? [plural(f.topics.length, 'topic')] : []),
    ...(f.kinds.length ? [plural(f.kinds.length, 'content type')] : []),
  ]
  return parts.length ? `${MODE_LABELS[f.mode]}: ${parts.join(', ')}` : MODE_LABELS[f.mode]
}

interface FocusSectionProps {
  userId: string
  focus: Focus
  onChange: (next: Focus) => void
  /** The forced or detected type: a CVE archive has no page list to focus. */
  siteType: string
  /** The account's "Always skip" (§4.8), which the Skip text adds to or replaces. */
  alwaysSkip: string
  /** The resource's effective limit on content checks, for the cost line. */
  maxContentChecks: number
  /** How many entries the map holds (Check URL's index or the saved map); null while unknown. */
  entryCount: number | null
  preview: FocusPreviewSource
}

/**
 * The Focus section of the resource form (§6.14): what a resource keeps. The chips write Keep
 * (until the person edits it), recipes fill the chips, Preview runs the title triage on 100
 * entries and saves nothing. Hidden for a CVE archive, whose lookups go straight to a CVE id.
 */
export function FocusSection(props: FocusSectionProps) {
  if (props.siteType === 'cve-poc-db') return null
  return (
    <FormSection title="Focus" status={focusStatus(props.focus)}>
      <FocusBody {...props} />
    </FormSection>
  )
}

function FocusBody({ userId, focus, onChange, alwaysSkip, maxContentChecks, entryCount, preview }: FocusSectionProps) {
  const id = useId()
  const [recipes, setRecipes] = useState<UserRecipe[]>([])
  const [skills, setSkills] = useState<{ id: string; name: string }[] | null>(null)
  const [result, setResult] = useState<PreviewResult | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [recipeName, setRecipeName] = useState('')
  const [savingRecipe, setSavingRecipe] = useState(false)
  const [error, setError] = useState('')

  // The owner's recipes and skills are read when the section opens; without them the built-in
  // recipes and the fixed topics still work.
  useEffect(() => {
    let live = true
    tradecraftClient.getSettings(userId).then(r => { if (live) setRecipes(r.recipes ?? []) }).catch(() => undefined)
    tradecraftClient.ownSkills(userId).then(s => { if (live) setSkills(Array.isArray(s) ? s.map(x => ({ id: x.id, name: x.name })) : []) }).catch(() => { if (live) setSkills([]) })
    return () => { live = false }
  }, [userId])

  const skillNames = Object.fromEntries((skills ?? []).map(s => [s.id, s.name]))
  // A topic of a skill the owner deleted since: shown, so it can be turned off (the save leaves it out anyway).
  const staleSkills = skills === null ? [] : focus.topics.flatMap(t => {
    const id = userSkillIdOf(t)
    return id && !Object.hasOwn(skillNames, id) ? [{ topic: t, id }] : []
  })
  const change = (next: Focus) => {
    setResult(null)
    onChange(next)
  }
  const toggle = (list: string[], item: string) => (list.includes(item) ? list.filter(x => x !== item) : [...list, item])
  const toggleTopic = (topic: string) => change(setChips(focus, { topics: toggle(focus.topics, topic) }, skillNames))
  const toggleKind = (kind: string) => change(setChips(focus, { kinds: toggle(focus.kinds, kind) }, skillNames))

  const runPreview = async () => {
    if (!preview) return
    setPreviewing(true)
    setError('')
    try {
      const input = { ...preview, focus: focusPayload(focus) } as FocusPreviewInput
      setResult((await tradecraftClient.previewFocus(userId, input)).result)
    } catch (e) {
      setResult(null)
      setError(toApiError(e, 'The focus preview failed').message)
    } finally {
      setPreviewing(false)
    }
  }

  const saveRecipe = async () => {
    setSavingRecipe(true)
    setError('')
    try {
      const res = await tradecraftClient.editRecipes(userId, { add: { name: recipeName.trim(), topics: focus.topics, kinds: focus.kinds } })
      setRecipes(res.recipes)
      setRecipeName('')
    } catch (e) {
      setError(toApiError(e, "Couldn't save the recipe").message)
    } finally {
      setSavingRecipe(false)
    }
  }

  return (
    <>
      <fieldset className={fcss.choiceGroup} aria-label="Focus mode">
        <legend className="formLabel">Mode</legend>
        <div className={fcss.choices}>
          {(['everything', 'focused', 'tagOnly'] as const).map(mode => (
            <label key={mode} className={fcss.choice}>
              <input
                type="radio" className="radio" name={`${id}-mode`} value={mode} checked={focus.mode === mode}
                aria-label={MODE_LABELS[mode]} onChange={() => change({ ...focus, mode })}
              />
              <span className={fcss.choiceBody}>
                <span className={fcss.choiceTitle}>{MODE_LABELS[mode]}</span>
                <span className={fcss.choiceDesc}>{MODE_HINTS[mode]}</span>
              </span>
            </label>
          ))}
        </div>
        {focus.mode === 'tagOnly' && <span className={`formHint ${fcss.groupNote}`}>{TAG_ONLY_NOTE}</span>}
      </fieldset>

      {focus.mode !== 'everything' && (
        <>
          <div className="formGroup">
            <span className="formLabel">Recipes</span>
            <div className={fcss.chips}>
              {RECIPES.map(r => (
                <button key={r.id} type="button" className={fcss.chip} aria-pressed={focus.recipe === r.id}
                  onClick={() => change(applyRecipe(focus, r, skillNames))}>{r.label}</button>
              ))}
              {recipes.map(r => (
                <button key={r.id} type="button" className={fcss.chip} aria-pressed={focus.recipe === r.id}
                  onClick={() => change(applyRecipe(focus, r, skillNames))}>{r.name}</button>
              ))}
            </div>
          </div>
          <div className="formGroup">
            <span className="formLabel">Topics</span>
            <div className={fcss.chips} role="group" aria-label="Topics">
              {TOPICS.map(t => (
                <button key={t.id} type="button" className={fcss.chip} aria-pressed={focus.topics.includes(t.id)} onClick={() => toggleTopic(t.id)}>{t.label}</button>
              ))}
              {(skills ?? []).map(s => (
                <button key={s.id} type="button" className={fcss.chip} aria-pressed={focus.topics.includes(userSkillTopic(s.id))}
                  onClick={() => toggleTopic(userSkillTopic(s.id))}>{s.name}</button>
              ))}
              {staleSkills.map(s => (
                <button key={s.topic} type="button" className={fcss.chip} aria-pressed={true} title="This skill was deleted: turn it off"
                  onClick={() => toggleTopic(s.topic)}>{`Deleted skill (${s.id})`}</button>
              ))}
            </div>
          </div>
          <div className="formGroup">
            <span className="formLabel">Content type</span>
            <div className={fcss.chips} role="group" aria-label="Content type">
              {KINDS.map(k => (
                <button key={k.id} type="button" className={fcss.chip} aria-pressed={focus.kinds.includes(k.id)} onClick={() => toggleKind(k.id)}>{k.label}</button>
              ))}
            </div>
          </div>
          <div className="formGroup">
            <label className="formLabel" htmlFor={`${id}-keep`}>Keep</label>
            <textarea id={`${id}-keep`} className="textarea" rows={2} value={focus.keep}
              onChange={e => change({ ...focus, keep: clampFocusText(e.target.value) })} placeholder="written by the chips; edit it freely" />
            <span className="formHint">{`${focus.keep.length} / ${FOCUS_TEXT_MAX}`}</span>
          </div>
          <div className="formGroup">
            <label className="formLabel" htmlFor={`${id}-skip`}>Skip</label>
            <textarea id={`${id}-skip`} className="textarea" rows={2} value={focus.skip}
              onChange={e => change({ ...focus, skip: clampFocusText(e.target.value) })} placeholder="for example: theory without payloads, news" />
            <span className="formHint">{`${focus.skip.length} / ${FOCUS_TEXT_MAX}`}</span>
            <select aria-label="Skip mode" className="select" value={focus.skipMode}
              onChange={e => change({ ...focus, skipMode: e.target.value === 'replace' ? 'replace' : 'add' })}>
              <option value="add">Add to my Always skip</option>
              <option value="replace">Replace my Always skip</option>
            </select>
            {alwaysSkip && <span className="formHint">{`Your Always skip: ${alwaysSkip}`}</span>}
          </div>
          <fieldset className={fcss.choiceGroup} aria-label="Strictness">
            <legend className="formLabel">Strictness</legend>
            <div className={fcss.choices}>
              {STRICTNESS.map(([value, label, hint]) => (
                <label key={value} className={fcss.choice}>
                  <input type="radio" className="radio" name={`${id}-strictness`} value={value} checked={focus.strictness === value} aria-label={label}
                    onChange={() => change({ ...focus, strictness: value })} />
                  <span className={fcss.choiceBody}>
                    <span className={fcss.choiceTitle}>{label}</span>
                    <span className={fcss.choiceDesc}>{hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          <div className="formGroup">
            <div className={fcss.row}>
              <button type="button" className="secondaryButton" onClick={runPreview} disabled={!preview || previewing}>
                {previewing && <Loader2 size={14} className={css.spin} />} Preview on 100 pages
              </button>
              <span className="formHint">{focusCostText(focusCost({ mode: focus.mode, entries: entryCount, maxContentChecks }))}</span>
            </div>
            {!preview && <span className="formHint">Run Check URL first: the preview samples the page list it finds.</span>}
            {result && (
              <div role="status" className={fcss.previewBox}>
                <span>{previewSummary(result)}</span>
                <ul className={fcss.previewList} aria-label="Preview examples">
                  {result.examples.map(x => (
                    <li key={x.url}>{`${x.title || x.url} — ${x.decision}${x.reason ? `: ${x.reason}` : ''}`}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className={fcss.inputRow}>
            <input aria-label="Recipe name" className="textInput" maxLength={RECIPE_NAME_MAX} value={recipeName}
              onChange={e => setRecipeName(e.target.value)} placeholder="name these chips to reuse them" />
            <button type="button" className="secondaryButton" onClick={saveRecipe}
              disabled={savingRecipe || !recipeName.trim() || (focus.topics.length === 0 && focus.kinds.length === 0)}>Save as recipe</button>
          </div>
          {error && <div className={fcss.checkFailed} role="alert">{error}</div>}
        </>
      )}
    </>
  )
}
