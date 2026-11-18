'use client'

import { useId, useState } from 'react'
import { toApiError } from '@/lib/apiError'
import { tradecraftClient, type UserRecipe } from '@/lib/tradecraft/client'
import { RECIPE_NAME_MAX, topicLabel } from '@/lib/tradecraft/focus'
import type { SettingDef } from '@/lib/tradecraft/settingsSpec'
import { KINDS } from '@/lib/tradecraft/vocab'
import { SectionFields, type SectionFieldsProps } from './SettingsSection'
import { formatValue, parseDraft, sameValue } from './draft'
import { VALUE_LABELS } from './SettingField'
import tc from '../tradecraft.module.css'
import css from './dialog.module.css'

const KIND_LABEL: Readonly<Record<string, string>> = Object.fromEntries(KINDS.map(k => [k.id, k.label]))

/** A recipe's chips in one line: its topics, then its content types. */
export function recipeChips(r: UserRecipe): string {
  return [r.topics.map(t => topicLabel(t)).join(', '), r.kinds.map(k => KIND_LABEL[k] ?? k).join(', ')].filter(Boolean).join(' · ')
}

/**
 * The Ingestion focus section of Configure ingestion (§4.8): the defaults a new resource's Focus
 * starts from, saved with the dialog, and the account's own recipes, renamed or deleted at once
 * (a recipe is saved from a resource's Focus section).
 */
export function FocusDefaultsFields({ recipes, onRecipes, ...fields }: SectionFieldsProps & {
  recipes: UserRecipe[]
  onRecipes: (recipes: UserRecipe[]) => void
}) {
  const modeDef = fields.defs.find(d => d.key === 'focus.defaultMode')
  return (
    <>
      {modeDef && (
        <DefaultModeField def={modeDef} value={fields.draft[modeDef.key]} error={fields.errors[modeDef.key]} onChange={v => fields.onChange(modeDef.key, v)} />
      )}
      <SectionFields {...fields} defs={fields.defs.filter(d => d !== modeDef)} />
      <MyRecipes userId={fields.userId} recipes={recipes} onRecipes={onRecipes} />
    </>
  )
}

/** The default mode as radios, each with its words. */
function DefaultModeField({ def, value, error, onChange }: { def: SettingDef; value: unknown; error?: string; onChange: (v: unknown) => void }) {
  const id = useId()
  const labels = VALUE_LABELS[def.key]
  const changed = !sameValue(parseDraft(def, value), def.default)
  return (
    <div className={css.field} data-setting={def.key}>
      <div className={css.fieldHead}>
        <span id={id}>{def.label}</span>
        {changed && <span className={css.changed} title="Changed from the default">● changed</span>}
      </div>
      <div className={css.choiceRow} role="radiogroup" aria-labelledby={id}>
        {def.values!.map(v => (
          <label key={v} className={css.check}>
            <input type="radio" className="radio" name={id} value={v} checked={value === v} aria-label={labels[v]} onChange={() => onChange(v)} />
            <span>{labels[v]}</span>
          </label>
        ))}
      </div>
      <div className={css.fieldMeta}>{def.help} Default: {formatValue(def, def.default, labels)}.</div>
      {error && <div className={css.fieldError} role="alert">{error}</div>}
    </div>
  )
}

function MyRecipes({ userId, recipes, onRecipes }: { userId: string; recipes: UserRecipe[]; onRecipes: (r: UserRecipe[]) => void }) {
  const [renaming, setRenaming] = useState<string | null>(null)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const edit = async (change: Parameters<typeof tradecraftClient.editRecipes>[1], failed: string) => {
    setBusy(true)
    setError('')
    try {
      onRecipes((await tradecraftClient.editRecipes(userId, change)).recipes)
      setRenaming(null)
    } catch (e) {
      setError(toApiError(e, failed).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={css.field}>
      <div className={css.fieldHead}><span>My focus recipes</span></div>
      {recipes.length === 0 ? (
        <div className={css.fieldMeta}>No recipe yet. Save one from a resource&apos;s Focus section (Save as recipe); at most 50.</div>
      ) : (
        <ul aria-label="My recipes" className={css.list}>
          {recipes.map(r => (
            <li key={r.id} className={css.listRow}>
              {renaming === r.id ? (
                <>
                  <input aria-label={`New name of ${r.name}`} className={`textInput ${css.listGrow}`} maxLength={RECIPE_NAME_MAX} value={name} onChange={e => setName(e.target.value)} />
                  <button type="button" className="secondaryButton" disabled={busy || !name.trim()}
                    onClick={() => edit({ rename: { id: r.id, name: name.trim() } }, "Couldn't rename the recipe")}>Save name</button>
                  <button type="button" className="textButton" onClick={() => setRenaming(null)}>Cancel</button>
                </>
              ) : (
                <>
                  <span className={css.listGrow}><strong>{r.name}</strong> <span className={css.fieldMeta}>{recipeChips(r)}</span></span>
                  <button type="button" className="textButton" disabled={busy} onClick={() => { setRenaming(r.id); setName(r.name) }}>Rename</button>
                  <button type="button" className="textButton" disabled={busy} onClick={() => edit({ delete: r.id }, "Couldn't delete the recipe")}>Delete</button>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {error && <div className={tc.failure} role="alert">{error}</div>}
    </div>
  )
}
