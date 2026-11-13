'use client'

import { useId } from 'react'
import {
  SHARE_PRESETS,
  SHARE_TOGGLES,
  presetById,
  type SharePresetId,
  type ShareTerms,
} from './sharePresets'
import styles from './ShareDialog.module.css'

/** What the picker holds: a preset, and Custom's own Raw data choice (kept apart from the presets'). */
export interface AccessChoice {
  presetId: SharePresetId
  customRaw: boolean
}

/** The terms a choice grants. Phase 4's Custom is Read with the Raw data toggle. */
export function termsOf(choice: AccessChoice): ShareTerms {
  const preset = presetById(choice.presetId)
  if (preset.terms) return preset.terms
  return { access: 'read', rawData: choice.customRaw, runScans: false, useAgent: false, exploit: false, manage: false }
}

interface AccessPickerProps {
  value: AccessChoice
  onChange: (next: AccessChoice) => void
  /** Why the Read + Write presets and toggles are offered disabled (sharePresets.writePresetsRefusal). */
  writeRefusal: string | null
  disabled?: boolean
}

/**
 * The share dialog's level picker (step 4.12, SH-05): the Read presets as radios, Custom's Raw data
 * toggle, and the Read + Write presets and toggles with their warnings (HD-22, SH-29), disabled with
 * the reason while write sharing cannot be granted. Used by the grant form and each share's editor.
 */
export function AccessPicker({ value, onChange, writeRefusal, disabled = false }: AccessPickerProps) {
  const id = useId()
  const radioName = `${id}-preset`
  const writeDisabled = disabled || writeRefusal !== null
  const raw = SHARE_TOGGLES.find(t => t.id === 'rawData')!

  const presetRadio = (presetId: SharePresetId, off: boolean) => {
    const preset = presetById(presetId)
    return (
      <label key={preset.id} className={styles.choice}>
        <input
          type="radio"
          name={radioName}
          value={preset.id}
          checked={value.presetId === preset.id}
          onChange={() => onChange({ ...value, presetId: preset.id })}
          disabled={off}
        />
        <span className={styles.choiceName}>{preset.label}</span>
        <span className={styles.choiceHint}>{preset.summary}</span>
      </label>
    )
  }

  return (
    <div className={styles.picker}>
      <div role="radiogroup" aria-labelledby={`${id}-access`} className={styles.choices}>
        <span id={`${id}-access`} className={styles.label}>Access</span>
        {SHARE_PRESETS.filter(p => p.level === 'read').map(p => presetRadio(p.id, disabled))}
      </div>
      {value.presetId === 'custom' && (
        <label className={styles.choice}>
          <input
            type="checkbox"
            checked={value.customRaw}
            onChange={(e) => onChange({ ...value, customRaw: e.target.checked })}
            disabled={disabled}
          />
          <span className={styles.choiceName}>{raw.label}</span>
          <span className={styles.choiceHint}>{raw.description}</span>
        </label>
      )}
      <fieldset className={styles.writeGroup} disabled={writeDisabled}>
        <legend className={styles.label}>Read + Write</legend>
        {writeRefusal && <p className={styles.writeNote}>{writeRefusal}</p>}
        <div className={styles.choices}>
          {SHARE_PRESETS.filter(p => p.level === 'write').map(p => presetRadio(p.id, writeDisabled))}
        </div>
        <ul className={styles.toggleList}>
          {SHARE_TOGGLES.filter(t => t.level === 'write').map((t) => {
            const noticeId = `${id}-${t.id}-notices`
            return (
              <li key={t.id}>
                <label className={styles.choice}>
                  <input
                    type="checkbox"
                    checked={false}
                    onChange={() => {}}
                    disabled={writeDisabled}
                    aria-describedby={t.notices.length ? noticeId : undefined}
                  />
                  <span className={styles.choiceName}>{t.label}</span>
                  <span className={styles.choiceHint}>{t.description}</span>
                </label>
                {t.notices.length > 0 && (
                  <span id={noticeId} className={styles.notice}>{t.notices.join(' ')}</span>
                )}
              </li>
            )
          })}
        </ul>
      </fieldset>
    </div>
  )
}
