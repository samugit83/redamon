'use client'

import { useId } from 'react'
import type { ShareGrantable } from '@/lib/authz/projectShares'
import {
  SHARE_PRESETS,
  SHARE_TOGGLES,
  fullTerms,
  presetById,
  presetOf,
  presetOffer,
  toggleOffer,
  type SharePresetId,
  type ShareTerms,
  type ShareTermsLike,
  type WriteToggleId,
} from './sharePresets'
import styles from './ShareDialog.module.css'

/** What the picker holds: a preset, and Custom's own terms (kept apart from the presets'). */
export interface AccessChoice {
  presetId: SharePresetId
  custom: ShareTerms
}

const READ_ONLY: ShareTerms = { access: 'read', rawData: false, runScans: false, useAgent: false, exploit: false, manage: false }

/** The picker's start: Viewer for a new grant, or the preset an existing share is (Custom holding its terms). */
export function choiceOf(share?: ShareTermsLike): AccessChoice {
  if (!share) return { presetId: 'viewer', custom: READ_ONLY }
  return { presetId: presetOf(share), custom: fullTerms(share) }
}

/** The terms a choice grants. */
export function termsOf(choice: AccessChoice): ShareTerms {
  return presetById(choice.presetId).terms ?? choice.custom
}

/** Read + Write includes Raw data; a Read share holds no Read + Write toggle. */
function withLevel(terms: ShareTerms, access: ShareTerms['access']): ShareTerms {
  return access === 'write'
    ? { ...terms, access, rawData: true }
    : { ...terms, access, runScans: false, useAgent: false, exploit: false, manage: false }
}

interface AccessPickerProps {
  value: AccessChoice
  onChange: (next: AccessChoice) => void
  /** Why the Read + Write presets and toggles are offered disabled (sharePresets.writePresetsRefusal); null once they may be granted. */
  writeRefusal: string | null
  /** What the person may grant (the share list's answer with write sharing in force); null: the route decides. */
  grantable?: Pick<ShareGrantable, 'toggles'> | null
  disabled?: boolean
}

/**
 * The share dialog's level picker (steps 4.12, 5.14; SH-05, UI-07): the Read presets as radios, Custom
 * (the level, Raw data and each toggle), and the Read + Write presets and toggles with their warnings
 * (HD-22, SH-29). With write sharing not in force the write part is disabled with the reason. Within
 * it, what the person cannot grant is disabled with why (Root's policy, the owner's consent) or, for a
 * co-owner, not shown (they grant only what they hold). Flipping a toggle from a preset moves to the
 * preset it makes, else to Custom; inside Custom it stays Custom. Used by the grant form and each
 * share's editor.
 */
export function AccessPicker({ value, onChange, writeRefusal, grantable = null, disabled = false }: AccessPickerProps) {
  const id = useId()
  const radioName = `${id}-preset`
  const writeDisabled = disabled || writeRefusal !== null
  const raw = SHARE_TOGGLES.find(t => t.id === 'rawData')!
  const terms = termsOf(value)
  const custom = value.presetId === 'custom'

  const setCustom = (next: ShareTerms) => onChange({ presetId: 'custom', custom: next })
  const flipToggle = (toggle: WriteToggleId, on: boolean) => {
    const next = { ...withLevel(terms, 'write'), [toggle]: on }
    onChange({ presetId: custom ? 'custom' : presetOf(next), custom: next })
  }

  const presetRadio = (presetId: SharePresetId) => {
    const preset = presetById(presetId)
    const offer = presetOffer(preset, writeRefusal, grantable)
    if (offer.state === 'hidden') return null
    const reasonId = `${id}-${preset.id}-why`
    const why = offer.state === 'disabled' && preset.level === 'write' && writeRefusal === null ? offer.reason : null
    return (
      <label key={preset.id} className={styles.choice}>
        <input
          type="radio"
          name={radioName}
          value={preset.id}
          checked={value.presetId === preset.id}
          onChange={() => onChange({ ...value, presetId: preset.id })}
          disabled={disabled || offer.state === 'disabled'}
          aria-describedby={why ? reasonId : undefined}
        />
        <span className={styles.choiceName}>{preset.label}</span>
        <span className={styles.choiceHint}>{preset.summary}</span>
        {why && <span id={reasonId} className={styles.notice}>{why}</span>}
      </label>
    )
  }

  return (
    <div className={styles.picker}>
      <div role="radiogroup" aria-labelledby={`${id}-access`} className={styles.choices}>
        <span id={`${id}-access`} className={styles.label}>Access</span>
        {SHARE_PRESETS.filter(p => p.level === 'read').map(p => presetRadio(p.id))}
      </div>
      {custom && (
        <div className={styles.choices}>
          {writeRefusal === null && (
            <label className={styles.choice}>
              <input
                type="checkbox"
                checked={value.custom.access === 'write'}
                onChange={(e) => setCustom(withLevel(value.custom, e.target.checked ? 'write' : 'read'))}
                disabled={disabled}
              />
              <span className={styles.choiceName}>Read + Write</span>
              <span className={styles.choiceHint}>Change the project: settings, findings, versions and reports.</span>
            </label>
          )}
          <label className={styles.choice}>
            <input
              type="checkbox"
              checked={value.custom.rawData || value.custom.access === 'write'}
              onChange={(e) => setCustom({ ...value.custom, rawData: e.target.checked })}
              disabled={disabled || value.custom.access === 'write'}
            />
            <span className={styles.choiceName}>{raw.label}</span>
            <span className={styles.choiceHint}>{value.custom.access === 'write' ? 'Included with Read + Write.' : raw.description}</span>
          </label>
        </div>
      )}
      <fieldset className={styles.writeGroup} disabled={writeDisabled}>
        <legend className={styles.label}>Read + Write</legend>
        {writeRefusal && <p className={styles.writeNote}>{writeRefusal}</p>}
        <div className={styles.choices}>
          {SHARE_PRESETS.filter(p => p.level === 'write').map(p => presetRadio(p.id))}
        </div>
        <ul className={styles.toggleList}>
          {SHARE_TOGGLES.filter(t => t.level === 'write').map((t) => {
            const toggle = t.id as WriteToggleId
            const offer = toggleOffer(toggle, writeRefusal, grantable)
            // What cannot be granted is never in the way of taking it away: a toggle the share already
            // holds stays shown and can be cleared.
            if (offer.state === 'hidden' && !terms[toggle]) return null
            const noticeId = `${id}-${t.id}-notices`
            const why = offer.state === 'disabled' && writeRefusal === null ? offer.reason : null
            const notices = [...(why ? [why] : []), ...t.notices]
            return (
              <li key={t.id}>
                <label className={styles.choice}>
                  <input
                    type="checkbox"
                    checked={terms[toggle]}
                    onChange={(e) => flipToggle(toggle, e.target.checked)}
                    disabled={writeDisabled || (offer.state !== 'offered' && !terms[toggle])}
                    aria-describedby={notices.length ? noticeId : undefined}
                  />
                  <span className={styles.choiceName}>{t.label}</span>
                  <span className={styles.choiceHint}>{t.description}</span>
                </label>
                {notices.length > 0 && <span id={noticeId} className={styles.notice}>{notices.join(' ')}</span>}
              </li>
            )
          })}
        </ul>
      </fieldset>
    </div>
  )
}
