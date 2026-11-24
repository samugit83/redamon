'use client'

import { useEffect, useMemo, useState } from 'react'
import { Check, ChevronDown, Eye, EyeOff } from 'lucide-react'
import { shortCredentialLabel, isSecretField } from '@/lib/credentialFields'
import type { KeyGroupSpec } from '@/lib/credentialFields'
import type { CredentialRequirement } from '@/lib/trufflehogSources'
import styles from './CredentialDrawer.module.css'

type GroupField = KeyGroupSpec['fields'][number]

interface CredentialDrawerProps {
  /** Anchor id. Scan cards deep-link to it, so it must not change casually. */
  id: string
  title: string
  intro: string
  groups: KeyGroupSpec[]
  /** Current draft value of a key. Stored secrets come back masked. */
  value: (name: string) => string
  /** Whether a stored value exists - the only thing the closed summary can say
   *  about a key it must never display. */
  isSet: (name: string) => boolean
  visible: (name: string) => boolean
  onToggleVisibility: (name: string) => void
  onChange: (name: string, value: string) => void
}

const REQUIREMENT_CHIP: Record<CredentialRequirement, { label: string; className: string }> = {
  required: { label: 'Required', className: styles.chipRequired },
  conditional: { label: 'Sometimes required', className: styles.chipConditional },
  optional: { label: 'Optional', className: styles.chipOptional },
}

/**
 * Drop the source name from a key that sits under a card already carrying it:
 * "Jenkins Password" under a Jenkins card is just "Password". Only leading
 * words are taken, so "GCP Service Account" under "Google Cloud Storage" is
 * left alone rather than mangled.
 */
export function labelUnder(groupLabel: string, label: string): string {
  const words = label.split(' ')
  const groupWords = groupLabel.split(' ')
  let i = 0
  while (i < groupWords.length && i < words.length - 1
    && words[i].toLowerCase() === groupWords[i].toLowerCase()) i++
  return words.slice(i).join(' ')
}

/**
 * A group of related credentials behind one drawer.
 *
 * Flat, 19 Secret Multiscanner keys were a wall of near-identical boxes in
 * which the two a given user actually needs are indistinguishable from the
 * seventeen they do not, and they pushed every other scanner's key off the
 * screen. Closed, the drawer answers the only question the hidden fields would
 * have: per source, what is set and what is not. Open, one card per source - so
 * the four Elasticsearch keys read as four ways to authenticate one cluster,
 * not as four unrelated tokens.
 */
export function CredentialDrawer({
  id,
  title,
  intro,
  groups,
  value,
  isSet,
  visible,
  onToggleVisibility,
  onChange,
}: CredentialDrawerProps) {
  const fields = useMemo(() => groups.flatMap(g => g.fields), [groups])

  const setCount = fields.filter(f => isSet(f.name)).length
  const missingRequired = groups.filter(
    g => g.requirement === 'required' && g.fields.some(f => !isSet(f.name)),
  )

  // Opened once, by what was missing when the tab rendered. Deriving it per
  // keystroke would shut the drawer under the cursor the moment the last
  // mandatory key stopped being empty.
  const [open, setOpen] = useState(() => missingRequired.length > 0)

  // The scan card links straight here to say a key is missing; landing on a
  // closed drawer would answer that with nothing to type into.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- the URL hash is only readable after hydration
    if (window.location.hash === `#${id}`) setOpen(true)
  }, [id])

  return (
    <section id={id} className={styles.drawer}>
      <button
        type="button"
        className={styles.trigger}
        aria-expanded={open}
        aria-controls={`${id}-panel`}
        onClick={() => setOpen(o => !o)}
      >
        <ChevronDown size={15} className={`${styles.chevron} ${open ? styles.chevronOpen : ''}`} />
        <span className={styles.title}>{title}</span>
        <span className={styles.spacer} />
        {missingRequired.length > 0 && (
          <span className={`${styles.chip} ${styles.chipRequired}`}>
            {missingRequired.length} required missing
          </span>
        )}
        <span className={styles.count}>{setCount} of {fields.length} keys set</span>
      </button>

      {!open && (
        <div className={styles.summary}>
          {groups.map(group => {
            const set = group.fields.filter(f => isSet(f.name)).length
            const all = group.fields.length
            const blocking = group.requirement === 'required' && set < all
            const state = set === all ? styles.pillSet : blocking ? styles.pillMissing : styles.pillIdle
            return (
              <span key={group.source} className={`${styles.pill} ${state}`}>
                {group.label}
                {set === all ? <Check size={10} /> : <span className={styles.pillCount}>{set}/{all}</span>}
              </span>
            )
          })}
        </div>
      )}

      {open && (
        <div id={`${id}-panel`} className={styles.panel}>
          <p className={styles.intro}>{intro}</p>

          <div className={styles.cards}>
            {groups.map(group => {
              const chip = REQUIREMENT_CHIP[group.requirement]
              const set = group.fields.filter(f => isSet(f.name)).length
              const solo = group.fields.length === 1

              return (
                <article
                  key={group.source}
                  id={`${id}-${group.source}`}
                  className={`${styles.card} ${solo ? '' : styles.cardGroup}`}
                >
                  {/* A card head only earns its line when the keys under it are
                      several and have to read as one set of credentials. */}
                  {!solo && (
                    <header className={styles.cardHead}>
                      <span className={styles.cardName}>
                        {group.label}
                        {group.alsoUsedBy.length > 0 && (
                          <span className={styles.also}> + {group.alsoUsedBy.join(', ')}</span>
                        )}
                      </span>
                      <span className={`${styles.chip} ${chip.className}`}>{chip.label}</span>
                      <span className={styles.spacer} />
                      <span className={styles.count}>{set}/{group.fields.length} set</span>
                    </header>
                  )}

                  {group.fields.map(field => (
                    <KeyRow
                      key={field.name}
                      field={field}
                      label={solo ? shortCredentialLabel(field.label)
                        : labelUnder(group.label, shortCredentialLabel(field.label))}
                      note={solo ? group.alsoUsedBy.join(', ') : ''}
                      // Under a card head the requirement is already stated; a
                      // row only repeats it when it differs from the group's.
                      chip={solo || field.requirement !== group.requirement
                        ? REQUIREMENT_CHIP[field.requirement] : null}
                      value={value(field.name)}
                      visible={visible(field.name)}
                      onToggleVisibility={() => onToggleVisibility(field.name)}
                      onChange={v => onChange(field.name, v)}
                    />
                  ))}
                </article>
              )
            })}
          </div>
        </div>
      )}
    </section>
  )
}

/** One key: what it is on the left, what it is set to on the right. */
function KeyRow({
  field,
  label,
  note,
  chip,
  value,
  visible,
  onToggleVisibility,
  onChange,
}: {
  field: GroupField
  label: string
  note: string
  chip: { label: string; className: string } | null
  value: string
  visible: boolean
  onToggleVisibility: () => void
  onChange: (value: string) => void
}) {
  const inputId = `credential-key-${field.name}`
  // Shortened for the eye, never for the ear: a screen reader still gets the
  // name that identifies the key on its own.
  const fullLabel = shortCredentialLabel(field.label)
  // A hostname is configuration, not a credential. Masking it hides the
  // allowlist value the operator needs to be able to read back.
  const secret = isSecretField(field.name)

  return (
    <div className={styles.row}>
      <div className={styles.rowLabel}>
        <div className={styles.rowTop}>
          {/* The second source that reads this key belongs in the name, not in
              a footnote beside it: one token, two sources. */}
          <label htmlFor={inputId} className={styles.rowName}>
            {label}
            {note && <span className={styles.also}> + {note}</span>}
          </label>
          {chip && <span className={`${styles.chip} ${chip.className}`}>{chip.label}</span>}
        </div>
        <p className={styles.rowHint}>
          {field.hint}
          {field.signupUrl && (
            <>
              {' '}
              <a href={field.signupUrl} target="_blank" rel="noopener noreferrer" className={styles.rowLink}>
                Get API key
              </a>
            </>
          )}
        </p>
      </div>
      <div className={styles.rowValue}>
        <div className={styles.inputWrap}>
          <input
            id={inputId}
            className="textInput"
            type={!secret || visible ? 'text' : 'password'}
            value={value ?? ''}
            aria-label={fullLabel}
            placeholder={field.placeholder ?? `Enter ${fullLabel.toLowerCase()}`}
            autoComplete={secret ? 'new-password' : 'off'}
            spellCheck={false}
            onChange={e => onChange(e.target.value)}
          />
          {secret && (
            <button
              type="button"
              className={styles.reveal}
              onClick={onToggleVisibility}
              aria-label={visible ? `Hide the ${fullLabel}` : `Show the ${fullLabel}`}
            >
              {visible ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
