'use client'

import { createContext, useContext, useState } from 'react'
import type { Project } from '@prisma/client'

import { field, type RegistryField } from '@/lib/reconSettings/registry'
import styles from './ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

/**
 * True while the whole form is read-only (a read share, step 4.11): every RegistryFields under it
 * renders read-only without each section passing the prop.
 */
export const RegistryFieldsReadOnly = createContext(false)

interface RegistryFieldsProps {
  /**
   * The columns to render, by name. A LITERAL list on purpose: it is what the
   * parity test reads to decide the form can reach this field, and a list built
   * at run time would satisfy the test while rendering nothing.
   */
  keys: readonly string[]
  data: FormData
  updateField: <K extends keyof FormData>(key: K, value: FormData[K]) => void
  /** Optional heading above the block. */
  title?: string
  /** Optional prose under the heading. */
  description?: string
  /** Render everything read-only, for an admin acting as another user. */
  readOnly?: boolean
}

/**
 * Inputs generated from the registry, for settings that have no bespoke UI.
 *
 * Sixty-five columns were writable over the API and had an input nowhere in this
 * form. That is not a cosmetic gap: it is the capability surface being unequal
 * in the direction nobody notices, because the missing half is the one a person
 * would have complained about. Most of them are ordinary numbers, strings and
 * toggles whose bound, unit, enum and meaning the registry already states, so
 * hand-writing sixty-five inputs would copy all of that a second time and let it
 * drift - which is exactly how the gap opened.
 *
 * So the input is DERIVED. A field with a `values:` list renders a select, which
 * is what closes the container-image hole: writing `attacker/evil:latest` used
 * to be accepted and then silently replaced at scan start, so a caller believed
 * a setting applied when it did not.
 *
 * Bespoke UI still wins wherever it exists. This is for the long tail, not a
 * replacement for the sections that explain what a setting does.
 */
export function RegistryFields({
  keys, data, updateField, title, description, readOnly: readOnlyProp = false,
}: RegistryFieldsProps) {
  const readOnly = useContext(RegistryFieldsReadOnly) || readOnlyProp
  const specs = keys
    .map(key => ({ key, spec: field(key) }))
    .filter((e): e is { key: string; spec: RegistryField } => Boolean(e.spec))

  if (specs.length === 0) return null

  return (
    <div className={styles.subSection}>
      {title && <h3 className={styles.subSectionTitle}>{title}</h3>}
      {description && <p className={styles.sectionDescription}>{description}</p>}
      {/* `.fieldRow` is a grid with `auto-fit, minmax(200px, 1fr)`, so this
          stacks at phone width without a media query of its own. */}
      <div className={styles.fieldRow}>
        {specs.map(({ key, spec }) => (
          <OneField
            key={key}
            name={key}
            spec={spec}
            data={data}
            updateField={updateField}
            readOnly={readOnly}
          />
        ))}
      </div>
    </div>
  )
}

/** `tlsxCipherConcurrency` -> `Cipher concurrency`, with the tool prefix dropped. */
export function humanise(key: string, tool: string): string {
  const words = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').split(' ')
  const toolWords = tool.split('_').filter(Boolean)
  while (words.length > 1 && toolWords.some(t => words[0].toLowerCase() === t.toLowerCase())) {
    words.shift()
  }
  const text = words.join(' ').toLowerCase()
  return text.charAt(0).toUpperCase() + text.slice(1)
}

function hint(spec: RegistryField): string {
  const parts = [spec.meaning.trim()]
  if (spec.zero_means === 'unlimited') {
    parts.push('0 means UNLIMITED here, so it is the fastest value and not the safest.')
  }
  if (spec.roe_capped) parts.push('Capped to the engagement rate ceiling at scan start.')
  return parts.join(' ')
}

function OneField({
  name, spec, data, updateField, readOnly,
}: {
  name: string
  spec: RegistryField
  data: FormData
  updateField: RegistryFieldsProps['updateField']
  readOnly: boolean
}) {
  const row = data as unknown as Record<string, unknown>
  const value = row[name]
  // An emptied number box keeps its draft while the person types and takes the
  // registry default on blur. Writing 0 at once refused the save on every field
  // whose minimum is above 0, and silently meant "disabled" where 0 means that.
  const [draft, setDraft] = useState<string | null>(null)
  const label = humanise(name, spec.tool)
  const id = `registry-field-${name}`
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const set = (v: unknown) => updateField(name as any, v as any)

  const wrap = (input: React.ReactNode) => (
    <div className={styles.fieldGroup} style={{ minWidth: 0 }}>
      <label className={styles.fieldLabel} htmlFor={id}>{label}</label>
      {input}
      <span className={styles.fieldHint}>{hint(spec)}</span>
    </div>
  )

  if (spec.type === 'boolean') {
    return wrap(
      <input
        id={id}
        type="checkbox"
        checked={Boolean(value)}
        disabled={readOnly}
        onChange={e => set(e.target.checked)}
      />
    )
  }

  // A closed vocabulary is a select. The container images are the case that
  // matters: as free text a value outside the shipped set was accepted at the
  // write and replaced at scan start, so `get_recon_settings` echoed one image
  // while the scan ran another.
  if (spec.values && spec.type === 'string') {
    return wrap(
      <select
        id={id}
        className="select"
        value={String(value ?? '')}
        disabled={readOnly}
        onChange={e => set(e.target.value)}
      >
        {spec.values.map(v => <option key={v} value={v}>{v}</option>)}
      </select>
    )
  }

  if (spec.type === 'int' || spec.type === 'float') {
    const step = spec.type === 'float' ? 'any' : 1
    return wrap(
      <input
        id={id}
        type="number"
        className="textInput"
        step={step}
        {...(spec.bounds ? { min: spec.bounds.min, max: spec.bounds.max } : {})}
        value={draft ?? Number(value ?? 0)}
        readOnly={readOnly}
        onChange={e => {
          const n = spec.type === 'float' ? parseFloat(e.target.value) : parseInt(e.target.value, 10)
          if (Number.isFinite(n)) {
            setDraft(null)
            set(n)
          } else {
            setDraft(e.target.value)
          }
        }}
        onBlur={() => {
          if (draft === null) return
          setDraft(null)
          if (spec.has_default) set(spec.default)
        }}
      />
    )
  }

  if (spec.type === 'string-list' || spec.type === 'number-list') {
    const list = Array.isArray(value) ? value : []
    return wrap(
      <input
        id={id}
        type="text"
        className="textInput"
        value={list.join(', ')}
        readOnly={readOnly}
        placeholder="comma separated"
        onChange={e => {
          const parts = e.target.value.split(',').map(s => s.trim()).filter(Boolean)
          set(spec.type === 'number-list' ? parts.map(Number).filter(Number.isFinite) : parts)
        }}
      />
    )
  }

  return wrap(
    <input
      id={id}
      type="text"
      className="textInput"
      value={String(value ?? '')}
      readOnly={readOnly}
      onChange={e => set(e.target.value)}
    />
  )
}
