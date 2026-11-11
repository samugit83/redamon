'use client'

/**
 * Include / Exclude filters of "Record + scan matching" (04_ui_spec.md §1-§2).
 *
 * Each textarea keeps the operator's raw text while they type, as the Domain
 * batch list does: re-rendering the parsed list would strip a separator the
 * instant it is typed. The parsed entries go up through the callbacks, and
 * TargetSection writes them (it owns every updateField call of the section).
 * The entries are read with the same parser the save and recon use
 * (ipHostnameFilter.parseEntries), so what this editor refuses the save refuses.
 */
import { useId, useMemo, useState } from 'react'
import { AlertTriangle, ShieldAlert } from 'lucide-react'
import { firstHardBlocked } from '@/lib/hard-guardrail'
import { INVALID_REASON_TEXT, type InvalidEntry } from '@/lib/domainBatch'
import { parseEntries } from '@/lib/ipHostnameFilter'
import { IP_HOSTNAME_MAX_ENTRIES } from '@/lib/scopeGroups'
import { FileImportButton } from './FileImportButton'
import formStyles from './ProjectForm.module.css'
import styles from './IpHostnameFilterEditor.module.css'

/** Operators paste from scope documents and spreadsheets: one per line, or
 *  separated by commas, semicolons or spaces. */
export function parseFilterText(text: string): string[] {
  return text.split(/[,;\s]+/).map(s => s.trim()).filter(Boolean)
}

/** An address in a filter is the one refusal whose batch wording ("use IP mode")
 *  would mislead here: the project already is in IP mode. */
function reasonText(i: InvalidEntry): string {
  return i.reason === 'ip_literal'
    ? 'an IP address: filters name hostnames, and your IPs are the targets above'
    : INVALID_REASON_TEXT[i.reason]
}

export interface IpHostnameFilterEditorProps {
  include: readonly string[]
  exclude: readonly string[]
  passiveExpand: boolean
  onIncludeChange: (entries: string[]) => void
  onExcludeChange: (entries: string[]) => void
  onPassiveExpandChange: (on: boolean) => void
  disabled?: boolean
}

interface ListProps {
  label: string
  entries: readonly string[]
  placeholder: string
  onChange: (entries: string[]) => void
  disabled: boolean
  invalid: InvalidEntry[]
  tooMany: boolean
}

function FilterList({ label, entries, placeholder, onChange, disabled, invalid, tooMany }: ListProps) {
  const id = useId()
  const [draft, setDraft] = useState<string | null>(null)
  const errorId = `${id}-errors`
  const hasError = invalid.length > 0 || tooMany
  return (
    <div className={styles.list}>
      <label className={formStyles.fieldLabel} htmlFor={id}>{label} (one per line)</label>
      <div className={styles.inputRow}>
        <textarea
          id={id}
          className="textarea"
          rows={4}
          value={draft ?? entries.join('\n')}
          placeholder={placeholder}
          disabled={disabled}
          aria-invalid={hasError || undefined}
          aria-describedby={hasError ? errorId : undefined}
          onChange={e => {
            setDraft(e.target.value)
            onChange(parseFilterText(e.target.value))
          }}
          onBlur={() => setDraft(null)}
        />
        {!disabled && (
          <span className={styles.importWrap}>
            <FileImportButton
              variant="textarea"
              fieldName={`${label.toLowerCase()} filters`}
              onImport={values => { setDraft(null); onChange(values) }}
            />
          </span>
        )}
      </div>
      {hasError && (
        <div id={errorId} className={`${formStyles.callout} ${formStyles.calloutDanger}`} role="alert">
          <AlertTriangle size={16} aria-hidden="true" />
          <span>
            {tooMany && <>At most {IP_HOSTNAME_MAX_ENTRIES} entries. </>}
            {invalid.length > 0 && (
              <>
                <strong>Not accepted:</strong>
                <ul className={styles.invalidList}>
                  {invalid.map(i => <li key={i.entry}><code>{i.entry}</code>: {reasonText(i)}</li>)}
                </ul>
                Remove or correct {invalid.length === 1 ? 'it' : 'them'} to save.
              </>
            )}
          </span>
        </div>
      )}
    </div>
  )
}

export function IpHostnameFilterEditor({
  include, exclude, passiveExpand, onIncludeChange, onExcludeChange, onPassiveExpandChange, disabled = false,
}: IpHostnameFilterEditorProps) {
  const inc = useMemo(() => parseEntries(include), [include])
  const exc = useMemo(() => parseEntries(exclude), [exclude])
  // The guardrail is judged on each include entry's base name, as the save does.
  const blocked = useMemo(() => firstHardBlocked(inc.patterns.map(p => p.host)), [inc])
  const noInclude = inc.patterns.length === 0 && inc.invalid.length === 0
  const wildcardCount = inc.patterns.filter(p => p.wildcard).length

  return (
    <div className={styles.editor}>
      <div className={styles.lists}>
        <FilterList
          label="Include"
          entries={include}
          placeholder={'*.example.com\n*.example.de\nshop.example.fr'}
          onChange={onIncludeChange}
          disabled={disabled}
          invalid={inc.invalid}
          tooMany={include.length > IP_HOSTNAME_MAX_ENTRIES}
        />
        <FilterList
          label="Exclude"
          entries={exclude}
          placeholder="old.example.com"
          onChange={onExcludeChange}
          disabled={disabled}
          invalid={exc.invalid}
          tooMany={exclude.length > IP_HOSTNAME_MAX_ENTRIES}
        />
      </div>
      <p className={formStyles.fieldHint}>
        <code>*.name</code> = every name under it · <code>name</code> = exactly that host · exclude wins
      </p>

      {noInclude && (
        <div className={`${formStyles.callout} ${formStyles.calloutWarning}`} role="status">
          <AlertTriangle size={16} aria-hidden="true" />
          <span>
            <strong>Add at least one include entry</strong> (for example <code>*.example.com</code>): with none,
            no hostname can be scanned and the save is refused.
          </span>
        </div>
      )}

      {blocked && (
        <div className={`${formStyles.callout} ${formStyles.calloutDanger}`} role="alert">
          <ShieldAlert size={16} aria-hidden="true" />
          <span>
            <strong>Target permanently blocked: {blocked.name}.</strong> Government, military, educational and
            international organization domains are always blocked and cannot be scanned, regardless of guardrail
            settings. Remove that entry to continue.
          </span>
        </div>
      )}

      <label className={`checkboxLabel ${styles.expand}`}>
        <input
          type="checkbox"
          className="checkbox"
          checked={passiveExpand}
          disabled={disabled}
          onChange={e => onPassiveExpandChange(e.target.checked)}
        />
        <span>
          Also search subdomains of the filter domains (passive: public sources only)
          <span className={styles.expandHint}>
            {wildcardCount > 0
              ? ` · ${wildcardCount} *. entr${wildcardCount === 1 ? 'y' : 'ies'} searched`
              : ' · only *. entries are searched'}
          </span>
        </span>
      </label>
    </div>
  )
}
