'use client'

import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useToast } from '@/components/ui'
import { GuardedLink } from '@/components/GuardedLink'
import { ForbiddenNotice } from '@/components/auth/ForbiddenNotice'
import { errorMessage, readApiError } from '@/lib/apiError'
import type { InstanceSettingsView } from './instanceView'
import { putInstanceSettings } from './instanceSettingsClient'
import {
  QUOTA_FIELD_SPECS, draftErrors, draftOf, emptyEntryCells, quotaPatch,
  type Cell, type CellMode, type Cells, type QuotaDraft, type QuotaFieldSpec, type QuotaStoreView,
} from './quotaModel'
import { Panel } from './Panel'
import styles from './instance.module.css'

interface SetOption { id: string; name: string; kind: string }
interface UserOption { id: string; email: string; name: string }

const SAVE_FAILED = 'The quotas were not saved'
const SEARCH_FAILED = "Couldn't search the accounts"

const LEAD = "Limits per permission set or per account. A person's limit is their own, else the most generous of their sets, " +
  'else the default. Every limit starts unlimited; Root is never limited.'

/**
 * The quotas (step 6.8; GV-09..GV-13): the defaults, an entry per permission set and per account,
 * saved through the `quotas` group of /api/admin/instance-settings (instance:quotas). The Save sends
 * only what changed, so two administrators changing two entries never undo each other.
 */
export function QuotasPanel({ settings, onSaved }: { settings: InstanceSettingsView; onSaved: (next: InstanceSettingsView) => void }) {
  const toast = useToast()
  const store = settings.quotas as QuotaStoreView | undefined
  const sets = useMemo(() => (Array.isArray(settings.quotaSets) ? settings.quotaSets as SetOption[] : []), [settings.quotaSets])
  const users = Array.isArray(settings.quotaUsers) ? settings.quotaUsers as UserOption[] : null
  const [saved, setSaved] = useState<QuotaDraft>(() => draftOf(store))
  const [draft, setDraft] = useState<QuotaDraft>(saved)
  const [addSet, setAddSet] = useState('')
  const [known, setKnown] = useState<UserOption[]>([])
  const [saving, setSaving] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)

  useEffect(() => {
    const next = draftOf(store)
    setSaved(next)
    setDraft(next)
  }, [store])

  if (!store || settings.canManageQuotas !== true) {
    return <Panel id="quotas" title="Quotas" lead={LEAD}><ForbiddenNotice permission="instance:quotas" /></Panel>
  }

  const errors = draftErrors(draft)
  const patch = quotaPatch(saved, draft)
  const setName = (id: string) => {
    const s = sets.find((o) => o.id === id)
    return s ? `${s.name}${s.kind === 'admin' ? ' (admin profile)' : ''}` : id
  }
  const userOf = (id: string) => users?.find((u) => u.id === id) ?? known.find((u) => u.id === id)
  const userName = (id: string) => {
    const u = userOf(id)
    return u ? `${u.name} (${u.email})` : id
  }
  const freeSets = sets.filter((s) => !draft.perSet[s.id])

  const change = (key: 'defaults' | 'perSet' | 'perUser', id: string | null, field: QuotaFieldSpec['field'], cell: Cell) => {
    setDraft((d) => {
      if (key === 'defaults') return { ...d, defaults: { ...d.defaults, [field]: cell } }
      return { ...d, [key]: { ...d[key], [id!]: { ...d[key][id!], [field]: cell } } }
    })
  }
  const remove = (key: 'perSet' | 'perUser', id: string) => {
    setDraft((d) => {
      const next = { ...d[key] }
      delete next[id]
      return { ...d, [key]: next }
    })
  }
  const add = (key: 'perSet' | 'perUser', id: string) => {
    setDraft((d) => (d[key][id] ? d : { ...d, [key]: { ...d[key], [id]: emptyEntryCells() } }))
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!patch || Object.keys(errors).length) return
    setSaving(true)
    setFailure(null)
    try {
      const next = await putInstanceSettings({ quotas: patch }, SAVE_FAILED)
      toast.success('Quotas saved')
      onSaved(next)
    } catch (err) {
      setFailure(errorMessage(err, SAVE_FAILED))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Panel id="quotas" title="Quotas" lead={LEAD}>
      <form onSubmit={submit} className={styles.page} style={{ gap: 'var(--space-3)' }} noValidate>
        <EntryFields
          legend="Default for everyone"
          prefix="quota-default"
          errorPrefix="defaults"
          cells={draft.defaults}
          allowInherit={false}
          errors={errors}
          onChange={(field, cell) => change('defaults', null, field, cell)}
        />

        <h3 className={styles.groupTitle}>Per permission set</h3>
        {Object.keys(draft.perSet).length === 0 && <p className={styles.state}>No set has its own quota.</p>}
        {Object.keys(draft.perSet).map((id, i) => (
          <EntryFields
            key={id}
            legend={setName(id)}
            prefix={`quota-set-${i}`}
            errorPrefix={`perSet.${id}`}
            cells={draft.perSet[id]}
            allowInherit
            errors={errors}
            onChange={(field, cell) => change('perSet', id, field, cell)}
            onRemove={() => remove('perSet', id)}
          />
        ))}
        {freeSets.length > 0 && (
          <div className={styles.actions}>
            <label htmlFor="quota-add-set">Give a set its own quota</label>
            <select id="quota-add-set" className="select" value={addSet} onChange={(e) => setAddSet(e.target.value)}>
              <option value="">Choose a set…</option>
              {freeSets.map((s) => <option key={s.id} value={s.id}>{setName(s.id)}</option>)}
            </select>
            <button type="button" className="secondaryButton" disabled={!addSet} onClick={() => { add('perSet', addSet); setAddSet('') }}>
              Add set
            </button>
          </div>
        )}

        <h3 className={styles.groupTitle}>Per account</h3>
        {Object.keys(draft.perUser).length === 0 && <p className={styles.state}>No account has its own quota.</p>}
        {Object.keys(draft.perUser).map((id, i) => (
          <EntryFields
            key={id}
            legend={userName(id)}
            link={users ? `/admin/users/${encodeURIComponent(id)}` : undefined}
            prefix={`quota-user-${i}`}
            errorPrefix={`perUser.${id}`}
            cells={draft.perUser[id]}
            allowInherit
            errors={errors}
            onChange={(field, cell) => change('perUser', id, field, cell)}
            onRemove={() => remove('perUser', id)}
          />
        ))}
        {users ? (
          <AccountSearch
            exclude={Object.keys(draft.perUser)}
            onPick={(u) => { setKnown((k) => [...k.filter((x) => x.id !== u.id), u]); add('perUser', u.id) }}
          />
        ) : (
          <p className={styles.note}>Reading the user directory (users:read) lets you give an account its own quota here.</p>
        )}

        {failure && <div className={styles.error} role="alert">{failure}</div>}
        <div className={styles.actions}>
          <button type="submit" className="primaryButton" disabled={!patch || saving || Object.keys(errors).length > 0}>
            {saving ? 'Saving…' : 'Save quotas'}
          </button>
          {patch && <button type="button" className="secondaryButton" onClick={() => setDraft(saved)}>Discard changes</button>}
        </div>
      </form>
    </Panel>
  )
}

const MODE_LABEL: Record<CellMode, string> = { inherit: 'Not set here', unlimited: 'Unlimited', limit: 'Limit' }

function EntryFields({ legend, link, prefix, errorPrefix, cells, allowInherit, errors, onChange, onRemove }: {
  legend: string
  link?: string
  prefix: string
  errorPrefix: string
  cells: Cells
  allowInherit: boolean
  errors: Record<string, string>
  onChange: (field: QuotaFieldSpec['field'], cell: Cell) => void
  onRemove?: () => void
}) {
  const modes: CellMode[] = allowInherit ? ['inherit', 'unlimited', 'limit'] : ['unlimited', 'limit']
  return (
    <fieldset className={styles.fields} style={{ border: '1px solid var(--border-default)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)' }}>
      <legend className={styles.groupTitle}>
        {link ? <GuardedLink href={link}>{legend}</GuardedLink> : legend}
      </legend>
      {QUOTA_FIELD_SPECS.map((spec) => {
        const id = `${prefix}-${spec.field}`
        const cell = cells[spec.field]
        const error = errors[`${errorPrefix}.${spec.field}`]
        return (
          <div key={spec.field} className={styles.field}>
            <label htmlFor={id}>{spec.label}</label>
            <select
              id={id}
              className="select"
              value={cell.mode}
              aria-describedby={`${id}-hint`}
              onChange={(e) => onChange(spec.field, { mode: e.target.value as CellMode, value: cell.value })}
            >
              {modes.map((m) => <option key={m} value={m}>{MODE_LABEL[m]}</option>)}
            </select>
            {cell.mode === 'limit' && (
              <input
                id={`${id}-value`}
                className="textInput"
                inputMode="numeric"
                aria-label={`${spec.label}: limit in ${spec.unit} for ${legend}`}
                aria-invalid={!!error}
                value={cell.value}
                onChange={(e) => onChange(spec.field, { mode: 'limit', value: e.target.value })}
              />
            )}
            <span id={`${id}-hint`} className={error ? styles.fieldError : styles.hint}>
              {error ?? (cell.mode === 'inherit' ? 'The next level decides.' : `${spec.min} to ${spec.max} ${spec.unit}.`)}
            </span>
          </div>
        )
      })}
      {onRemove && (
        <div className={styles.actions}>
          <button type="button" className="textButton" onClick={onRemove} aria-label={`Remove the quota of ${legend}`}>Remove</button>
        </div>
      )}
    </fieldset>
  )
}

function AccountSearch({ exclude, onPick }: { exclude: string[]; onPick: (u: UserOption) => void }) {
  const [q, setQ] = useState('')
  const [results, setResults] = useState<UserOption[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const search = async () => {
    if (!q.trim()) return
    setBusy(true)
    setError(null)
    try {
      const res = await fetch(`/api/admin/users?q=${encodeURIComponent(q.trim())}&limit=8`, { cache: 'no-store' })
      if (!res.ok) throw await readApiError(res, SEARCH_FAILED)
      const body = await res.json() as { users?: UserOption[] }
      setResults((body.users ?? []).map((u) => ({ id: u.id, email: u.email, name: u.name })))
    } catch (err) {
      setError(errorMessage(err, SEARCH_FAILED))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={styles.fields}>
      <div className={styles.actions}>
        <label htmlFor="quota-user-search">Give an account its own quota</label>
        <input
          id="quota-user-search"
          className="textInput"
          placeholder="Name or email"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); search() } }}
        />
        <button type="button" className="secondaryButton" disabled={!q.trim() || busy} onClick={search}>
          {busy ? 'Searching…' : 'Search'}
        </button>
      </div>
      {error && <div className={styles.error} role="alert">{error}</div>}
      {results && results.length === 0 && <p className={styles.state}>No account matches.</p>}
      {results && results.length > 0 && (
        <ul className={styles.toolList} aria-label="Accounts found">
          {results.map((u) => (
            <li key={u.id}>
              {u.name} ({u.email}){' '}
              <button type="button" className="textButton" disabled={exclude.includes(u.id)} onClick={() => onPick(u)}>
                {exclude.includes(u.id) ? 'Has its own quota' : `Add ${u.email}`}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
