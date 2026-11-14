'use client'

import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useCan } from '@/hooks/useCan'
import { useAlertModal } from '@/components/ui'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { fetchJson, readApiError, toApiError } from '@/lib/apiError'
import type { AuditEntryView, AuditPage, AuditTable } from '@/lib/authz/auditReader'
import { AuditDetails } from './AuditDetails'
import { AuditRows } from './AuditRows'
import { RetentionStatus } from './RetentionStatus'
import {
  GROUP_OPTIONS, TABS, TAB_FILTERS, downloadName, hasFilters, queryOf, viewFrom, type Filters, type ViewState,
} from './auditView'
import { ConsoleHeader } from '../ConsoleHeader'
import { SECTION_ICONS } from '../consoleIcons'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import usersStyles from '../users/users.module.css'
import styles from './audit.module.css'

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; page: AuditPage; more: 'idle' | 'loading' | string }

type ExportFormat = 'csv' | 'json'

/**
 * The admin console's audit viewer (step 6.6; GV-07, AU-04, AU-07): the audit log, the act-as rows and
 * the Fireteam settings changes, newest first, filtered (the filters live in the address, so a view can
 * be shared), a page at a time, each row naming its actor by email and account type. A row's details
 * open in a dialog. Whoever holds audit:export downloads the current filters as CSV or JSON (the
 * export is itself audited). The console shows the denied state to anyone without audit:read before
 * this page renders; nothing here deletes a row.
 */
export default function AdminAuditPage() {
  const uid = useId()
  const router = useRouter()
  const searchParams = useSearchParams()
  const canExport = useCan('audit:export')
  const { alertError } = useAlertModal()
  const [view, setView] = useState<ViewState>(() => viewFrom(searchParams))
  const [draft, setDraft] = useState<Filters>(view.filters)
  const [state, setState] = useState<View>({ kind: 'loading' })
  const [selected, setSelected] = useState<AuditEntryView | null>(null)
  const [exporting, setExporting] = useState<ExportFormat | null>(null)
  const [exported, setExported] = useState<string | null>(null)
  const generation = useRef(0)
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([])

  const load = useCallback(async (v: ViewState) => {
    const mine = ++generation.current
    setState({ kind: 'loading' })
    try {
      const page = await fetchJson<AuditPage>(`/api/admin/audit?${queryOf(v)}`, { cache: 'no-store' }, 'Could not read the audit log')
      if (mine !== generation.current) return
      setState({ kind: 'ready', page, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      const error = toApiError(err, 'Could not read the audit log')
      const permission = forbiddenPermission(error)
      setState(permission ? { kind: 'denied', permission } : { kind: 'error', message: error.message })
    }
  }, [])

  useEffect(() => { void load(view) }, [load, view])

  function apply(next: ViewState) {
    setView(next)
    setDraft(next.filters)
    setExported(null)
    const qs = queryOf(next)
    router.replace(qs ? `/admin/audit?${qs}` : '/admin/audit', { scroll: false })
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    apply({ ...view, filters: draft })
  }

  function switchTab(table: AuditTable) {
    if (table === view.table) return
    // Each table takes its own filters: those the new tab has keep their values.
    const keep = new Set(TAB_FILTERS[table].map((f) => f.key))
    apply({ table, filters: Object.fromEntries(Object.entries(view.filters).filter(([k]) => keep.has(k as never))) })
  }

  function tabKey(e: KeyboardEvent<HTMLButtonElement>, index: number) {
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0
    const to = e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1 : step ? (index + step + TABS.length) % TABS.length : -1
    if (to < 0) return
    e.preventDefault()
    tabRefs.current[to]?.focus()
    switchTab(TABS[to].id)
  }

  async function loadMore() {
    if (state.kind !== 'ready' || !state.page.nextCursor) return
    const { page } = state
    const mine = generation.current
    setState({ ...state, more: 'loading' })
    try {
      const next = await fetchJson<AuditPage>(`/api/admin/audit?${queryOf(view, { cursor: page.nextCursor! })}`, { cache: 'no-store' }, 'Could not read more rows')
      if (mine !== generation.current) return
      setState({ kind: 'ready', page: { ...next, entries: [...page.entries, ...next.entries] }, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      setState({ kind: 'ready', page, more: toApiError(err, 'Could not read more rows').message })
    }
  }

  async function exportAs(format: ExportFormat) {
    setExporting(format)
    setExported(null)
    try {
      const res = await fetch(`/api/admin/audit/export?${queryOf(view, { format })}`, { cache: 'no-store' })
      if (!res.ok) throw await readApiError(res, 'Could not export the audit log')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = downloadName(res.headers.get('content-disposition'), `redamon-audit.${format}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      const rows = res.headers.get('x-audit-export-rows') ?? '?'
      const total = res.headers.get('x-audit-export-total') ?? rows
      setExported(res.headers.get('x-audit-export-truncated') === 'true'
        ? `Exported the first ${rows} of ${total} rows: narrow the filters to export the rest.`
        : `Exported ${rows} row${rows === '1' ? '' : 's'}.`)
    } catch (err) {
      await alertError(toApiError(err, 'Could not export the audit log').message, 'Export failed')
    } finally {
      setExporting(null)
    }
  }

  const filtered = hasFilters(view)
  const fields = TAB_FILTERS[view.table]
  const tabLabel = TABS.find((t) => t.id === view.table)!.label

  return (
    <div className={consoleStyles.page}>
      <ConsoleHeader
        icon={SECTION_ICONS.audit}
        title="Audit"
        lead={<>Who did what and when. Rows are never deleted from here; the instance&apos;s audit retention decides how long they are kept.</>}
        actions={canExport ? (
          <div className={pageStyles.actions} role="group" aria-label="Export the rows these filters select">
            {(['csv', 'json'] as const).map((f) => (
              <button key={f} type="button" className={pageStyles.actionButton} onClick={() => void exportAs(f)} disabled={exporting !== null}>
                {exporting === f ? 'Exporting…' : `Export ${f.toUpperCase()}`}
              </button>
            ))}
          </div>
        ) : undefined}
      />
      <RetentionStatus />

      <div role="tablist" aria-label="Audit tables" className={styles.tabs}>
        {TABS.map((t, i) => (
          <button
            key={t.id}
            ref={(el) => { tabRefs.current[i] = el }}
            type="button"
            role="tab"
            id={`${uid}-tab-${t.id}`}
            aria-selected={view.table === t.id}
            aria-controls={`${uid}-panel`}
            tabIndex={view.table === t.id ? 0 : -1}
            className={view.table === t.id ? `${styles.tab} ${styles.tabActive}` : styles.tab}
            onClick={() => switchTab(t.id)}
            onKeyDown={(e) => tabKey(e, i)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`${uid}-panel`} aria-labelledby={`${uid}-tab-${view.table}`} className={styles.panel}>
        <form className={usersStyles.filters} onSubmit={submit} role="search" aria-label={`Filter the ${tabLabel} rows`}>
          {fields.map((f) => (
            <div key={f.key} className={usersStyles.filter}>
              <label className={pageStyles.label} htmlFor={`${uid}-${f.key}`}>{f.label}</label>
              {f.kind === 'group' ? (
                <select id={`${uid}-${f.key}`} className={pageStyles.select} value={draft[f.key] ?? ''} onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}>
                  <option value="">Any kind</option>
                  {GROUP_OPTIONS.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
                </select>
              ) : (
                <input
                  id={`${uid}-${f.key}`}
                  type={f.kind === 'date' ? 'date' : 'text'}
                  className={pageStyles.input}
                  value={draft[f.key] ?? ''}
                  placeholder={f.hint}
                  aria-describedby={f.hint ? `${uid}-${f.key}-hint` : undefined}
                  onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                  maxLength={320}
                />
              )}
              {f.hint && <span id={`${uid}-${f.key}-hint`} className={styles.srOnly}>{f.hint}</span>}
            </div>
          ))}
          <button type="submit" className={pageStyles.actionButton}>Apply</button>
          {filtered && (
            <button type="button" className={pageStyles.actionButton} onClick={() => apply({ ...view, filters: {} })}>Clear filters</button>
          )}
        </form>

        {exported && <p className={usersStyles.count} role="status">{exported}</p>}

        {state.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the audit rows…</p>}
        {state.kind === 'denied' && <ForbiddenNotice permission={state.permission} />}
        {state.kind === 'error' && (
          <div className={pageStyles.errorState}>
            <div className={pageStyles.error} role="alert">{state.message}</div>
            <button type="button" className={pageStyles.actionButton} onClick={() => void load(view)}>Retry</button>
          </div>
        )}
        {state.kind === 'ready' && (
          state.page.entries.length === 0 ? (
            <p className={consoleStyles.state}>{filtered ? 'No row matches these filters.' : 'No row recorded yet.'}</p>
          ) : (
            <>
              <p className={usersStyles.count} aria-live="polite">
                Showing {state.page.entries.length} row{state.page.entries.length === 1 ? '' : 's'}{state.page.nextCursor ? ' (more below)' : ''}
              </p>
              <AuditRows table={state.page.table} entries={state.page.entries} onOpen={setSelected} />
              {state.page.nextCursor && (
                <div className={usersStyles.more}>
                  <button type="button" className={pageStyles.actionButton} onClick={() => void loadMore()} disabled={state.more === 'loading'}>
                    {state.more === 'loading' ? 'Loading…' : 'Load more'}
                  </button>
                </div>
              )}
              {state.more !== 'idle' && state.more !== 'loading' && <div className={pageStyles.error} role="alert">{state.more}</div>}
            </>
          )
        )}
      </div>

      <AuditDetails entry={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
