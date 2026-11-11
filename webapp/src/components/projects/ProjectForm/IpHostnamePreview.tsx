'use client'

/**
 * "Preview (names found by the last run on these IPs)" under the filters of
 * Record + scan matching (04_ui_spec.md §1, §2, §8).
 *
 * The route judges the form's UNSAVED policy over every name the last run
 * found (the TS mirror of the rule, without DNS), so "would scan N of M" is what
 * a run with these filters would do, DNS permitting, and stays exact however
 * many names there are; only one page of rows is fetched. A name the last run
 * refused for a DNS reason shows that reason: where it points now is checked at
 * run time, not here.
 */
import { useEffect, useId, useMemo, useState } from 'react'
import { AlertTriangle, Check, Info, X } from 'lucide-react'
import { ApiError, fetchJson } from '@/lib/apiError'
import { REASON_TEXT } from '@/lib/ipHostnameFilter'
import type { IpHostnamePreview as PreviewBody, PreviewName } from '@/lib/ipHostnamePreview'
import type { IpHostnameMode } from './ipHostnameModes'
import formStyles from './ProjectForm.module.css'
import styles from './IpHostnamePreview.module.css'

const PAGE = 100
const DEBOUNCE_MS = 250
/** Past this, the unsaved lists stay off the URL (a header-size limit) and the
 *  saved filters are judged instead, with a note saying so. */
const MAX_URL = 6000

/** Reasons that come from where the name pointed when the last run resolved it
 *  (checks 10-16 of the rule, and the post-probe move). */
const LAST_RUN_RESULTS: ReadonlySet<string> = new Set([
  'dns_disabled', 'resolver_unavailable', 'no_current_resolution', 'never_scannable_address',
  'resolves_outside_targets', 'wildcard_zone', 'moved_during_scan',
])

const RECORDING_RUN: ReadonlySet<string> = new Set(['record_only', 'record_filter', 'scan_all'])

function reasonWords(code: string): string {
  return (REASON_TEXT as Record<string, string>)[code] ?? 'not scanned'
}

/** Source codes as the operator knows them: cert, ptr, otx, shodan... */
export function sourceLabel(source: string): string {
  const s = source.toLowerCase()
  if (s === 'ptr' || s.startsWith('ptr_') || s.includes('reverse_dns')) return 'ptr'
  if (s.includes('san') || s.includes('cert') || s.endsWith('_cn')) return 'cert'
  if (s.includes('redirect')) return 'redirect'
  if (s.startsWith('passive_')) return `${s.slice('passive_'.length)} (passive)`
  return s.split('_')[0]
}

function sourcesText(sources: readonly string[]): string {
  return [...new Set(sources.map(sourceLabel))].join(', ') || '–'
}

function ResultCell({ row }: { row: PreviewName }) {
  if (row.result === 'scanned') {
    return (
      <span className={styles.scan}>
        <Check size={13} aria-hidden="true" /> scan <span className={styles.muted}>(DNS checked at run time)</span>
      </span>
    )
  }
  if (!row.result) return <span className={styles.muted}>not looked up</span>
  const lastRun = LAST_RUN_RESULTS.has(row.result) && row.result === row.reason
  return (
    <span className={styles.refused}>
      <X size={13} aria-hidden="true" /> {lastRun ? 'last run: ' : ''}{reasonWords(row.result)}
    </span>
  )
}

export interface IpHostnamePreviewProps {
  /** Absent in create mode: nothing has run yet. */
  projectId?: string
  mode: IpHostnameMode
  include: readonly string[]
  exclude: readonly string[]
  maxScanned: number
}

type Load =
  | { state: 'loading' }
  | { state: 'error'; notFound: boolean; message: string }
  | { state: 'ready'; body: PreviewBody }

export function IpHostnamePreview({ projectId, mode, include, exclude, maxScanned }: IpHostnamePreviewProps) {
  const headingId = useId()
  const searchId = useId()
  const [load, setLoad] = useState<Load>({ state: 'loading' })
  // A refetch while the filters are edited keeps the last answer on screen.
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)
  // The page is addressed by the names that start each page walked so far.
  const [cursors, setCursors] = useState<(string | null)[]>([null])
  const [reason, setReason] = useState<string | null>(null)
  const [q, setQ] = useState('')

  // A changed policy is a different list: the page walked so far no longer
  // means anything, so it starts again from the first page.
  const policyKey = JSON.stringify([mode, include, exclude, maxScanned])
  const [pagedPolicy, setPagedPolicy] = useState(policyKey)
  if (pagedPolicy !== policyKey) {
    setPagedPolicy(policyKey)
    setCursors([null])
  }
  // A result chip the new answer no longer has would filter to nothing.
  if (load.state === 'ready' && reason !== null && load.body.totals.byReason[reason] === undefined) {
    setReason(null)
    setCursors([null])
  }

  const cursor = cursors[cursors.length - 1]
  const { url, savedFilters } = useMemo(() => {
    if (!projectId) return { url: null, savedFilters: false }
    const base = new URLSearchParams({ limit: String(PAGE) })
    if (cursor) base.set('cursor', cursor)
    if (reason) base.set('reason', reason)
    if (q.trim()) base.set('q', q.trim())
    const withPolicy = new URLSearchParams(base)
    withPolicy.set('mode', mode)
    for (const e of include) withPolicy.append('include', e)
    for (const e of exclude) withPolicy.append('exclude', e)
    withPolicy.set('cap', String(maxScanned))
    const path = `/api/projects/${encodeURIComponent(projectId)}/ip-hostnames?`
    const full = path + withPolicy.toString()
    return full.length <= MAX_URL ? { url: full, savedFilters: false } : { url: path + base.toString(), savedFilters: true }
  }, [projectId, cursor, reason, q, mode, include, exclude, maxScanned])

  useEffect(() => {
    if (!url) return
    let alive = true
    const timer = setTimeout(() => {
      setBusy(true)
      setLoad(prev => (prev.state === 'ready' ? prev : { state: 'loading' }))
      fetchJson<PreviewBody>(url, undefined, "Couldn't load the names found last run")
        .then(body => {
          if (!alive) return
          // A body without totals is not this route's answer (a proxy page, an
          // older server): say so rather than render half a table.
          if (!body || typeof body !== 'object' || typeof body.totals?.found !== 'number') {
            setLoad({ state: 'error', notFound: false, message: 'unexpected answer' })
          } else {
            setLoad({ state: 'ready', body })
          }
        })
        .catch((err: unknown) => {
          if (!alive) return
          const notFound = err instanceof ApiError && err.status === 404
          setLoad({ state: 'error', notFound, message: err instanceof Error ? err.message : String(err) })
        })
        .finally(() => { if (alive) setBusy(false) })
    }, DEBOUNCE_MS)
    return () => { alive = false; clearTimeout(timer) }
  }, [url, reload])

  // A filter change starts the list over, from its first page.
  const restart = () => setCursors([null])

  const heading = (
    <span id={headingId} className={formStyles.fieldLabel}>Preview (names found by the last run on these IPs)</span>
  )

  if (!projectId) {
    return (
      <div className={styles.preview} aria-labelledby={headingId} role="region">
        {heading}
        <p className={styles.message}><Info size={14} aria-hidden="true" /> Available after the first scan in a recording mode.</p>
      </div>
    )
  }

  if (load.state === 'loading') {
    return (
      <div className={styles.preview} aria-labelledby={headingId} role="region" aria-busy="true">
        {heading}
        <p className={styles.message} role="status">Loading names found last run…</p>
        <div className={styles.skeleton} data-testid="ip-hostname-preview-skeleton" aria-hidden="true">
          <span /><span /><span />
        </div>
      </div>
    )
  }

  if (load.state === 'error') {
    return (
      <div className={styles.preview} aria-labelledby={headingId} role="region">
        {heading}
        {load.notFound ? (
          <p className={styles.message} role="alert">Couldn&apos;t find this project&apos;s names. Reload the page.</p>
        ) : (
          <div className={`${formStyles.callout} ${formStyles.calloutWarning}`} role="alert">
            <AlertTriangle size={16} aria-hidden="true" />
            <span>
              Couldn&apos;t load the names found last run. The filters still apply at run time.{' '}
              <span className={styles.muted}>({load.message})</span>{' '}
              <button type="button" className="textButton" onClick={() => {
                setLoad({ state: 'loading' })
                setReload(n => n + 1)
              }}>Retry</button>
            </span>
          </div>
        )}
      </div>
    )
  }

  const { body } = load
  const t = body.totals
  const filtering = reason !== null || q.trim() !== ''

  if (t.found === 0) {
    const text = body.legacy
      ? "This project's graph predates hostname recording. Run a full scan to see names here."
      : body.lastRunMode && RECORDING_RUN.has(body.lastRunMode)
        ? 'No hostname was found on these IPs.'
        : 'No names recorded yet. Run once in Record hostnames (or higher) to fill this list.'
    return (
      <div className={styles.preview} aria-labelledby={headingId} role="region">
        {heading}
        <p className={styles.message}><Info size={14} aria-hidden="true" /> {text}</p>
      </div>
    )
  }

  const page = cursors.length - 1
  const from = page * PAGE + 1
  const to = page * PAGE + body.recorded.length
  const paged = t.found > PAGE || filtering

  return (
    <div className={styles.preview} aria-labelledby={headingId} role="region" aria-busy={busy || undefined}>
      <div className={styles.head}>
        {heading}
        <span className={styles.count} data-testid="ip-hostname-preview-count" aria-live="polite">
          would scan {t.wouldScan.toLocaleString('en-US')} of {t.found.toLocaleString('en-US')}
        </span>
      </div>
      {savedFilters && (
        <p className={styles.note}>The lists are too long to judge unsaved: these counts use the saved filters.</p>
      )}

      {paged && (
        <div className={styles.tools}>
          <div className={styles.chips} role="group" aria-label="Show names by result">
            <button
              type="button"
              className={`${styles.chip} ${reason === null ? styles.chipOn : ''}`}
              aria-pressed={reason === null}
              onClick={() => { setReason(null); restart() }}
            >
              All
            </button>
            {Object.entries(t.byReason).sort((a, b) => b[1] - a[1]).map(([code, n]) => (
              <button
                key={code}
                type="button"
                className={`${styles.chip} ${reason === code ? styles.chipOn : ''}`}
                aria-pressed={reason === code}
                onClick={() => { setReason(code); restart() }}
              >
                {code === 'scanned' ? 'would scan' : reasonWords(code)} ({n.toLocaleString('en-US')})
              </button>
            ))}
          </div>
          <label className={styles.search} htmlFor={searchId}>
            <span className={styles.srOnly}>Search names</span>
            <input
              id={searchId}
              type="search"
              className="textInput"
              placeholder="Search names"
              value={q}
              onChange={e => { setQ(e.target.value); restart() }}
            />
          </label>
        </div>
      )}

      <div className={styles.tableWrap}>
        <table className={styles.table} aria-labelledby={headingId}>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col" className={styles.wideOnly}>Seen on</th>
              <th scope="col" className={styles.wideOnly}>Sources</th>
              <th scope="col">Result</th>
            </tr>
          </thead>
          <tbody>
            {body.recorded.map(row => (
              <tr key={row.name} data-result={row.result ?? ''}>
                <td>
                  <span className={styles.name}>{row.name}</span>
                  <details className={styles.rowDetail}>
                    <summary>Details</summary>
                    <dl>
                      <dt>Seen on</dt><dd>{row.ips.join(', ') || '–'}</dd>
                      <dt>Sources</dt><dd>{sourcesText(row.sources)}</dd>
                    </dl>
                  </details>
                </td>
                <td className={styles.wideOnly}>{row.ips.join(', ') || '–'}</td>
                <td className={styles.wideOnly}>{sourcesText(row.sources)}</td>
                <td><ResultCell row={row} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {paged && (
        <div className={styles.pager}>
          <span>
            {body.recorded.length === 0
              ? `No name matches (of ${t.found.toLocaleString('en-US')})`
              : `Showing ${from.toLocaleString('en-US')}-${to.toLocaleString('en-US')} of ${t.matching.toLocaleString('en-US')}`}
          </span>
          <button
            type="button"
            className="secondaryButton"
            disabled={page === 0}
            onClick={() => setCursors(c => c.slice(0, -1))}
          >
            Previous
          </button>
          <button
            type="button"
            className="secondaryButton"
            disabled={!body.nextCursor}
            onClick={() => body.nextCursor && setCursors(c => [...c, body.nextCursor])}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}

