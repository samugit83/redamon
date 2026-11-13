'use client'

/**
 * The API usage report. Sections run errors first (they need action), then
 * usage, then the rest. Status is carried by text and an icon, never by colour
 * alone. Every provider-supplied string renders as text, and links come only
 * from the registry's dashboard/docs URLs (https only), never from a response.
 */
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, CircleAlert, CircleCheck, CircleDashed, CircleHelp, ExternalLink, Loader2, RotateCw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import type { KeyResult, Meter } from '@/lib/apiUsage/types'
import type { CollaboratorSpends } from '@/lib/authz/ownerCredentials'
import type { ApiUsageController, ShownReport } from './useApiUsageReport'
import {
  errorText, formatDateTime, formatDuration, formatRelative, keyRoleText, meterFigure, meterShare, notCheckedText,
  windowText,
} from './format'
import styles from './ApiUsageReportModal.module.css'

interface Props {
  controller: ApiUsageController
}

type SectionId = 'errors' | 'usage' | 'valid' | 'notChecked' | 'other'

const SECTIONS: { id: SectionId; title: string; outcome?: KeyResult['outcome'] }[] = [
  { id: 'errors', title: 'Errors', outcome: 'error' },
  { id: 'usage', title: 'Usage reported', outcome: 'usage' },
  { id: 'valid', title: 'Valid, no usage API', outcome: 'valid_no_usage' },
  { id: 'notChecked', title: 'Not checked', outcome: 'not_checked' },
  { id: 'other', title: 'Other' },
]
const KNOWN_OUTCOMES = new Set(['error', 'usage', 'valid_no_usage', 'not_checked'])

function safeHref(url: string | undefined): string | null {
  return url && /^https:\/\//i.test(url) ? url : null
}

function healthClass(m: Meter): string {
  const share = meterShare(m)
  if (share == null) return styles.fillOk
  if (share <= 0) return styles.fillExhausted
  return share < 0.1 ? styles.fillLow : styles.fillOk
}

function MeterRow({ m }: { m: Meter }) {
  const share = meterShare(m)
  const figure = meterFigure(m)
  return (
    <div className={styles.meter}>
      <div className={styles.meterHead}>
        <span className={styles.meterLabel}>{m.label}</span>
        <span className={styles.meterFigure}>{figure} <span className={styles.muted}>· {windowText(m.window)}</span></span>
      </div>
      {share != null && (
        <div
          className={styles.bar}
          role="progressbar"
          aria-label={`${m.label}: ${figure}`}
          aria-valuemin={0}
          aria-valuemax={m.limit ?? 0}
          aria-valuenow={m.remaining ?? Math.max(0, (m.limit ?? 0) - (m.used ?? 0))}
        >
          <div className={`${styles.fill} ${healthClass(m)}`} style={{ width: `${Math.round(share * 1000) / 10}%` }} />
        </div>
      )}
      {(m.resetsAt || m.note) && (
        <div className={styles.meterFoot}>
          {m.resetsAt && (
            <span title={m.resetsAtSource === 'computed' ? 'Computed from the provider\'s documented reset rule' : 'Reported by the provider'}>
              Resets {formatDateTime(m.resetsAt)} ({formatRelative(m.resetsAt)}){m.resetsAtSource === 'computed' ? ', estimated' : ''}
            </span>
          )}
          {m.note && <span>{m.note}</span>}
        </div>
      )}
    </div>
  )
}

function StatusBadge({ r }: { r: KeyResult }) {
  if (r.outcome === 'error') {
    return <span className={`${styles.badge} ${styles.badgeError}`}><CircleAlert size={12} aria-hidden /> {errorText(r.error?.kind).title}</span>
  }
  if (r.outcome === 'usage') {
    if (r.health === 'exhausted') return <span className={`${styles.badge} ${styles.badgeError}`}><CircleAlert size={12} aria-hidden /> Exhausted</span>
    if (r.health === 'low') return <span className={`${styles.badge} ${styles.badgeWarning}`}><AlertTriangle size={12} aria-hidden /> Low</span>
    return <span className={`${styles.badge} ${styles.badgeOk}`}><CircleCheck size={12} aria-hidden /> OK</span>
  }
  if (r.outcome === 'valid_no_usage') return <span className={`${styles.badge} ${styles.badgeOk}`}><CircleCheck size={12} aria-hidden /> Valid</span>
  if (r.outcome === 'not_checked') return <span className={`${styles.badge} ${styles.badgeMuted}`}><CircleDashed size={12} aria-hidden /> {notCheckedText(r.notCheckedReason)}</span>
  return <span className={`${styles.badge} ${styles.badgeMuted}`}><CircleHelp size={12} aria-hidden /> Unknown</span>
}

function ResultRow({ r }: { r: KeyResult }) {
  const [showAll, setShowAll] = useState(false)
  const primary = r.meters.filter(m => m.primary)
  const secondary = r.meters.filter(m => !m.primary)
  const dashboard = safeHref(r.dashboardUrl)
  const err = r.error ? errorText(r.error.kind) : null
  return (
    <li className={styles.row}>
      <div className={styles.rowHead}>
        <span className={styles.service}>{r.serviceLabel}{r.sourceName ? ` · ${r.sourceName}` : ''}</span>
        <code className={styles.hint}>{r.keyHint || '—'}</code>
        <span className={styles.role}>{keyRoleText(r)}</span>
        <StatusBadge r={r} />
      </div>

      {r.account && (r.account.plan || r.account.label || r.account.expiresAt) && (
        <div className={styles.account}>
          {r.account.plan && <span>Plan: <b>{r.account.plan}</b></span>}
          {r.account.label && <span>{r.account.label}</span>}
          {r.account.expiresAt && <span>Expires {formatDateTime(r.account.expiresAt)} ({formatRelative(r.account.expiresAt)})</span>}
        </div>
      )}

      {r.error && err && (
        <div className={styles.errorBox}>
          <div>
            <b>{err.title}</b>
            {(r.error.httpStatus || r.error.providerCode) && (
              <span className={styles.muted}> · {[r.error.httpStatus ? `HTTP ${r.error.httpStatus}` : '', r.error.providerCode ? `code ${r.error.providerCode}` : ''].filter(Boolean).join(' · ')}</span>
            )}
          </div>
          {r.error.message && <div className={styles.errorMessage}>{r.error.message}</div>}
          <div className={styles.action}>{err.action}</div>
        </div>
      )}

      {primary.length > 0 && <div className={styles.meters}>{primary.map(m => <MeterRow key={m.id} m={m} />)}</div>}
      {secondary.length > 0 && (
        <div className={styles.secondary}>
          <button type="button" className={styles.linkButton} onClick={() => setShowAll(v => !v)} aria-expanded={showAll}>
            {showAll ? 'Hide' : 'Show'} {secondary.length} more meter{secondary.length === 1 ? '' : 's'}
          </button>
          {showAll && <div className={styles.meters}>{secondary.map(m => <MeterRow key={m.id} m={m} />)}</div>}
        </div>
      )}

      {(r.notes?.length || r.warnings?.length) ? (
        <ul className={styles.notes}>
          {r.warnings?.map(w => <li key={w} className={styles.warning}><AlertTriangle size={12} aria-hidden /> {w}</li>)}
          {r.notes?.map(n => <li key={n}>{n}</li>)}
        </ul>
      ) : null}

      <div className={styles.rowFoot}>
        <span>{r.costNote}</span>
        {r.experimental && <span className={styles.tag}>experimental endpoint</span>}
        {dashboard && (
          <a href={dashboard} target="_blank" rel="noopener noreferrer" className={styles.link}>
            Dashboard <ExternalLink size={11} aria-hidden />
          </a>
        )}
      </div>
    </li>
  )
}

const SPEND_FEATURE_TEXT: Record<string, string> = {
  report_narratives: 'report narratives',
  roe_parse: 'RoE parsing',
  command_whisperer: 'command whisperer',
  multi_mute: 'multi mute',
  text_to_cypher: 'text-to-Cypher',
  scan: 'scans',
  triage_run: 'triage runs',
  agent_session: 'agent sessions',
  codefix_session: 'CodeFix sessions',
  shell_session: 'Kali terminal sessions',
}

/**
 * Step 5.6 (C1): what collaborators spent of these credentials on the projects you own, from the audit
 * record of each spend. Counts of uses, not tokens: the providers bill the usage above.
 */
function CollaboratorSpendsSection({ spends }: { spends: CollaboratorSpends }) {
  if (spends.people.length === 0) return null
  return (
    <section className={styles.section} aria-label="Spent by collaborators">
      <h3 className={styles.sectionTitle}>Spent by collaborators, last {spends.sinceDays} days ({spends.people.length})</h3>
      <p className={styles.muted}>
        Collaborators you allowed to spend your credentials on a project, and how many times each used them.
        {spends.truncated ? ' Only the most recent uses were counted.' : ''}
      </p>
      <ul className={styles.rows}>
        {spends.people.map(p => (
          <li key={p.userId} className={styles.row}>
            <div className={styles.rowHead}>
              <span className={styles.service}>{p.name || p.email || 'A deleted account'}</span>
              {p.email && p.name && <span className={styles.muted}>{p.email}</span>}
              <span>{p.total} use{p.total === 1 ? '' : 's'}</span>
            </div>
            <div className={styles.rowFoot}>
              <span>
                {Object.entries(p.byFeature).map(([f, n]) => `${SPEND_FEATURE_TEXT[f] ?? f} ${n}`).join(' · ') || 'other uses'}
              </span>
              <span>
                {p.projects.map(pr => `${pr.name} (${pr.count})`).join(', ')} · last {formatDateTime(p.lastAt)}
              </span>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}

function Chip({ count, label, tone, onClick, icon }: { count: number; label: string; tone: string; onClick: () => void; icon: ReactNode }) {
  return (
    <button type="button" className={`${styles.chip} ${tone}`} onClick={onClick} disabled={count === 0}>
      {icon} {count} {label}
    </button>
  )
}

function ReportView({ shown, stale, controller }: { shown: ShownReport; stale: boolean; controller: ApiUsageController }) {
  const { report } = shown
  const refs = useRef<Partial<Record<SectionId, HTMLElement | null>>>({})
  const results = Array.isArray(report.results) ? report.results : []
  const bySection = (s: (typeof SECTIONS)[number]) =>
    s.outcome ? results.filter(r => r.outcome === s.outcome) : results.filter(r => !KNOWN_OUTCOMES.has(r.outcome))
  const scrollTo = (id: SectionId) => refs.current[id]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  const counts = report.counts
  const runBy = controller.meta?.runBy
  const isSavedReport = shown.saved && controller.meta?.report?.finishedAt === report.finishedAt

  return (
    <div className={styles.report}>
      <p className={styles.summary}>
        Checked {formatDateTime(report.finishedAt, true)} ({formatRelative(report.finishedAt)}) · {counts?.keys ?? results.length} key{(counts?.keys ?? results.length) === 1 ? '' : 's'} · {formatDuration(report.durationMs ?? 0)}
      </p>
      {runBy && isSavedReport && <p className={styles.runBy}>Run by {runBy.name} while acting as you</p>}

      {!shown.saved && (
        <div className={`${styles.banner} ${styles.bannerError}`} role="alert">
          <CircleAlert size={14} aria-hidden />
          <span>
            Not saved: {shown.saveError ?? 'the save failed'}.{' '}
            {shown.previousFinishedAt ? <>The saved report from {formatDateTime(shown.previousFinishedAt)} is unchanged.</> : 'No report was saved.'}
          </span>
        </div>
      )}
      {stale && (
        <div className={`${styles.banner} ${styles.bannerWarning}`} role="status">
          <AlertTriangle size={14} aria-hidden />
          <span>Your keys changed since this report.</span>
          <button type="button" className={styles.linkButton} onClick={() => void controller.startCheck()} disabled={controller.running}>
            Run new check
          </button>
        </div>
      )}

      <div className={styles.chips}>
        <Chip count={counts?.errors ?? 0} label={(counts?.errors ?? 0) === 1 ? 'error' : 'errors'} tone={styles.chipError} onClick={() => scrollTo('errors')} icon={<CircleAlert size={12} aria-hidden />} />
        <Chip count={counts?.usage ?? 0} label="usage" tone={styles.chipOk} onClick={() => scrollTo('usage')} icon={<CircleCheck size={12} aria-hidden />} />
        <Chip count={counts?.validNoUsage ?? 0} label="valid, no usage API" tone={styles.chipInfo} onClick={() => scrollTo('valid')} icon={<CircleCheck size={12} aria-hidden />} />
        <Chip count={counts?.notChecked ?? 0} label="not checked" tone={styles.chipMuted} onClick={() => scrollTo('notChecked')} icon={<CircleDashed size={12} aria-hidden />} />
      </div>

      {SECTIONS.map(s => {
        const rows = bySection(s)
        if (rows.length === 0) return null
        return (
          <section key={s.id} ref={el => { refs.current[s.id] = el }} className={styles.section} aria-label={s.title}>
            <h3 className={styles.sectionTitle}>{s.title} ({rows.length})</h3>
            <ul className={styles.rows}>
              {rows.map(r => <ResultRow key={`${r.field}:${r.keyIndex}:${r.serviceId}`} r={r} />)}
            </ul>
          </section>
        )
      })}

      {controller.meta?.collaboratorSpends && <CollaboratorSpendsSection spends={controller.meta.collaboratorSpends} />}

      {report.skippedEmpty?.length > 0 && (
        <details className={styles.skipped}>
          <summary>Empty, skipped: {report.skippedEmpty.length} field{report.skippedEmpty.length === 1 ? '' : 's'}</summary>
          <p>{report.skippedEmpty.map(s => s.label).join(', ')}</p>
        </details>
      )}
    </div>
  )
}

function RunningView({ startedAt, pending }: { startedAt: string | null; pending: { id: string; label: string }[] }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  const started = startedAt ? new Date(startedAt).getTime() : now
  const elapsed = Math.max(0, Math.round((now - started) / 1000))
  return (
    <div className={styles.report} aria-busy="true">
      <p className={styles.summary}>
        <Loader2 size={14} className={styles.spin} aria-hidden /> Checking {pending.length > 0 ? `${pending.length} service${pending.length === 1 ? '' : 's'}` : 'your keys'}… {elapsed} s
      </p>
      <p className={styles.muted}>
        Closing this window does not stop the check: it finishes and is saved, and this page picks it up again.
      </p>
      {pending.length > 0 && (
        <ul className={styles.pending}>
          {pending.map(p => (
            <li key={p.id}><Loader2 size={12} className={styles.spin} aria-hidden /> {p.label}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function ApiUsageReportModal({ controller }: Props) {
  const { view, shown, close, startCheck, running, runStartedAt, stale } = controller
  const pending = controller.summary.services
  return (
    <Modal
      isOpen={view !== 'closed'}
      onClose={close}
      title="API usage report"
      size="large"
      className={styles.modal}
      headerActions={
        <button type="button" className={styles.headerButton} onClick={() => void startCheck()} disabled={running}>
          <RotateCw size={13} aria-hidden /> Run new check
        </button>
      }
    >
      {view === 'running' && <RunningView startedAt={runStartedAt} pending={pending} />}
      {view === 'report' && shown && <ReportView shown={shown} stale={stale} controller={controller} />}
    </Modal>
  )
}
