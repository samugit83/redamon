'use client'

import { useEffect, useState } from 'react'
import { Modal } from '@/components/ui'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { AuditEntryView, AuditLogDetail } from '@/lib/authz/auditReader'
import { Person, when } from './AuditRows'
import { valueText } from './auditView'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './audit.module.css'

type Loaded = { kind: 'loading' } | { kind: 'error'; message: string } | { kind: 'ready'; row: AuditLogDetail }

/**
 * One row's details. An audit log row is read again through GET /api/admin/audit/[id], which adds the
 * email it recorded and its `before` and `after` with credentials, tokens, hashes and step-up fields
 * withheld; an act-as or Fireteam row shows what the list already carries.
 */
export function AuditDetails({ entry, onClose }: { entry: AuditEntryView | null; onClose: () => void }) {
  const [loaded, setLoaded] = useState<Loaded>({ kind: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (!entry || entry.kind !== 'audit') return
    let live = true
    setLoaded({ kind: 'loading' })
    fetchJson<{ row: AuditLogDetail }>(`/api/admin/audit/${encodeURIComponent(entry.id)}`, { cache: 'no-store' }, 'Could not read the audit row')
      .then(({ row }) => { if (live) setLoaded({ kind: 'ready', row }) })
      .catch((err) => { if (live) setLoaded({ kind: 'error', message: toApiError(err, 'Could not read the audit row').message }) })
    return () => { live = false }
  }, [entry, attempt])

  if (!entry) return null
  const title = entry.kind === 'audit' ? entry.label : entry.kind === 'act_as' ? entry.label : `${entry.field} changed`
  return (
    <Modal isOpen onClose={onClose} title={title} size="large">
      <dl className={styles.facts}>
        <dt>When</dt><dd><time dateTime={entry.at}>{when(entry.at)}</time></dd>
        <dt>Row id</dt><dd><code>{entry.id}</code></dd>
        {entry.kind === 'audit' && <LogFacts entry={entry} />}
        {entry.kind === 'act_as' && (
          <>
            <dt>Admin</dt><dd><Person person={entry.admin} /></dd>
            <dt>Account acted as</dt><dd><Person person={entry.target} /></dd>
            <dt>Event</dt><dd><code>{entry.event}</code></dd>
            <dt>Reason</dt><dd>{entry.reason ?? '—'}</dd>
            <dt>Duration</dt><dd>{entry.durationMinutes !== null ? `${entry.durationMinutes} min` : '—'}</dd>
            <dt>Ended by</dt><dd>{entry.endedBy ?? '—'}</dd>
            <dt>Source</dt><dd>{entry.source}</dd>
          </>
        )}
        {entry.kind === 'fireteam' && (
          <>
            <dt>Project</dt><dd>{entry.project.name ?? '—'} <code>{entry.project.id}</code></dd>
            <dt>Setting</dt><dd><code>{entry.field}</code></dd>
            <dt>Before</dt><dd><code>{valueText(entry.oldValue)}</code></dd>
            <dt>After</dt><dd><code>{valueText(entry.newValue)}</code></dd>
            <dt>Changed by</dt><dd><Person person={entry.user} /></dd>
            <dt>Source</dt><dd>{entry.source}</dd>
          </>
        )}
      </dl>
      {entry.kind === 'audit' && (
        <section aria-label="What the row recorded" className={styles.recorded}>
          {loaded.kind === 'loading' && <p role="status">Loading what the row recorded…</p>}
          {loaded.kind === 'error' && (
            <div className={pageStyles.errorState}>
              <div className={pageStyles.error} role="alert">{loaded.message}</div>
              <button type="button" className={pageStyles.actionButton} onClick={() => setAttempt((n) => n + 1)}>Retry</button>
            </div>
          )}
          {loaded.kind === 'ready' && (
            <>
              <p className={styles.note}>
                Recorded actor email: {loaded.row.actorEmailRecorded ?? 'none'}. Credentials, tokens, hashes and step-up fields are withheld.
              </p>
              <h3 className={styles.recordedTitle}>Before</h3>
              <pre className={styles.json}>{loaded.row.before === null ? '—' : JSON.stringify(loaded.row.before, null, 2)}</pre>
              <h3 className={styles.recordedTitle}>After</h3>
              <pre className={styles.json}>{loaded.row.after === null ? '—' : JSON.stringify(loaded.row.after, null, 2)}</pre>
            </>
          )}
        </section>
      )}
    </Modal>
  )
}

function LogFacts({ entry }: { entry: Extract<AuditEntryView, { kind: 'audit' }> }) {
  return (
    <>
      <dt>Action</dt><dd>{entry.label} <code>{entry.action}</code></dd>
      <dt>Actor</dt><dd><Person person={entry.actor} /></dd>
      <dt>On behalf of</dt><dd>{entry.onBehalfOf ? <Person person={entry.onBehalfOf} /> : '—'}</dd>
      <dt>Target</dt><dd>{entry.target.account ? <Person person={entry.target.account} /> : <>{entry.target.type} {entry.target.id && <code>{entry.target.id}</code>}</>}</dd>
      <dt>Project</dt><dd>{entry.project ? <>{entry.project.name ?? '—'} <code>{entry.project.id}</code></> : '—'}</dd>
      <dt>Permission used</dt><dd>{entry.permission ? <code>{entry.permission}</code> : '—'}</dd>
      <dt>Source</dt><dd>{entry.source}</dd>
    </>
  )
}
