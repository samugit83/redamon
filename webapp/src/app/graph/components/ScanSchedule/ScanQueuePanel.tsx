'use client'

/**
 * Every in-flight scan for the open project, whatever started it, in one table.
 *
 * Three sources behind `GET /api/system/jobs`, because no single one sees them
 * all: the JobQueue (only queued work), ScanJob rows (only full recon) and the
 * orchestrator's live state (every kind, but lost on its restart). Rows carry a
 * `source` so the UI knows which ones it can act on - only a queue row can be
 * canceled or re-confirmed; the rest are stopped from the toolbar.
 *
 * Scope: this project in full, the operator's other projects as a count only. With sharing in force
 * the projects shared with the operator are counted apart (`sharedProjectIds`), and a queued job is
 * cancelled or re-confirmed only by someone whose access reaches recon:schedule (step 4.11).
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Loader2, Activity } from 'lucide-react'
import { useAlertModal } from '@/components/ui'
import { usePaged, Pager } from './pagination'
import { readApiError, toApiError, type ApiError } from '@/lib/apiError'
import { useRefusal } from '@/hooks/useRefusal'
import styles from './ScanScheduleTable.module.css'

export interface QueueJob {
  id: string
  projectId: string
  projectName: string
  kind: string
  status: string
  blockedReason: string
  error: string
  /** Extra identity for a run-keyed kind (the partial-recon tool, the AI tool). */
  detail?: string
  enqueuedAt: string
  startedAt: string | null
  /** 'queue': a JobQueue row, the only source that can be canceled or re-confirmed.
   *  'scan':  a running ScanJob (full recon).
   *  'live':  the orchestrator is holding it right now, any kind. */
  source: 'queue' | 'scan' | 'live'
}

interface ActivityPayload {
  mine: { running: QueueJob[]; queued: QueueJob[]; needsReview: QueueJob[]; recent: QueueJob[] }
  others: { queued: number; running: number; needsReview: number }
  /** With sharing in force: the listed projects shared with the operator, not theirs. */
  sharedProjectIds?: string[]
}

const KIND_LABEL: Record<string, string> = {
  full_recon: 'Full recon',
  partial_recon: 'Partial recon',
  gvm: 'GVM',
  github_hunt: 'GitHub hunt',
  trufflehog: 'Secret Multiscanner',
  supply_chain: 'Supply chain',
  supply_chain_repo: 'Supply chain (repo)',
  ai_attack: 'AI attack surface',
}

const POLL_MS = 8000

/** Shared with the Run history table so one scan kind reads the same in both. */
export function kindLabel(k: string) { return KIND_LABEL[k] ?? k }

function fmt(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

function statusClass(status: string): string {
  // 'starting' and 'stopping' come from the orchestrator's live state.
  if (status === 'running' || status === 'dispatching' || status === 'starting') return styles.statusRunning
  if (status === 'queued' || status === 'paused' || status === 'stopping') return styles.statusDeferred
  if (status === 'needs_review') return styles.statusBad
  return styles.badgeOff
}

/** Everything that is not waiting in the queue is, to an operator, in flight. */
function isRunning(status: string): boolean {
  return status !== 'queued' && status !== 'needs_review'
}

export function ScanQueuePanel({ projectId }: { projectId: string | null }) {
  const [data, setData] = useState<ActivityPayload | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  // Both queue actions ask recon:schedule on the job's project (route manifest).
  const queueRefusal = useRefusal('recon:schedule', projectId)?.text ?? null

  const refresh = useCallback(async () => {
    try {
      const res = await fetch('/api/system/jobs')
      if (!res.ok) { setError((await readApiError(res, 'Could not load scan activity.')).message); return }
      setData(await res.json())
      setError(null)
    } catch (err) {
      setError(toApiError(err, 'Could not load scan activity.').message)
    }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, POLL_MS)
    return () => clearInterval(t)
  }, [refresh])

  const { confirm } = useAlertModal()
  const act = useCallback(async (id: string, action: 'cancel' | 'reconfirm') => {
    setBusyId(id)
    try {
      const failure = `Could not ${action} the job.`
      let res = await fetch(`/api/job-queue/${id}/${action}`, { method: 'POST' })
      let refusal: ApiError | null = res.ok ? null : await readApiError(res, failure)
      // An AI attack launch needs the RoE confirmed again once settings changed.
      if (refusal?.code === 'roe_confirmation_required') {
        const ok = await confirm(
          'The project settings changed since this AI attack scan was queued. Confirm that its targets are ' +
          'within the current Rules of Engagement and that you authorise the launch.',
          'Confirm the Rules of Engagement',
          { confirmLabel: 'Confirm and re-queue' },
        )
        if (!ok) {
          await refresh()
          return
        }
        res = await fetch(`/api/job-queue/${id}/${action}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ roeConfirmed: true }),
        })
        refusal = res.ok ? null : await readApiError(res, failure)
      }
      if (refusal) {
        setError(refusal.message)
      } else {
        await refresh()
      }
    } catch (err) {
      setError(toApiError(err, `Could not ${action} the job.`).message)
    } finally {
      setBusyId(null)
    }
  }, [refresh, confirm])

  const { here, elsewhere, shared } = useMemo(() => {
    const mine = data?.mine
    const all = [...(mine?.running ?? []), ...(mine?.needsReview ?? []), ...(mine?.queued ?? [])]
    // Newest created on top: sort by enqueue/start time descending.
    const byNewest = (a: QueueJob, b: QueueJob) =>
      new Date(b.enqueuedAt).getTime() - new Date(a.enqueuedAt).getTime()
    const sharedIds = new Set(data?.sharedProjectIds ?? [])
    const notHere = all.filter(j => j.projectId !== projectId)
    return {
      here: all.filter(j => j.projectId === projectId).sort(byNewest),
      elsewhere: notHere.filter(j => !sharedIds.has(j.projectId)),
      shared: notHere.filter(j => sharedIds.has(j.projectId)),
    }
  }, [data, projectId])

  const elsewhereRunning = elsewhere.filter(j => isRunning(j.status)).length
  const elsewhereQueued = elsewhere.length - elsewhereRunning
  const sharedRunning = shared.filter(j => isRunning(j.status)).length
  const sharedQueued = shared.length - sharedRunning
  const others = data?.others

  // At most 30 rows (fixed); a big org batch pages through the rest.
  const herePage = usePaged(here)

  return (
    <section className={styles.section}>
      <h3 className={styles.heading}>
        <Activity size={14} /> Scan queue
        {!data && !error && <Loader2 size={12} className={styles.spinner} />}
      </h3>

      {error && <div className={styles.loadError}>{error}</div>}

      <table className={styles.table}>
        <thead>
          <tr>
            <th>Scan</th><th>Status</th><th>Since</th><th>Reason</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {here.length === 0 && (
            <tr><td colSpan={5} className={styles.empty}>Nothing running or queued for this project.</td></tr>
          )}
          {herePage.slice.map(j => (
            <tr key={`${j.source}:${j.id}`}>
              <td>{kindLabel(j.kind)}</td>
              <td><span className={statusClass(j.status)}>{j.status.replace('_', ' ')}</span></td>
              <td className={styles.muted}>{fmt(j.startedAt ?? j.enqueuedAt)}</td>
              <td className={styles.muted}>{j.detail || j.blockedReason || j.error || '-'}</td>
              <td className={styles.actions}>
                {/* A 'scan' row has no queue row behind it: stop it from the toolbar. */}
                {j.source === 'queue' && j.status === 'needs_review' && (
                  <button
                    className={`${styles.iconBtn} ${styles.textBtn}`}
                    disabled={busyId === j.id || !!queueRefusal}
                    onClick={() => act(j.id, 'reconfirm')}
                    title={queueRefusal ?? 'Run it again. A job is held when the project settings changed after it was ' +
                      'queued (it then runs with the current settings), or when its start got no ' +
                      'answer (check first that the scan did not start).'}
                  >
                    Re-confirm
                  </button>
                )}
                {j.source === 'queue' && !isRunning(j.status) && (
                  <button
                    className={`${styles.iconBtn} ${styles.textBtn} ${styles.dangerBtn}`}
                    disabled={busyId === j.id || !!queueRefusal}
                    onClick={() => act(j.id, 'cancel')}
                    title={queueRefusal ?? 'Cancel this queued job'}
                  >
                    Cancel
                  </button>
                )}
                {j.source !== 'queue' && <span className={styles.muted}>-</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager page={herePage.page} pageCount={herePage.pageCount} total={herePage.total} onPage={herePage.setPage} />

      {(elsewhere.length > 0 || shared.length > 0 || (others && others.running + others.queued + others.needsReview > 0)) && (
        <p className={styles.hint}>
          {elsewhere.length > 0 && (
            <>Your other projects: {elsewhereRunning} running, {elsewhereQueued} queued. </>
          )}
          {shared.length > 0 && (
            <>Projects shared with you: {sharedRunning} running, {sharedQueued} queued. </>
          )}
          {others && others.running + others.queued + others.needsReview > 0 && (
            <>Other users: {others.running} running, {others.queued} queued
              {others.needsReview ? `, ${others.needsReview} awaiting review` : ''}.</>
          )}
        </p>
      )}
    </section>
  )
}

export default ScanQueuePanel
