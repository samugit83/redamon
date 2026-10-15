'use client'

import { useCallback, useEffect, useState } from 'react'
import { Loader2, Plus, Play, Pause, Trash2, CalendarClock } from 'lucide-react'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { ScanQueuePanel, kindLabel } from './ScanQueuePanel'
import { usePaged, Pager } from './pagination'
import styles from './ScanScheduleTable.module.css'

interface Schedule {
  id: string
  label: string
  mode: 'once' | 'interval' | 'cron'
  runAt: string | null
  intervalMinutes: number | null
  cronExpr: string | null
  scanMode: 'new' | 'overwrite'
  enabled: boolean
  nextRunAt: string | null
  lastRunAt: string | null
}

interface Job {
  id: string
  /** full_recon for a ScanJob row; the queue kind for a finished queued job. */
  kind: string
  trigger: 'manual' | 'scheduled'
  mode: 'new' | 'overwrite' | null
  status: string
  startedAt: string | null
  finishedAt: string | null
  createdAt: string
  nodeCount: number | null
  ramReason: string | null
  /** Finding sources a full_recon could not fully re-check (circuit breakers).
   *  null = unknown/complete, N>0 = partial. */
  degradedSources: number | null
  version: { seq: number; label: string } | null
  /** Stored delta vs the previous completed run (null = first scan / untracked). */
  change: {
    newSubdomains: number
    removedSubdomains: number
    newCves: string[]
    newVulnCount: number
    newPorts: number
  } | null
}

interface AlertConfig {
  enabled: boolean
  slackConfigured: boolean
  webhookConfigured: boolean
  notifyOnNew: boolean
  notifyOnRemoved: boolean
}

function describeChange(
  c: NonNullable<Job['change']>
): string {
  const bits: string[] = []
  if (c.newSubdomains) bits.push(`+${c.newSubdomains} sub`)
  if (c.removedSubdomains) bits.push(`-${c.removedSubdomains} sub`)
  if (c.newPorts) bits.push(`+${c.newPorts} port`)
  if (c.newCves.length) bits.push(`+${c.newCves.length} CVE`)
  if (c.newVulnCount) bits.push(`+${c.newVulnCount} finding`)
  return bits.length ? bits.join(' ') : 'no changes'
}

interface ScanScheduleTableProps {
  projectId: string | null
}

function fmt(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

function duration(job: Job): string {
  if (!job.startedAt || !job.finishedAt) return '-'
  const ms = new Date(job.finishedAt).getTime() - new Date(job.startedAt).getTime()
  if (!Number.isFinite(ms) || ms < 0) return '-'
  const mins = Math.floor(ms / 60000)
  return mins >= 60 ? `${Math.floor(mins / 60)}h ${mins % 60}m` : `${mins}m`
}

function describeSchedule(s: Schedule): string {
  if (s.mode === 'once') return `once at ${fmt(s.runAt)}`
  if (s.mode === 'interval') return `every ${s.intervalMinutes} min`
  return `cron ${s.cronExpr} (UTC)`
}

/**
 * The Scans tab: a project's whole scan lifecycle, in time order.
 *
 * Scheduled scans (what will run) -> Scan queue (what is running or waiting now)
 * -> Run history (what already ran). The history is the honest record of what
 * happened: a run that could not start shows up as `failed` or `deferred_ram`
 * with the reason, rather than silently not happening.
 */
export function ScanScheduleTable({ projectId }: ScanScheduleTableProps) {
  const { alertError, dangerConfirm } = useAlertModal()
  const toast = useToast()
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [jobs, setJobs] = useState<Job[]>([])
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  // Run-history multi-select (checkboxes on the left of the history table).
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [clearing, setClearing] = useState(false)

  // create form
  const [mode, setMode] = useState<Schedule['mode']>('interval')
  const [runAt, setRunAt] = useState('')
  const [intervalMinutes, setIntervalMinutes] = useState(1440)
  const [cronExpr, setCronExpr] = useState('0 3 * * *')
  const [scanMode, setScanMode] = useState<Schedule['scanMode']>('new')
  const [label, setLabel] = useState('')

  // change-alert preferences (webhook URLs are write-only: the API only ever
  // reports whether one is stored, never the secret itself)
  const [alerts, setAlerts] = useState<AlertConfig | null>(null)
  const [slackUrl, setSlackUrl] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [savingAlerts, setSavingAlerts] = useState(false)

  // Depends on `projectId` ONLY. The alert helpers are rebuilt by their provider
  // whenever an alert opens or closes, so depending on one here would re-run the
  // effect below on every alert - and reporting a load failure through an alert
  // would then re-trigger the load that failed, in a request storm.
  const load = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setLoadError(null)
    try {
      const res = await fetch(`/api/projects/${projectId}/schedules`)
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || 'Failed to load schedules')
      setSchedules(body.schedules ?? [])
      setJobs(body.jobs ?? [])
      // Drop any selection that no longer maps to a visible row.
      setSelected(new Set())
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!projectId) return
    fetch(`/api/projects/${projectId}/alert-config`)
      .then(r => r.json().catch(() => ({})))
      .then(body => {
        if (body?.config) setAlerts(body.config as AlertConfig)
      })
      .catch(() => undefined)
  }, [projectId])

  const saveAlerts = async () => {
    if (!projectId || !alerts) return
    setSavingAlerts(true)
    try {
      const res = await fetch(`/api/projects/${projectId}/alert-config`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enabled: alerts.enabled,
          notifyOnNew: alerts.notifyOnNew,
          notifyOnRemoved: alerts.notifyOnRemoved,
          ...(slackUrl.trim() ? { slackWebhookUrl: slackUrl.trim() } : {}),
          ...(webhookUrl.trim() ? { genericWebhookUrl: webhookUrl.trim() } : {}),
        }),
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        alertError(String(body.error || 'Could not save alert preferences'), 'Change alerts')
        return
      }
      setAlerts(body.config as AlertConfig)
      setSlackUrl('')
      setWebhookUrl('')
      toast.info('Alert preferences saved')
    } finally {
      setSavingAlerts(false)
    }
  }

  const create = async () => {
    if (!projectId) return
    setCreating(true)
    try {
      const res = await fetch(`/api/projects/${projectId}/schedules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode,
          label,
          scanMode,
          ...(mode === 'once' ? { runAt: runAt ? new Date(runAt).toISOString() : null } : {}),
          ...(mode === 'interval' ? { intervalMinutes: Number(intervalMinutes) } : {}),
          ...(mode === 'cron' ? { cronExpr } : {}),
        }),
      })
      const body = await res.json()
      if (!res.ok) {
        alertError(String(body.error || 'Could not create the schedule'), 'Schedule not created')
        return
      }
      toast.info('Schedule created')
      setLabel('')
      load()
    } finally {
      setCreating(false)
    }
  }

  const patch = async (s: Schedule, data: Record<string, unknown>) => {
    if (!projectId) return
    setBusyId(s.id)
    try {
      const res = await fetch(`/api/projects/${projectId}/schedules/${s.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      const body = await res.json()
      if (!res.ok) {
        alertError(String(body.error || 'Could not update the schedule'), 'Schedule')
        return
      }
      load()
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (s: Schedule) => {
    if (!projectId) return
    const confirmed = await dangerConfirm(
      `Delete this schedule (${describeSchedule(s)})? Past runs stay in the history.`,
      'Delete schedule'
    )
    if (!confirmed) return
    setBusyId(s.id)
    try {
      const res = await fetch(`/api/projects/${projectId}/schedules/${s.id}`, { method: 'DELETE' })
      const body = await res.json()
      if (!res.ok) {
        alertError(String(body.error || 'Could not delete the schedule'), 'Schedule')
        return
      }
      toast.info('Schedule deleted')
      load()
    } finally {
      setBusyId(null)
    }
  }

  const toggleJob = (jobId: string) =>
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(jobId)) next.delete(jobId)
      else next.add(jobId)
      return next
    })

  const allSelected = jobs.length > 0 && selected.size === jobs.length
  const toggleAll = () =>
    setSelected(allSelected ? new Set() : new Set(jobs.map(j => j.id)))

  // Each table shows at most 30 rows (fixed) and pages through the rest.
  const schedPage = usePaged(schedules)
  const historyPage = usePaged(jobs)

  const deleteSelected = async () => {
    if (!projectId || selected.size === 0) return
    const n = selected.size
    const confirmed = await dangerConfirm(
      `Delete ${n} run-history ${n === 1 ? 'record' : 'records'}? This cannot be undone. ` +
      'Schedules and saved versions are not affected, and any scan still running keeps running.',
      'Delete run history'
    )
    if (!confirmed) return
    setClearing(true)
    try {
      const res = await fetch(`/api/projects/${projectId}/schedules/history`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: Array.from(selected) }),
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        alertError(String(body.error || 'Could not clear run history'), 'Run history')
        return
      }
      const deleted = body.deleted ?? n
      toast.info(`Deleted ${deleted} run ${deleted === 1 ? 'record' : 'records'}`)
      load()
    } finally {
      setClearing(false)
    }
  }

  return (
    <div className={styles.wrap}>
      <section className={styles.section}>
        <h3 className={styles.heading}>
          <CalendarClock size={14} /> Scheduled scans
          <WikiInfoButton target="ScanSchedule" title="Open the Scans wiki page" />
          {loading && <Loader2 size={12} className={styles.spinner} />}
        </h3>

        {loadError && <div className={styles.loadError}>{loadError}</div>}

        {/* Schedules run full recon ONLY: the schedule runner calls startFullScan
            and enqueues kind 'full_recon'. C-11: queue-origin jobs never appear in
            this schedule-keyed table; they are in the Scan queue section below. */}
        <p className={styles.hint}>
          Schedules run the <strong>full recon pipeline</strong> only. The other scans
          (GVM, GitHub hunt, Secret Multiscanner, supply chain, AI attack surface) and partial
          recon are started by hand from their own cards and cannot be scheduled here.
          <br />
          A scheduled run that cannot start on time is queued and runs automatically
          when resources free up; watch it in Scan queue, below.
        </p>

        <div className={styles.form}>
          <label className={styles.field}>
            When
            <select className={styles.input} value={mode} onChange={e => setMode(e.target.value as Schedule['mode'])}>
              <option value="once">Once</option>
              <option value="interval">Every N minutes</option>
              <option value="cron">Cron</option>
            </select>
          </label>
          {mode === 'once' && (
            <label className={styles.field}>
              Date/time (local)
              <input className={styles.input} type="datetime-local" value={runAt} onChange={e => setRunAt(e.target.value)} />
            </label>
          )}
          {mode === 'interval' && (
            <label className={styles.field}>
              Minutes
              <input
                className={styles.input}
                type="number"
                min={15}
                value={intervalMinutes}
                onChange={e => setIntervalMinutes(Number(e.target.value))}
              />
            </label>
          )}
          {mode === 'cron' && (
            <label className={styles.field}>
              Expression (UTC)
              <input className={styles.input} value={cronExpr} onChange={e => setCronExpr(e.target.value)} placeholder="0 3 * * *" />
            </label>
          )}
          <label className={styles.field}>
            Previous graph
            <select className={styles.input} value={scanMode} onChange={e => setScanMode(e.target.value as Schedule['scanMode'])}>
              <option value="new">Keep as a new version</option>
              <option value="overwrite">Overwrite (discard)</option>
            </select>
          </label>
          <label className={styles.field}>
            Label
            <input className={styles.input} value={label} maxLength={120} onChange={e => setLabel(e.target.value)} placeholder="optional" />
          </label>
          <button className={styles.createBtn} onClick={create} disabled={creating || !projectId}>
            {creating ? <Loader2 size={13} className={styles.spinner} /> : <Plus size={13} />}
            <span>Add schedule</span>
          </button>
        </div>

        <table className={styles.table}>
          <thead>
            <tr>
              <th>Label</th><th>Schedule</th><th>Previous graph</th>
              <th>Next run</th><th>Last run</th><th>State</th><th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {schedules.length === 0 && (
              <tr><td colSpan={7} className={styles.empty}>No scheduled scans.</td></tr>
            )}
            {schedPage.slice.map(s => (
              <tr key={s.id}>
                <td>{s.label || '-'}</td>
                <td>{describeSchedule(s)}</td>
                <td>{s.scanMode === 'new' ? 'keep as version' : 'overwrite'}</td>
                <td className={styles.muted}>{s.enabled ? fmt(s.nextRunAt) : '-'}</td>
                <td className={styles.muted}>{fmt(s.lastRunAt)}</td>
                <td>
                  <span className={s.enabled ? styles.badgeOn : styles.badgeOff}>
                    {s.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td className={styles.actions}>
                  <button
                    className={styles.iconBtn}
                    disabled={busyId === s.id}
                    onClick={() => patch(s, { enabled: !s.enabled })}
                    title={s.enabled ? 'Disable' : 'Enable'}
                  >
                    {s.enabled ? <Pause size={13} /> : <Play size={13} />}
                  </button>
                  <button
                    className={`${styles.iconBtn} ${styles.dangerBtn}`}
                    disabled={busyId === s.id}
                    onClick={() => remove(s)}
                    title="Delete schedule"
                  >
                    <Trash2 size={13} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pager page={schedPage.page} pageCount={schedPage.pageCount} total={schedPage.total} onPage={schedPage.setPage} />
      </section>

      <section className={styles.section}>
        <h3 className={styles.heading}>Change alerts</h3>
        <p className={styles.hint}>
          When a scheduled scan finishes, RedAmon diffs it against the previous
          run (new subdomains, open ports, CVEs) and posts to your Slack or
          generic webhook. URLs are stored server-side and never shown back.
        </p>
        {alerts && (
          <div className={styles.form}>
            <label className={styles.field}>
              Slack webhook (https)
              <input
                className={styles.input}
                type="url"
                value={slackUrl}
                onChange={e => setSlackUrl(e.target.value)}
                placeholder={alerts.slackConfigured ? 'stored — paste to replace' : 'https://hooks.slack.com/…'}
              />
            </label>
            <label className={styles.field}>
              Generic webhook (https)
              <input
                className={styles.input}
                type="url"
                value={webhookUrl}
                onChange={e => setWebhookUrl(e.target.value)}
                placeholder={alerts.webhookConfigured ? 'stored — paste to replace' : 'https://…'}
              />
            </label>
            <label className={styles.field}>
              Alert me
              <select
                className={styles.input}
                value={alerts.notifyOnNew ? (alerts.notifyOnRemoved ? 'all' : 'new') : 'none'}
                onChange={e => {
                  const v = e.target.value
                  setAlerts({ ...alerts, notifyOnNew: v !== 'none', notifyOnRemoved: v === 'all' })
                }}
              >
                <option value="new">New findings only</option>
                <option value="all">New + removed</option>
                <option value="none">Paused</option>
              </select>
            </label>
            <button className={styles.createBtn} onClick={saveAlerts} disabled={savingAlerts || !projectId}>
              {savingAlerts ? <Loader2 size={13} className={styles.spinner} /> : null}
              <span>Save alerts</span>
            </button>
          </div>
        )}
      </section>

      {/* Between the schedules that produce work and the history of work that
          finished: what is running or waiting right now. */}
      <ScanQueuePanel projectId={projectId} />

      <section className={styles.section}>
        <div className={styles.historyHead}>
          <h3 className={styles.heading}>Run history</h3>
          {selected.size > 0 && (
            <button className={styles.clearBtn} onClick={deleteSelected} disabled={clearing}>
              {clearing ? <Loader2 size={13} className={styles.spinner} /> : <Trash2 size={13} />}
              <span>Delete selected ({selected.size})</span>
            </button>
          )}
        </div>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.checkCol}>
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={toggleAll}
                  disabled={jobs.length === 0}
                  aria-label="Select all runs"
                  title="Select all"
                />
              </th>
              <th>Type</th><th>Trigger</th><th>Mode</th><th>Status</th><th>Version</th>
              <th>Started</th><th>Duration</th><th className={styles.num}>Nodes</th><th>Changes</th><th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {jobs.length === 0 && (
              <tr><td colSpan={11} className={styles.empty}>No scans recorded yet.</td></tr>
            )}
            {historyPage.slice.map(j => (
              <tr key={j.id} className={selected.has(j.id) ? styles.rowSelected : undefined}>
                <td className={styles.checkCol}>
                  <input
                    type="checkbox"
                    checked={selected.has(j.id)}
                    onChange={() => toggleJob(j.id)}
                    aria-label={`Select run ${j.version ? `v${j.version.seq}` : j.id}`}
                  />
                </td>
                <td>{kindLabel(j.kind)}</td>
                <td>{j.trigger}</td>
                <td>{j.mode ?? '-'}</td>
                <td>
                  <span className={
                    j.status === 'completed' ? styles.statusOk
                    : j.status === 'running' ? styles.statusRunning
                    : j.status === 'deferred_ram' ? styles.statusDeferred
                    : styles.statusBad
                  }>
                    {j.status}
                  </span>
                  {typeof j.degradedSources === 'number' && j.degradedSources > 0 && (
                    <span className={styles.partialBadge}
                      title="Some finding sources could not be fully re-checked this run">
                      partial — {j.degradedSources} source{j.degradedSources === 1 ? '' : 's'} skipped
                    </span>
                  )}
                </td>
                <td className={styles.muted}>{j.version ? `v${j.version.seq}` : '-'}</td>
                <td className={styles.muted}>{fmt(j.startedAt ?? j.createdAt)}</td>
                <td className={styles.muted}>{duration(j)}</td>
                <td className={styles.num}>{j.nodeCount ?? '-'}</td>
                <td className={styles.muted} title={j.change?.newCves?.join(', ') || undefined}>
                  {j.change ? describeChange(j.change) : '-'}
                </td>
                <td className={styles.muted}>{j.ramReason ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pager page={historyPage.page} pageCount={historyPage.pageCount} total={historyPage.total} onPage={historyPage.setPage} />
      </section>
    </div>
  )
}

export default ScanScheduleTable
