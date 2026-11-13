'use client'

/**
 * State and flow of "Check API usage": the saved-report metadata, the confirms
 * before a run, the POST and every answer it can get, and the pick-up of a run
 * that started elsewhere (another tab, before a reload or a tab switch). The
 * settings page renders a tab's content only while it is active, so "running"
 * always comes from the server, never from this component's memory.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useAlertModal, useToast } from '@/components/ui'
import { buildInventory, inventoryChanges, savedKeySummary, type LlmInventoryRow, type TrackedField } from '@/lib/apiUsage/inventory'
import type { ApiUsageReportV1, UserActivity } from '@/lib/apiUsage/types'
import type { CollaboratorSpends } from '@/lib/authz/ownerCredentials'
import { formatDateTime, scanKindText } from './format'
import { formatApiError, readApiError, toApiError, type ApiError } from '@/lib/apiError'
import { failureText } from '../failureText'

export interface ApiUsageMeta {
  enabled: boolean
  report: ApiUsageReportV1 | null
  running: { startedAt: string; keys: number } | null
  runBy: { id: string; name: string } | null
  activity: UserActivity | null
  tracked: TrackedField[]
  /** Step 5.6: who spent your credentials on your projects (write sharing on only). */
  collaboratorSpends?: CollaboratorSpends
}

export interface ShownReport {
  report: ApiUsageReportV1
  saved: boolean
  saveError?: string
  /** The saved report the unsaved run failed to replace. */
  previousFinishedAt?: string | null
}

export type ApiUsageView = 'closed' | 'running' | 'report'

export interface UseApiUsageReportArgs {
  userId: string | null
  /** The tab showing the controls is open: load the metadata. */
  active: boolean
  settingsDirty: boolean
  saveSettings: () => Promise<boolean>
  /** The settings as the page holds them (masked, as the settings GET returns them). */
  values: Record<string, unknown>
  /** Rotation tool -> number of saved extra keys. */
  extraKeyCounts: Record<string, number>
  llmRows: readonly (LlmInventoryRow & { name?: string })[]
  llmLabel: (providerType: string) => string
}

export const POLL_MS = 3000
export const POLL_MAX_MS = 120_000

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? '' : 's'}`
}

const P = { margin: '0 0 8px' }

function ScansWarning({ activity }: { activity: UserActivity }) {
  const scans = activity.runningScans
  const agents = activity.agentRuns
  const scanText = scans.map(s => `${scanKindText(s.kind)} on ${s.projectName}`).join(', ')
  const agentText = agents.map(a => a.projectName).join(', ')
  return (
    <p style={P}>
      {scans.length > 0 && <><b>{plural(scans.length, 'scan')} {scans.length === 1 ? 'is' : 'are'} running</b> ({scanText}){agents.length > 0 ? ' and ' : '. '}</>}
      {agents.length > 0 && <>{scans.length === 0 && <b>The agent is working </b>}{scans.length > 0 && 'the agent is working '}on {agentText}. </>}
      They use these keys; checking now can push their Shodan, Censys, FOFA, Netlas or OTX calls into rate limits, and they then skip results.
    </p>
  )
}

export function useApiUsageReport(args: UseApiUsageReportArgs) {
  const { userId, active, settingsDirty, saveSettings, values, extraKeyCounts, llmRows, llmLabel } = args
  const { confirm, alertError, alert } = useAlertModal()
  const toast = useToast()
  const [meta, setMeta] = useState<ApiUsageMeta | null>(null)
  const [view, setView] = useState<ApiUsageView>('closed')
  const [shown, setShown] = useState<ShownReport | null>(null)
  const [posting, setPosting] = useState(false)
  const [runStartedAt, setRunStartedAt] = useState<string | null>(null)
  const mounted = useRef(true)
  // A run that is refused (cooldown, busy, network) returns to what was open:
  // re-running from an open report must not close it.
  const viewRef = useRef<ApiUsageView>('closed')
  useEffect(() => {
    viewRef.current = view
  }, [view])

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  const url = userId ? `/api/users/${userId}/settings/api-usage` : null
  const tracked = meta?.tracked
  const summary = useMemo(
    () => savedKeySummary(values, extraKeyCounts, tracked ?? [], llmRows, llmLabel),
    [values, extraKeyCounts, tracked, llmRows, llmLabel],
  )
  // post() and confirmAndRun() call each other (a 409 re-asks, a confirm posts):
  // the ref always holds the current render's confirmAndRun, never a stale one.
  const confirmAndRunRef = useRef<(reportFinishedAt: string | null, activity: UserActivity | null, forceActivityPrompt?: boolean) => Promise<void>>(async () => {})
  // The confirm counts keys against the tracked list the server just returned,
  // which can be newer than this render's: read the page state through a ref.
  const inputsRef = useRef({ values, extraKeyCounts, llmRows, llmLabel })
  useEffect(() => {
    inputsRef.current = { values, extraKeyCounts, llmRows, llmLabel }
  }, [values, extraKeyCounts, llmRows, llmLabel])
  const trackedRef = useRef<TrackedField[] | undefined>(undefined)
  // Why the last refresh returned null, for the message that refuses to run on it.
  const refreshErrorRef = useRef<ApiError | null>(null)

  const refresh = useCallback(async (): Promise<ApiUsageMeta | null> => {
    if (!url) return null
    const fallback = 'Could not load the saved report state'
    try {
      const res = await fetch(url, { cache: 'no-store' })
      if (!res.ok) {
        refreshErrorRef.current = await readApiError(res, fallback)
        return null
      }
      const data = (await res.json()) as ApiUsageMeta
      trackedRef.current = data.tracked
      refreshErrorRef.current = null
      if (mounted.current) setMeta(data)
      return data
    } catch (err) {
      refreshErrorRef.current = toApiError(err, fallback)
      return null
    }
  }, [url])

  useEffect(() => {
    if (active && url) void refresh()
  }, [active, url, refresh])

  // A run in flight that this tab did not start: poll until it lands (or 2 min).
  const remoteRun = !posting ? meta?.running?.startedAt ?? null : null
  useEffect(() => {
    if (!remoteRun) return
    const until = Date.now() + POLL_MAX_MS
    let stopped = false
    let timer: ReturnType<typeof setTimeout>
    const tick = async () => {
      if (stopped) return
      const m = await refresh()
      if (!stopped && m?.running && Date.now() < until) timer = setTimeout(tick, POLL_MS)
    }
    timer = setTimeout(tick, POLL_MS)
    return () => {
      stopped = true
      clearTimeout(timer)
    }
  }, [remoteRun, refresh])

  // The run the modal was waiting on finished elsewhere: show its report.
  useEffect(() => {
    if (view === 'running' && !posting && meta && !meta.running) {
      if (meta.report) {
        setShown({ report: meta.report, saved: true })
        setView('report')
      } else {
        setView('closed')
      }
    }
  }, [view, posting, meta])

  const openReport = useCallback(() => {
    if (meta?.running) {
      setRunStartedAt(meta.running.startedAt)
      setView('running')
      return
    }
    if (!meta?.report) return
    setShown({ report: meta.report, saved: true })
    setView('report')
  }, [meta])

  const close = useCallback(() => setView('closed'), [])

  const post = useCallback(async (overwrite: boolean, ignoreRunningScans: boolean, previousFinishedAt: string | null): Promise<void> => {
    if (!url) return
    const viewBefore = viewRef.current === 'report' ? 'report' : 'closed'
    setPosting(true)
    setRunStartedAt(new Date().toISOString())
    setView('running')
    let res: Response
    let data: Record<string, unknown> = {}
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ overwrite, ignoreRunningScans }),
      })
      data = await res.json().catch(() => ({}))
    } catch {
      if (!mounted.current) return
      setPosting(false)
      setView(viewBefore)
      await alertError('The check could not reach the server. The saved report is unchanged.')
      return
    }
    if (!mounted.current) return
    setPosting(false)

    if (res.ok && data.report) {
      setShown({
        report: data.report as ApiUsageReportV1,
        saved: data.saved !== false,
        saveError: typeof data.saveError === 'string' ? data.saveError : undefined,
        previousFinishedAt,
      })
      setView('report')
      void refresh()
      return
    }

    setView(viewBefore)
    const error = typeof data.error === 'string' ? data.error : ''
    switch (error) {
      case 'report_exists': {
        // Another tab saved a report meanwhile: ask again, naming the new date.
        const fresh = await refresh()
        await confirmAndRunRef.current(typeof data.finishedAt === 'string' ? data.finishedAt : fresh?.report?.finishedAt ?? null, fresh?.activity ?? null)
        return
      }
      case 'scans_running': {
        const activity: UserActivity = {
          runningScans: Array.isArray(data.scans) ? (data.scans as UserActivity['runningScans']) : [],
          agentRuns: Array.isArray(data.agentRuns) ? (data.agentRuns as UserActivity['agentRuns']) : [],
        }
        await confirmAndRunRef.current(overwrite ? previousFinishedAt : null, activity, true)
        return
      }
      case 'cooldown': {
        const wait = Number(data.retryAfterSec) || 60
        toast.info(`A check ran less than a minute ago. Try again in ${wait} s.`)
        return
      }
      case 'run_in_progress': {
        await refresh()
        setRunStartedAt(typeof data.startedAt === 'string' ? data.startedAt : new Date().toISOString())
        setView('running')
        return
      }
      case 'disabled':
        await refresh()
        toast.warning('API usage checks are disabled on this host (API_USAGE_CHECK_ENABLED=false).')
        return
      case 'no_keys':
        toast.info('No saved keys to check.')
        return
      case 'busy':
        toast.info('Another check is running on this server. Try again in 30 s.')
        return
      case 'activity_unknown':
        await alertError('Could not tell whether scans are running, so nothing was checked.')
        return
      default:
        if (res.status === 401) {
          await alert('Your session expired. The check may still finish and be saved: log in and open Last report.', 'Session expired')
          return
        }
        // `error` is itself a code for the route's refusals (`run_failed`); a catch-all sends `code`.
        await alertError(`${formatApiError({
          reason: 'The check failed',
          code: typeof data.code === 'string' ? data.code : /^[a-z_]+$/.test(error) ? error : undefined,
          status: res.status,
        })}. The saved report is unchanged.`)
    }
  }, [url, refresh, alert, alertError, toast])

  const confirmAndRun = useCallback(async (reportFinishedAt: string | null, activity: UserActivity | null, forceActivityPrompt = false): Promise<void> => {
    const busy = !!activity && (activity.runningScans.length > 0 || activity.agentRuns.length > 0)
    if (reportFinishedAt || busy || forceActivityPrompt) {
      const inputs = inputsRef.current
      const counts = savedKeySummary(inputs.values, inputs.extraKeyCounts, trackedRef.current ?? [], inputs.llmRows, inputs.llmLabel)
      const keyCount = counts.keys
      const serviceCount = counts.services.length
      const body: ReactNode = (
        <>
          {reportFinishedAt && (
            <p style={P}>The report from <b>{formatDateTime(reportFinishedAt)}</b> will be replaced. The previous report cannot be recovered.</p>
          )}
          <p style={P}>This calls {plural(serviceCount, 'service')} ({plural(keyCount, 'key')}). It calls only account and usage endpoints and never runs a search.</p>
          {busy && activity && <ScansWarning activity={activity} />}
        </>
      )
      const ok = await confirm(
        body,
        reportFinishedAt ? 'Replace the saved report?' : 'Scans are running',
        { confirmLabel: 'Run new check', cancelLabel: reportFinishedAt ? 'Keep current report' : 'Cancel', size: 'default' },
      )
      if (!ok) return
    }
    await post(!!reportFinishedAt, busy, reportFinishedAt)
  }, [confirm, post])
  useEffect(() => {
    confirmAndRunRef.current = confirmAndRun
  }, [confirmAndRun])

  const startCheck = useCallback(async () => {
    if (!url || posting) return
    if (settingsDirty) {
      const ok = await confirm('You have unsaved key changes. The check uses the saved keys.', 'Save first?', { confirmLabel: 'Save and check' })
      if (!ok) return
      if (!(await saveSettings())) return
    }
    const fresh = await refresh()
    if (!fresh) {
      await alertError(`${failureText('Could not load the saved report state', refreshErrorRef.current)}, so nothing was checked. Try again.`)
      return
    }
    if (!fresh.enabled) {
      toast.warning('API usage checks are disabled on this host (API_USAGE_CHECK_ENABLED=false).')
      return
    }
    if (fresh.running) {
      setRunStartedAt(fresh.running.startedAt)
      setView('running')
      return
    }
    await confirmAndRun(fresh.report?.finishedAt ?? null, fresh.activity)
  }, [url, posting, settingsDirty, confirm, saveSettings, refresh, alertError, toast, confirmAndRun])

  // Unsaved edits are not "your keys changed": the report is about the saved keys.
  const stale = useMemo(() => {
    if (settingsDirty || !shown?.report?.inventory || !tracked) return false
    const current = buildInventory(values, extraKeyCounts, tracked, llmRows)
    return inventoryChanges(shown.report.inventory, current).length > 0
  }, [settingsDirty, shown, tracked, values, extraKeyCounts, llmRows])

  const running = posting || !!meta?.running
  return {
    meta,
    summary,
    stale,
    view,
    shown,
    running,
    runStartedAt: posting ? runStartedAt : meta?.running?.startedAt ?? runStartedAt,
    startCheck,
    openReport,
    close,
    refresh,
  }
}

export type ApiUsageController = ReturnType<typeof useApiUsageReport>
