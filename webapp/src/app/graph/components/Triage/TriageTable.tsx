'use client'

/**
 * Finding triage: verdicts, and the mute / unmute suppression control.
 *
 * Two tables rather than one list with a filter, because they answer different
 * questions. The Findings table is the working set an operator is triaging; the
 * Muted table is the audit trail of what they decided to stop looking at, and it
 * is the ONLY place in the product where a suppressed finding is visible at all.
 * Everything else -- the graph, the agent, analytics, reports -- has them
 * filtered out, which is the point of the feature.
 *
 * Mute is deliberately a two-step action with a confirm: it changes what the AI
 * agent can see for the whole project, so it is not a click to make by accident.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Loader2, EyeOff, Eye, Play } from 'lucide-react'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import { useCypherFixTriageWS } from '@/hooks/useCypherFixTriageWS'
import { TriageProgress, PHASE_LABELS } from '../CypherFixTab/TriageProgress/TriageProgress'
import styles from './TriageTable.module.css'

export interface TriageFinding {
  id: string
  label: string
  name: string
  severity: string
  source: string
  location?: string
  host?: string
  triage_status: TriageStatus
  triage_confidence: number | null
  triage_reason: string | null
  triage_source?: string
  triage_cluster_id?: string | null
  triage_priority_score?: number | null
  triage_signals?: string[]
  updated_at?: string | null
}

export interface MutedFinding {
  id: string
  label: string
  name: string
  severity: string
  source: string
  muted_at: string | null
  muted_by: string
  muted_reason: string
  triage_status: TriageStatus
  triage_reason: string | null
}

export type TriageStatus =
  | 'confirmed'
  | 'likely_noise'
  | 'needs_verification'
  | 'unreviewed'

/**
 * Priority band derived from the deterministic score. Mirrors
 * scoring.py::tier_for_score -- keep these thresholds in sync with _TIER_BANDS
 * there (Critical 1000 / High 500 / Medium 150 / Low 40, else Info). The old
 * real/noise verdict chips (Confirmed / Likely noise / Needs verification /
 * Unreviewed) are gone: the new system ranks by exploitability and exposure, so
 * the filter matches the ranking rather than a verdict we no longer produce.
 */
export type TriageTier = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'

const TIER_ORDER: TriageTier[] = ['Critical', 'High', 'Medium', 'Low', 'Info']
const TIER_BANDS: [number, TriageTier][] = [
  [1000, 'Critical'],
  [500, 'High'],
  [150, 'Medium'],
  [40, 'Low'],
]

function tierForScore(score: number | null | undefined): TriageTier {
  const s = score ?? -1
  for (const [threshold, tier] of TIER_BANDS) if (s >= threshold) return tier
  return 'Info'
}

/** Worst-first, so the operator's attention lands where it should. */
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', '']

function severityRank(sev: string): number {
  const i = SEVERITY_ORDER.indexOf((sev || '').toLowerCase())
  return i === -1 ? SEVERITY_ORDER.length : i
}

function fmtWhen(iso: string | null): string {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '-' : d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

interface TriageTableProps {
  projectId: string | null
}

export function TriageTable({ projectId }: TriageTableProps) {
  const [findings, setFindings] = useState<TriageFinding[]>([])
  const [muted, setMuted] = useState<MutedFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [showMuted, setShowMuted] = useState(false)
  /** Server-side total, which can exceed what the query returned. */
  const [total, setTotal] = useState(0)
  const [tierFilter, setTierFilter] = useState<TriageTier | 'all'>('all')
  const [showProgress, setShowProgress] = useState(false)
  /** True when the run was launched from this mount, rather than re-attached. */
  const startedHereRef = useRef(false)

  const { userId } = useProject()
  const { alertError, dangerConfirm } = useAlertModal()
  const toast = useToast()

  const load = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setError(null)
    try {
      const [f, m] = await Promise.all([
        fetch(`/api/triage/findings?projectId=${encodeURIComponent(projectId)}`),
        fetch(`/api/triage/muted?projectId=${encodeURIComponent(projectId)}`),
      ])
      if (!f.ok) throw new Error((await f.json().catch(() => ({}))).error || `Findings: ${f.status}`)
      if (!m.ok) throw new Error((await m.json().catch(() => ({}))).error || `Muted: ${m.status}`)
      const findingsBody = await f.json()
      setFindings(findingsBody.findings ?? [])
      setTotal(findingsBody.total ?? (findingsBody.findings ?? []).length)
      setMuted((await m.json()).findings ?? [])
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load Priority Board data')
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    void load()
  }, [load])

  // Triage is a run of the CypherFix pipeline (collect -> classify -> correlate
  // -> remediate), driven over the same WebSocket the CypherFix page uses. This
  // tab launches it and reloads the verdict table when it finishes, so an
  // operator never has to leave to /cypherfix to classify what a scan found.
  const triage = useCypherFixTriageWS({
    userId: userId || '',
    projectId: projectId || '',
    enabled: !!projectId && !!userId,
    // Connect as soon as the tab opens, not just when Run is pressed: a run
    // started here keeps going after you navigate away, and re-attaching is the
    // only way to see it again.
    autoConnect: true,
    onComplete: () => { void load() },
  })

  // A run outlives the tab that started it, so on (re)connect the server
  // replays a run already in progress. Surfacing that matters -- otherwise a
  // live run is invisible -- but HOW depends on who started it.
  //
  // The full panel is a blocking overlay. That is right when you just pressed
  // Run and are watching it work; it is wrong when you merely came back to the
  // tab during a long background run, because it hides the findings table you
  // came to read. Re-attached runs get the inline banner instead.
  useEffect(() => {
    if (triage.status === 'running' && startedHereRef.current) setShowProgress(true)
  }, [triage.status])

  /** A run in flight that is NOT being shown in the blocking panel. */
  const backgroundRun = triage.status === 'running' && !showProgress

  const runTriage = useCallback(async () => {
    if (!projectId || !userId) return
    const ok = await dangerConfirm(
      'Rank the findings on this project?\n\n' +
        'Every finding is scored and ranked by exploitability and exposure, ' +
        'worst first. The AI then writes a short "why it matters" for the top ' +
        'findings and generates remediations. It uses the model set in Project ' +
        'Settings -> CypherFix & Priority Board LLM Model. Nothing is muted ' +
        'automatically -- muting stays a manual action.',
      'Rank findings',
      { confirmLabel: 'Rank findings' },
    )
    if (!ok) return
    startedHereRef.current = true
    setShowProgress(true)
    triage.startTriage()
  }, [projectId, userId, dangerConfirm, triage])

  const closeProgress = useCallback(() => {
    setShowProgress(false)
    // Only drop the socket once there is nothing left to stream. Disconnecting
    // mid-run no longer cancels anything, but it would stop the progress this
    // view is about to want again. Dismissing the panel is not "stop the run" --
    // that is the Stop button.
    if (triage.status !== 'running' && triage.status !== 'connecting') {
      triage.disconnect()
    }
    if (triage.status === 'completed') void load()
  }, [triage, load])

  const mute = useCallback(
    async (finding: TriageFinding) => {
      if (!projectId) return
      const ok = await dangerConfirm(
        `Mute "${finding.name || finding.id}"?\n\n` +
          'It will be hidden from the graph, from reports, and from the AI agent, ' +
          'which will no longer be able to see or reason about it. You can restore ' +
          'it from the Muted table at any time.',
        'Mute finding',
        { confirmLabel: 'Mute' },
      )
      if (!ok) return

      setBusyId(finding.id)
      try {
        const res = await fetch('/api/triage/mute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectId, nodeId: finding.id }),
        })
        const body = await res.json().catch(() => ({}))
        if (!res.ok || !body.muted) {
          throw new Error(body.error || 'The finding could not be muted.')
        }
        // Move it across locally rather than refetching both tables: the graph
        // write already succeeded, and a round trip here just makes it feel slow.
        setFindings(prev => prev.filter(f => f.id !== finding.id))
        setMuted(prev => [
          {
            id: finding.id,
            label: finding.label,
            name: finding.name,
            severity: finding.severity,
            source: finding.source,
            muted_at: new Date().toISOString(),
            muted_by: 'you',
            muted_reason: '',
            triage_status: finding.triage_status,
            triage_reason: finding.triage_reason,
          },
          ...prev,
        ])
        toast.success('Finding muted. It is now hidden from the agent.')
      } catch (e) {
        await alertError(e instanceof Error ? e.message : 'Mute failed', 'Mute finding')
      } finally {
        setBusyId(null)
      }
    },
    [projectId, dangerConfirm, alertError, toast],
  )

  const unmute = useCallback(
    async (finding: MutedFinding) => {
      if (!projectId) return
      setBusyId(finding.id)
      try {
        const res = await fetch('/api/triage/unmute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectId, nodeId: finding.id }),
        })
        const body = await res.json().catch(() => ({}))
        if (!res.ok || !body.unmuted) {
          throw new Error(body.error || 'The finding could not be restored.')
        }
        setMuted(prev => prev.filter(f => f.id !== finding.id))
        // Refetch the findings side: unmute restores relationships and verdict
        // fields this component never had, so a locally-built row would be thin.
        void load()
        toast.success('Finding restored.')
      } catch (e) {
        await alertError(e instanceof Error ? e.message : 'Unmute failed', 'Restore finding')
      } finally {
        setBusyId(null)
      }
    },
    [projectId, alertError, toast, load],
  )

  const visible = useMemo(() => {
    const rows = tierFilter === 'all'
      ? findings
      : findings.filter(f => tierForScore(f.triage_priority_score) === tierFilter)
    // Rank by the deterministic priority score, worst first. The server already
    // returns them in this order; this mirrors it so a client-side filter keeps
    // the ranking. Severity is only the tiebreak among equal scores.
    return [...rows].sort((a, b) => {
      const p = (b.triage_priority_score ?? -1) - (a.triage_priority_score ?? -1)
      if (p !== 0) return p
      return severityRank(a.severity) - severityRank(b.severity)
    })
  }, [findings, tierFilter])

  // The query is capped server-side. Saying so is not cosmetic: without it a
  // truncated list reads as the complete set of findings to triage, and an
  // operator would work through it believing nothing was left.
  const truncated = total > findings.length

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of findings) {
      const t = tierForScore(f.triage_priority_score)
      c[t] = (c[t] || 0) + 1
    }
    return c
  }, [findings])

  if (!projectId) {
    return <div className={styles.empty}>Select a project to rank its findings.</div>
  }

  if (loading && findings.length === 0 && muted.length === 0) {
    return (
      <div className={styles.empty}>
        <Loader2 className={styles.spin} size={18} /> Loading findings...
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.error}>
        <p>{error}</p>
        <button className={styles.button} onClick={() => void load()}>Retry</button>
      </div>
    )
  }

  return (
    <div className={styles.wrap}>
      <div className={styles.toolbar}>
        <div className={styles.filters}>
          <button
            className={`${styles.chip} ${tierFilter === 'all' ? styles.chipActive : ''}`}
            onClick={() => setTierFilter('all')}
          >
            All ({findings.length}{truncated ? ` of ${total}` : ''})
          </button>
          {TIER_ORDER.map(tier => (
            <button
              key={tier}
              className={`${styles.chip} ${tierFilter === tier ? styles.chipActive : ''}`}
              onClick={() => setTierFilter(tier)}
            >
              {tier} ({counts[tier] ?? 0})
            </button>
          ))}
        </div>
        <div className={styles.actions}>
          <WikiInfoButton target="PriorityBoard" />
          <button
            className={styles.button}
            onClick={() => void runTriage()}
            disabled={!projectId || !userId || showProgress}
          >
            <Play size={14} /> Rank Findings
          </button>
          <button className={styles.button} onClick={() => setShowMuted(v => !v)}>
            {showMuted ? <Eye size={14} /> : <EyeOff size={14} />}
            {showMuted ? 'Hide' : 'Show'} muted ({muted.length})
          </button>
        </div>
      </div>

      {backgroundRun && (
        <div className={styles.runBanner} role="status">
          <Loader2 className={styles.spin} size={13} />
          <span className={styles.runBannerText}>
            Priority Board running
            {triage.currentPhase ? ` — ${PHASE_LABELS[triage.currentPhase] ?? triage.currentPhase}` : ''}
            . The ranking fills in below as it goes; you can leave this page.
          </span>
          <button className={styles.runBannerBtn} onClick={() => setShowProgress(true)}>
            Details
          </button>
          <button className={styles.runBannerBtn} onClick={triage.stopTriage}>
            Stop
          </button>
        </div>
      )}

      {truncated && (
        <div className={styles.truncationNotice} role="status">
          Showing the {findings.length} highest-severity findings of {total}. Mute or resolve
          some, or narrow by verdict, to see the rest.
        </div>
      )}

      {visible.length === 0 ? (
        <div className={styles.empty}>
          {findings.length === 0
            ? 'No findings in scope yet. Run a scan, then rank the findings to see what matters most.'
            : 'No findings match this filter.'}
        </div>
      ) : (
        <div className={styles.tableScroll}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>#</th>
                <th>Finding</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Signals</th>
                <th>Where</th>
                <th>Why</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {visible.map((f, i) => {
                return (
                  <tr key={f.id}>
                    <td className={styles.rank}>
                      {i + 1}
                      {f.triage_source === 'human' && (
                        <span className={styles.humanTag} title="Set by a person; the AI will not overwrite it">
                          human
                        </span>
                      )}
                    </td>
                    <td className={styles.name}>{f.name || f.id}</td>
                    <td>{f.label}</td>
                    <td>
                      <span className={`${styles.sev} ${styles[(f.severity || '').toLowerCase()] ?? ''}`}>
                        {f.severity || '-'}
                      </span>
                    </td>
                    <td className={styles.signalsCell}>
                      <div className={styles.signals}>
                        {(f.triage_signals ?? []).length === 0
                          ? <span className={styles.confidence}>-</span>
                          : (f.triage_signals ?? []).map(sig => (
                              <span key={sig} className={styles.signalChip} title={sig}>
                                {sig.replace(/_/g, ' ')}
                              </span>
                            ))}
                      </div>
                    </td>
                    <td className={styles.where}>{f.host || f.location || '-'}</td>
                    <td className={styles.reason}>{f.triage_reason || '-'}</td>
                    <td>
                      <button
                        className={styles.muteButton}
                        disabled={busyId === f.id}
                        onClick={() => void mute(f)}
                        title="Hide this finding from the graph, reports and the AI agent"
                      >
                        {busyId === f.id ? <Loader2 className={styles.spin} size={13} /> : <EyeOff size={13} />}
                        Mute
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {showMuted && (
        <div className={styles.mutedSection}>
          <h3 className={styles.mutedHeading}>
            Muted findings ({muted.length})
          </h3>
          <p className={styles.mutedNote}>
            These are hidden from the graph, from reports and from the AI agent. This table is the
            only place they are still visible.
          </p>
          {muted.length === 0 ? (
            <div className={styles.empty}>Nothing has been muted in this project.</div>
          ) : (
            <div className={styles.tableScroll}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Muted</th>
                    <th>By</th>
                    <th>Reason</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {muted.map(f => (
                    <tr key={f.id} className={styles.mutedRow}>
                      <td className={styles.name}>{f.name || f.id}</td>
                      <td>{f.label}</td>
                      <td>
                        <span className={`${styles.sev} ${styles[(f.severity || '').toLowerCase()] ?? ''}`}>
                          {f.severity || '-'}
                        </span>
                      </td>
                      <td>{fmtWhen(f.muted_at)}</td>
                      <td>{f.muted_by || '-'}</td>
                      <td className={styles.reason}>{f.muted_reason || f.triage_reason || '-'}</td>
                      <td>
                        <button
                          className={styles.unmuteButton}
                          disabled={busyId === f.id}
                          onClick={() => void unmute(f)}
                          title="Make this finding visible again everywhere"
                        >
                          {busyId === f.id ? <Loader2 className={styles.spin} size={13} /> : <Eye size={13} />}
                          Restore
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <TriageProgress
        isVisible={showProgress}
        title="Priority Board"
        phase={triage.currentPhase}
        progress={triage.progress}
        findings={triage.findings}
        thinking={triage.thinking}
        error={triage.error}
        status={triage.status}
        onClose={closeProgress}
        onStop={triage.stopTriage}
      />
    </div>
  )
}

export default TriageTable
