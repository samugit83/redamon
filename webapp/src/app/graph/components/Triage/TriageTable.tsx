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
import { Loader2, EyeOff, Eye, Check, X } from 'lucide-react'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import { useCypherFixTriageWS } from '@/hooks/useCypherFixTriageWS'
import { TriageProgress, PHASE_LABELS } from '../CypherFixTab/TriageProgress/TriageProgress'
import { TriageRunButton } from '@/components/triage/TriageRunButton'
import styles from './TriageTable.module.css'

export interface TriageFinding {
  id: string
  label: string
  name: string
  severity: string
  source: string
  location?: string
  host?: string
  /** Which of the board's four sections this row belongs in. Decided by the
   *  server so the client cannot disagree with it. */
  section?: number
  triage_state?: string
  triage_status: TriageStatus
  triage_confidence: number | null
  triage_reason: string | null
  triage_source?: string
  triage_tier?: string
  triage_tier_rule?: string
  triage_factors?: string | null
  triage_math_score?: number | null
  triage_priority_score?: number | null
  triage_signals?: string[]
  triage_group_key?: string
  triage_run_id?: string
  triage_ai_verdict?: string
  triage_ai_quote?: string | null
  triage_ai_model?: string
  triage_fix_lever?: string
  triaged_at?: string | null
  updated_at?: string | null
}

/** The four board sections, in the order they are always shown. */
export const SECTION_RANKED = 0
export const SECTION_NOT_TRIAGED = 1
export const SECTION_FALSE_POSITIVE = 2
export const SECTION_RESOLVED = 3

export const SECTION_TITLES: Record<number, string> = {
  [SECTION_RANKED]: 'Ranked',
  [SECTION_NOT_TRIAGED]: 'Not triaged yet',
  [SECTION_FALSE_POSITIVE]: 'Likely false positive, check me',
  [SECTION_RESOLVED]: 'Resolved',
}

export const SECTION_BLURBS: Record<number, string> = {
  [SECTION_RANKED]: 'Scored by the last triage run, most urgent first.',
  [SECTION_NOT_TRIAGED]:
    'Found since the last run, or never triaged. Run triage to rank them.',
  [SECTION_FALSE_POSITIVE]:
    'The AI or a person judged these not real. They are not muted or deleted, ' +
    'and one click puts them back.',
  [SECTION_RESOLVED]:
    'Fixed, gone, or a credential that no longer works. Kept so they can come ' +
    'back if a scan finds them again.',
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

export type TriageStatus = 'confirmed' | 'likely_noise' | 'unreviewed'

/**
 * The four tiers the score model assigns. These are no longer score BANDS: the
 * tier is decided by fixed rules on the facts, and the score is built from it
 * (25 x tier + 25 x risk), so reading the tier back off the number would be
 * backwards. The server sends `triage_tier`; this is only the fallback for a
 * row from before the model existed.
 *
 * Severity bands are deliberately gone from this filter. "Critical" described
 * how bad a finding COULD be; "Act now" describes what to do about this one,
 * on this project, given what is actually reachable.
 */
export type TriageTier = 'T1' | 'T2' | 'T3' | 'T4'

const TIER_ORDER: TriageTier[] = ['T1', 'T2', 'T3', 'T4']

export const TIER_LABELS: Record<TriageTier, string> = {
  T1: 'Act now',
  T2: 'Act soon',
  T3: 'Plan',
  T4: 'Track',
}

/** Mirrors score_model.py: 25 x tier_level + 25 x risk. */
function tierForScore(score: number | null | undefined): TriageTier {
  const s = score ?? -1
  if (s >= 75) return 'T1'
  if (s >= 50) return 'T2'
  if (s >= 25) return 'T3'
  return 'T4'
}

function tierOf(f: TriageFinding): TriageTier {
  const stored = (f.triage_tier || '') as TriageTier
  return TIER_ORDER.includes(stored) ? stored : tierForScore(f.triage_priority_score)
}

/** What the AI concluded, in words an operator can act on. */
const VERDICT_LABELS: Record<string, string> = {
  real: 'Real',
  doubtful: 'Doubtful',
  false_positive: 'Likely false positive',
  unclear: 'Unclear',
  not_reviewed: 'Not reviewed',
}

interface Factor {
  value: number
  evidence: string
}

/** One section's title, count and blurb, on a single line.
 *
 *  The FIRST section's header is rendered into the toolbar's empty left slot
 *  rather than above its own table, which buys back another row of vertical
 *  space on a board that is mostly table. Later sections keep theirs in place,
 *  because there is no toolbar to share.
 */
function SectionHead({ sectionKey, count }: { sectionKey: number; count: number }) {
  return (
    <div className={styles.sectionHead}>
      <h3 className={styles.sectionHeading}>
        {SECTION_TITLES[sectionKey]}
        <span className={styles.sectionCount}>{count}</span>
      </h3>
      <p className={styles.sectionBlurb}>{SECTION_BLURBS[sectionKey]}</p>
    </div>
  )
}

/** The four factors, parsed from the JSON the server stores. Never throws: a
 *  row written by an older run simply has no breakdown to show. */
function parseFactors(raw: string | null | undefined): Record<string, Factor> | null {
  if (!raw) return null
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

function factorLine(factors: Record<string, Factor> | null): string {
  if (!factors) return ''
  const pct = (v: number | undefined) =>
    v === undefined ? '?' : `${Math.round(v * 100)}%`
  const num = (v: number | undefined) => (v === undefined ? '?' : v.toFixed(2))
  return (
    `real ${pct(factors.C?.value)} · ` +
    `exploit ${pct(factors.L?.value)} · ` +
    `impact ${num(factors.I?.value)} · ` +
    `reach ${num(factors.R?.value)}`
  )
}

/** The evidence behind each factor, for the hover.
 *
 * The line above is four numbers, and a number an operator cannot interrogate
 * is a number they cannot disagree with. This matters most for C, which now
 * also carries what their own Real / False positive clicks on that detector
 * have taught it ("you judged 2 of 10 of these real"): a score that moved for
 * an invisible reason is how a ranking loses its users.
 */
function factorEvidence(factors: Record<string, Factor> | null): string {
  if (!factors) return ''
  const labels: Record<string, string> = {
    C: 'real', L: 'exploit', I: 'impact', R: 'reach',
  }
  return ['C', 'L', 'I', 'R']
    .map(key => {
      const evidence = factors[key]?.evidence
      return evidence ? `${labels[key]}: ${evidence}` : ''
    })
    .filter(Boolean)
    .join('\n')
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

  // R8: reload on EVERY terminal state, not just success. A run that errored or
  // was stopped may still have published part of its result (a Stop during the
  // publish finishes the batch it is on), and the error path used to leave the
  // board showing the previous order with no hint that it was stale.
  const lastTerminalRef = useRef<string | null>(null)
  useEffect(() => {
    const terminal = ['error', 'stopped', 'completed']
    if (!terminal.includes(triage.status)) {
      lastTerminalRef.current = null
      return
    }
    if (lastTerminalRef.current === triage.status) return
    lastTerminalRef.current = triage.status
    void load()
  }, [triage.status, load])

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

  // The dialog lives in TriageRunButton, which is the same component the
  // CypherFix page uses: one button, one wording, one set of numbers.
  const runTriage = useCallback(() => {
    if (!projectId || !userId) return
    startedHereRef.current = true
    setShowProgress(true)
    triage.startTriage()
  }, [projectId, userId, triage])

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
        if (res.status === 409) {
          // A rescan or a version activation replaced the node this tab is
          // holding an id for. Silently doing nothing looked like success.
          await load()
          throw new Error(
            'This finding changed while the page was open, so it was not muted. ' +
            'The list has been reloaded; try again.'
          )
        }
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
    [projectId, dangerConfirm, alertError, toast, load],
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

  /**
   * The board's four sections, in their fixed order.
   *
   * THE ORDERING CONTRACT. The server decides the section and returns the rows
   * already sorted by (section, score DESC, severity, id); this mirrors that key
   * exactly so a client-side tier filter cannot produce a different order from
   * the one the server published. When the two disagree, the operator is looking
   * at a ranking nobody computed.
   */
  const sections = useMemo(() => {
    const rows = tierFilter === 'all'
      ? findings
      : findings.filter(f => tierOf(f) === tierFilter)

    const bySection = new Map<number, TriageFinding[]>()
    for (const f of rows) {
      const key = f.section ?? SECTION_NOT_TRIAGED
      const list = bySection.get(key)
      if (list) list.push(f)
      else bySection.set(key, [f])
    }
    for (const list of bySection.values()) {
      list.sort((a, b) => {
        const p = (b.triage_priority_score ?? -1) - (a.triage_priority_score ?? -1)
        if (p !== 0) return p
        const sev = severityRank(a.severity) - severityRank(b.severity)
        return sev !== 0 ? sev : a.id.localeCompare(b.id)
      })
    }
    return [SECTION_RANKED, SECTION_NOT_TRIAGED, SECTION_FALSE_POSITIVE,
            SECTION_RESOLVED]
      .map(key => ({ key, rows: bySection.get(key) ?? [] }))
      .filter(section => section.rows.length > 0)
  }, [findings, tierFilter])

  const visible = useMemo(
    () => sections.flatMap(section => section.rows), [sections])

  /** The newest completed run on the board, for the "from an older run" note. */
  const latestRunId = useMemo(() => {
    let best: string | null = null
    let bestAt = ''
    for (const f of findings) {
      if (f.triage_run_id && (f.triaged_at || '') > bestAt) {
        bestAt = f.triaged_at || ''
        best = f.triage_run_id
      }
    }
    return best
  }, [findings])

  // The query is capped server-side. Saying so is not cosmetic: without it a
  // truncated list reads as the complete set of findings to triage, and an
  // operator would work through it believing nothing was left.
  const truncated = total > findings.length

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const f of findings) {
      const t = tierOf(f)
      c[t] = (c[t] || 0) + 1
    }
    return c
  }, [findings])

  /** Real / False positive. The verdict route already refuses to let the AI
   *  overwrite this, which is what makes the button worth having (R6). */
  const setVerdict = useCallback(
    async (finding: TriageFinding, status: 'confirmed' | 'likely_noise') => {
      if (!projectId) return
      setBusyId(finding.id)
      try {
        const res = await fetch('/api/triage/verdict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ projectId, nodeId: finding.id, status }),
        })
        const body = await res.json().catch(() => ({}))
        if (res.status === 409 || (res.ok && body.updated === false)) {
          await load()
          throw new Error(
            'This finding changed while the page was open. The list has been ' +
            'reloaded; try again.'
          )
        }
        if (!res.ok) throw new Error(body.error || 'The verdict could not be saved.')
        toast.success(
          status === 'confirmed'
            ? 'Marked real. Triage will not change this again.'
            : 'Marked a false positive. It is not muted, so you can undo it.'
        )
        await load()
      } catch (e) {
        await alertError(
          e instanceof Error ? e.message : 'The verdict could not be saved.',
          'Your verdict')
      } finally {
        setBusyId(null)
      }
    },
    [projectId, alertError, toast, load],
  )

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
        {sections.length > 0 && (
          <SectionHead
            sectionKey={sections[0].key}
            count={sections[0].rows.length}
          />
        )}
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
              className={`${styles.chip} ${styles[`tier${tier}`] ?? ''} ${
                tierFilter === tier ? styles.chipActive : ''}`}
              onClick={() => setTierFilter(tier)}
            >
              {TIER_LABELS[tier]} ({counts[tier] ?? 0})
            </button>
          ))}
        </div>
        <div className={styles.actions}>
          <WikiInfoButton target="PriorityBoard" />
          <TriageRunButton
            projectId={projectId}
            onConfirm={runTriage}
            running={triage.status === 'running'}
            // A published run stamped triage_run_id on the findings, so this is
            // authoritative and costs nothing: the board already has the rows.
            hasPreviousRun={latestRunId !== null}
            disabled={!userId || showProgress}
          />
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
            ? 'No findings in scope yet. Run a scan, then run triage to see what matters most.'
            : 'No findings match this filter.'}
        </div>
      ) : (
        sections.map((section, sectionIndex) => (
          <div key={section.key} className={styles.section}>
            {sectionIndex > 0 && (
              <SectionHead sectionKey={section.key} count={section.rows.length} />
            )}
            <div className={styles.tableScroll}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Finding</th>
                    <th>Type</th>
                    <th>Score</th>
                    <th>Verdict</th>
                    <th>Signals</th>
                    <th>Where</th>
                    <th>Why</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {section.rows.map((f, i) => {
                    const factors = parseFactors(f.triage_factors)
                    const tier = tierOf(f)
                    const score = f.triage_priority_score
                    const isHuman = f.triage_source === 'human'
                    const verdict = isHuman
                      ? `You: ${f.triage_status === 'confirmed' ? 'Real' : 'False positive'}`
                      : VERDICT_LABELS[f.triage_ai_verdict || ''] ?? 'Not reviewed'
                    const stale =
                      section.key === SECTION_RANKED &&
                      latestRunId !== null &&
                      Boolean(f.triage_run_id) &&
                      f.triage_run_id !== latestRunId

                    return (
                      <tr key={f.id}>
                        <td className={styles.rank}>{i + 1}</td>
                        <td className={styles.name}>
                          {f.name || f.id}
                          {stale && (
                            <span
                              className={styles.staleTag}
                              title={
                                'Scored by an earlier run. Its facts were true ' +
                                'on that date; re-triage to refresh it.'
                              }
                            >
                              from {fmtWhen(f.triaged_at ?? null)}
                            </span>
                          )}
                        </td>
                        <td>{f.label}</td>
                        <td className={styles.scoreCell}>
                          {score === null || score === undefined ? (
                            <span className={styles.confidence}>-</span>
                          ) : (
                            <>
                              <span className={styles.scoreValue}>
                                {score.toFixed(1)}
                              </span>
                              <span
                                className={`${styles.tierChip} ${styles[`tier${tier}`] ?? ''}`}
                                title={f.triage_tier_rule || ''}
                              >
                                {TIER_LABELS[tier]}
                              </span>
                              {factors ? (
                                <span
                                  className={styles.factorLine}
                                  title={factorEvidence(factors)}
                                >
                                  {factorLine(factors)}
                                </span>
                              ) : (
                                <span className={styles.factorLine}>math only</span>
                              )}
                            </>
                          )}
                        </td>
                        <td className={styles.verdictCell}>
                          <span
                            className={`${styles.verdictChip} ${
                              isHuman ? styles.verdictHuman : ''}`}
                            title={f.triage_ai_model
                              ? `Reviewed by ${f.triage_ai_model}`
                              : ''}
                          >
                            {verdict}
                          </span>
                          {f.triage_ai_quote && (
                            <span
                              className={styles.quote}
                              title={f.triage_ai_quote}
                            >
                              &ldquo;{f.triage_ai_quote}&rdquo;
                            </span>
                          )}
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
                        <td className={styles.reason}>
                          {f.triage_reason || '-'}
                          {f.triage_fix_lever && (
                            <span className={styles.fixLever}>{f.triage_fix_lever}</span>
                          )}
                        </td>
                        <td className={styles.rowActions}>
                          <button
                            className={styles.verdictButton}
                            disabled={busyId === f.id}
                            onClick={() => void setVerdict(f, 'confirmed')}
                            title="Mark this real. Triage will not change it again."
                          >
                            <Check size={13} /> Real
                          </button>
                          <button
                            className={styles.verdictButton}
                            disabled={busyId === f.id}
                            onClick={() => void setVerdict(f, 'likely_noise')}
                            title="Mark this a false positive. It is not muted."
                          >
                            <X size={13} /> False
                          </button>
                          <button
                            className={styles.muteButton}
                            disabled={busyId === f.id}
                            onClick={() => void mute(f)}
                            title="Hide this finding from the graph, reports and the AI agent"
                          >
                            {busyId === f.id
                              ? <Loader2 className={styles.spin} size={13} />
                              : <EyeOff size={13} />}
                            Mute
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ))
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
