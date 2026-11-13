'use client'

/**
 * The Priority Board: what to fix first, and who decided it.
 *
 * Every finding carries three layers: the rules' score from a run, a review
 * (the built-in AI during a run, or an external agent over MCP) and a person's
 * decision. The server combines them into the one final score the board ranks
 * by. Each row names the layer that decided it and how far that moved the
 * rules' score; the detail panel shows why.
 *
 * This is the working set an operator is triaging. What they decided to stop
 * looking at lives in its own table, Muted Nodes (All Nodes dropdown), which is
 * the ONLY place in the product where a suppressed finding is visible at all.
 * Everything else -- the graph, the agent, analytics, reports -- has them
 * filtered out, which is the point of the feature. It is paged there because a
 * node-filter rule can mute thousands of findings, and this board used to load
 * every muted row on each visit.
 *
 * The mute itself is `useMuteNode`, shared with the node drawer and the graph
 * tables so every Mute button behaves the same.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Loader2, EyeOff, Check, X, RotateCcw } from 'lucide-react'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { useProject } from '@/providers/ProjectProvider'
import { useCypherFixTriageWS } from '@/hooks/useCypherFixTriageWS'
import { TriageProgress } from '../CypherFixTab/TriageProgress/TriageProgress'
import { TriageRunButton } from '@/components/triage/TriageRunButton'
import { TriageRunBanner } from '@/components/triage/TriageRunBanner'
import { MuteButton, MultiMuteButton, useMuteNode } from '../MuteNode'
import { NodeIdCell, NodeIdTh } from '../RedZoneTables/nodeId'
import { TriageDetailPanel, type DetailTarget } from './TriageDetailPanel'
import { DispositionChip } from './DispositionChip'
import {
  DISPOSITIONS, DISPOSITION_LABELS, readDisposition, type Disposition, type DispositionResult,
} from '@/lib/triage/disposition'
import {
  FACTOR_KEYS, FACTOR_NAMES, TIER_LABELS, TIER_ORDER, baseLine, changedFactors,
  decisionChip, factorEvidence, fmtWhen, formatFactor, parseFactors, personDecided,
  resetConfirmText, reviewChip, tierOf, whyText, REVIEW_VERDICT_TONE,
  type Factors, type TriageFinding, type TriageTier, type VerdictResult, type VerdictStatus,
} from './triageLayers'
import { triageBodyErrorText } from '@/lib/triage/errorText'
import { toApiError } from '@/lib/apiError'
import { useRefusal } from '@/hooks/useRefusal'
import styles from './TriageTable.module.css'

const BOARD_LOAD_FAILED = 'The Priority Board could not be loaded'

export type { TriageFinding, TriageStatus, TriageTier } from './triageLayers'
export { TIER_LABELS } from './triageLayers'

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
    'A review or a person judged these not real. They are not muted or deleted, ' +
    'and one click puts them back.',
  [SECTION_RESOLVED]:
    'Fixed, gone, or a credential that no longer works. Kept so they can come ' +
    'back if a scan finds them again.',
}

/** The uncapped counts behind the filters (`facets` on the findings answer). */
interface Facets {
  total?: number
  decided_by?: Record<string, number>
  decided_via?: Record<string, number>
  reviewed_via?: Record<string, number>
  review_current?: Record<string, number>
  sections?: Record<string, number>
  tiers?: Record<string, number>
}

type FilterParam = 'decidedBy' | 'reviewedVia' | 'reviewCurrent'

interface BoardFilter {
  param: FilterParam
  value: string
}

const FACET_OF: Record<FilterParam, keyof Facets> = {
  decidedBy: 'decided_by',
  reviewedVia: 'reviewed_via',
  reviewCurrent: 'review_current',
}

/**
 * The "Decided by" menu. Each choice is a SERVER filter, applied in the graph
 * before the cap: filtering the capped page client-side would hide every
 * matching row beyond it, and the operator would read the page as the set.
 */
const FILTER_GROUPS: Array<{ label: string; options: Array<{ param: FilterParam; value: string; label: string }> }> = [
  {
    label: 'Decided by',
    options: [
      { param: 'decidedBy', value: 'person', label: 'You' },
      { param: 'decidedBy', value: 'review', label: 'A review' },
      { param: 'decidedBy', value: 'rules', label: 'Rules only' },
    ],
  },
  {
    label: 'Reviewed by',
    options: [
      { param: 'reviewedVia', value: 'builtin', label: 'The built-in AI' },
      { param: 'reviewedVia', value: 'mcp', label: 'An external agent (MCP)' },
      { param: 'reviewedVia', value: 'none', label: 'Nobody (not reviewed)' },
    ],
  },
  {
    label: 'Review',
    options: [
      { param: 'reviewCurrent', value: 'current', label: 'Review current' },
      { param: 'reviewCurrent', value: 'stale', label: 'Review out of date' },
    ],
  },
]

/** The review chip's tint, by what it concluded. A decision overrides all of
 *  these (see .verdictHuman). */
const REVIEW_TONE_CLASS: Record<string, string> = {
  real: 'verdictReal',
  doubtful: 'verdictDoubtful',
  dismissed: 'verdictDismissed',
}

const VERDICT_TOASTS: Record<VerdictStatus, string> = {
  confirmed: 'Marked real. It counts as 100% real, and no run changes your decision.',
  likely_noise: 'Marked a false positive. It is not muted, so you can undo it.',
  unreviewed: 'Decision reset. The rules and any review rank it again.',
}

function rowKey(f: Pick<TriageFinding, 'id' | 'label'>): string {
  return `${f.label}:${f.id}`
}

/** The count badge carries each section's colour; see the CSS module for why
 *  it is the only element that can. Likely-false-positive keeps the neutral
 *  default: it is the one section whose rows are claims about nothing. */
const SECTION_COUNT_CLASS: Record<number, string> = {
  [SECTION_RANKED]: 'countRanked',
  [SECTION_NOT_TRIAGED]: 'countNotTriaged',
  [SECTION_RESOLVED]: 'countResolved',
}

/** One section's title, count and blurb, on a single line.
 *
 *  The FIRST section's header is rendered into the toolbar's empty left slot
 *  rather than above its own table, which buys back another row of vertical
 *  space on a board that is mostly table. Later sections keep theirs in place,
 *  because there is no toolbar to share.
 */
function SectionHead({ sectionKey, count }: { sectionKey: number; count: number }) {
  const tint = styles[SECTION_COUNT_CLASS[sectionKey] ?? ''] ?? ''
  return (
    <div className={styles.sectionHead}>
      <h3 className={styles.sectionHeading}>
        {SECTION_TITLES[sectionKey]}
        <span className={`${styles.sectionCount} ${tint}`}>{count}</span>
      </h3>
      <p className={styles.sectionBlurb}>{SECTION_BLURBS[sectionKey]}</p>
    </div>
  )
}

/**
 * The four factors on one line. A factor a review or a decision moved away
 * from the rules' value is marked, and its hover gives the rules' value, so
 * "what did the review change" is answerable from the row.
 *
 * The line's own hover carries the evidence behind every factor. A number an
 * operator cannot interrogate is a number they cannot disagree with; this
 * matters most for C, which also carries what their own Real / False positive
 * clicks on that detector have taught it ("you judged 2 of 10 of these real").
 */
function FactorLine({ factors, base }: { factors: Factors; base: Factors | null }) {
  const moved = changedFactors(factors, base)
  const parts: ReactNode[] = []
  FACTOR_KEYS.forEach((key, i) => {
    if (i > 0) parts.push(' · ')
    const value = formatFactor(key, factors[key]?.value)
    if (moved.has(key)) {
      parts.push(`${FACTOR_NAMES[key]} `)
      parts.push(
        <mark key={key} className={styles.factorMoved}
              title={`rules: ${formatFactor(key, base?.[key]?.value)}`}>
          {value}
        </mark>,
      )
    } else {
      parts.push(`${FACTOR_NAMES[key]} ${value}`)
    }
  })
  return (
    <span className={styles.factorLine} title={factorEvidence(factors)}>{parts}</span>
  )
}

interface TriageTableProps {
  projectId: string | null
  /** Switch the page to Muted Nodes; offered on the toast after a mute. */
  onViewMuted?: () => void
}

export function TriageTable({ projectId, onViewMuted }: TriageTableProps) {
  // A read share reads the board and changes nothing on it (step 4.11): each row action says why.
  const verdictRefusal = useRefusal('triage:verdict', projectId)?.text ?? null
  const muteRefusal = useRefusal('triage:mute', projectId)?.text ?? null
  const [findings, setFindings] = useState<TriageFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  /** Server-side total of the filtered set, which can exceed what was returned. */
  const [total, setTotal] = useState(0)
  const [facets, setFacets] = useState<Facets | null>(null)
  /** The run whose results the board shows, as the server names it from its
   *  run records (B9). Guessing it from the rows' newest `triaged_at` breaks
   *  on an imported project, which has scores but no runs. */
  const [latestRunId, setLatestRunId] = useState<string | null>(null)
  const [tierFilter, setTierFilter] = useState<TriageTier | 'all'>('all')
  const [boardFilter, setBoardFilter] = useState<BoardFilter | null>(null)
  const [dispositionFilter, setDispositionFilter] = useState<Disposition | 'all'>('all')
  const [rowErrors, setRowErrors] = useState<Record<string, { message: string; reload: boolean }>>({})
  const [selected, setSelected] = useState<DetailTarget | null>(null)
  const [showProgress, setShowProgress] = useState(false)
  /** True when the run was launched from this mount, rather than re-attached. */
  const startedHereRef = useRef(false)
  /** A filter change can race the previous fetch; only the newest may land. */
  const loadSeqRef = useRef(0)
  /** Findings the panel found gone: dropped from the board on purpose, so the
   *  panel stays open to say so instead of closing under the operator. */
  const goneRef = useRef(new Set<string>())

  const { userId } = useProject()
  const { dangerConfirm } = useAlertModal()
  const toast = useToast()

  const load = useCallback(async () => {
    if (!projectId) return
    const seq = ++loadSeqRef.current
    setLoading(true)
    setError(null)
    try {
      const query = new URLSearchParams({ projectId })
      if (boardFilter) query.set(boardFilter.param, boardFilter.value)
      const f = await fetch(`/api/triage/findings?${query.toString()}`)
      if (!f.ok) {
        throw new Error(triageBodyErrorText(await f.json().catch(() => ({})), f.status, BOARD_LOAD_FAILED))
      }
      const findingsBody = await f.json()
      if (seq !== loadSeqRef.current) return
      setFindings(findingsBody.findings ?? [])
      setTotal(findingsBody.total ?? (findingsBody.findings ?? []).length)
      setFacets(findingsBody.facets ?? null)
      setLatestRunId(findingsBody.latestRunId ?? null)
      setRowErrors({})
    } catch (e) {
      if (seq !== loadSeqRef.current) return
      // A TypeError is fetch getting no answer at all; its "Failed to fetch" says nothing.
      setError(e instanceof Error && !(e instanceof TypeError)
        ? e.message : toApiError(e, BOARD_LOAD_FAILED).message)
    } finally {
      if (seq === loadSeqRef.current) setLoading(false)
    }
  }, [projectId, boardFilter])

  useEffect(() => {
    void load()
  }, [load])

  useEffect(() => {
    setSelected(null)
    setBoardFilter(null)
    setDispositionFilter('all')
  }, [projectId])

  // Triage is a run of the CypherFix pipeline (score -> group -> review ->
  // fix items -> publish), driven over the same WebSocket the CypherFix page
  // uses. This tab launches it and reloads the board when it finishes, so an
  // operator never has to leave to /cypherfix to rank what a scan found.
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

  // R8: reload on EVERY terminal state, not just success. A run that errored
  // may still have published some of its batches, and the error path used to
  // leave the board showing the previous order with no hint that it was stale.
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

  const { mute: muteNode, mutingKey } = useMuteNode(projectId, onViewMuted)
  const mute = useCallback(
    (finding: TriageFinding) => muteNode(
      { name: finding.name || finding.id, nodeId: finding.id },
      {
        // Drop it locally rather than refetching: the graph write already
        // succeeded, and a round trip here just makes it feel slow.
        onMuted: () => setFindings(prev => prev.filter(f => f.id !== finding.id)),
        onStale: load,
      },
    ),
    [muteNode, load],
  )

  /** Each loaded row's disposition (lib/triage/disposition.ts), read once per
   *  load from the props the row carries. Null for a row it cannot read. */
  const dispositions = useMemo(
    () => new Map<string, DispositionResult | null>(findings.map(f => [rowKey(f), readDisposition(f)])),
    [findings])

  /** Loaded rows per disposition, for the filter's counts. */
  const dispositionCounts = useMemo(() => {
    const c: Partial<Record<Disposition, number>> = {}
    for (const d of dispositions.values()) if (d) c[d.disposition] = (c[d.disposition] ?? 0) + 1
    return c
  }, [dispositions])

  /**
   * The board's four sections, in their fixed order.
   *
   * THE ORDERING CONTRACT. The server decides the section and returns the rows
   * already sorted by (section, score DESC, severity, id). The board keeps that
   * order as it arrived and never re-sorts: a client sort with its own idea of
   * severity is how the board and the server came to disagree (U8). A tier
   * filter keeps RANKED rows only, since an unscored row has no tier (U6).
   * The disposition filter, like the tier chips, narrows the loaded rows.
   */
  const sections = useMemo(() => {
    const rows = findings.filter(f =>
      (tierFilter === 'all' ||
        ((f.section ?? SECTION_NOT_TRIAGED) === SECTION_RANKED && tierOf(f) === tierFilter)) &&
      (dispositionFilter === 'all' || dispositions.get(rowKey(f))?.disposition === dispositionFilter))

    const bySection = new Map<number, TriageFinding[]>()
    for (const f of rows) {
      const key = f.section ?? SECTION_NOT_TRIAGED
      const list = bySection.get(key)
      if (list) list.push(f)
      else bySection.set(key, [f])
    }
    return [SECTION_RANKED, SECTION_NOT_TRIAGED, SECTION_FALSE_POSITIVE,
            SECTION_RESOLVED]
      .map(key => ({ key, rows: bySection.get(key) ?? [] }))
      .filter(section => section.rows.length > 0)
  }, [findings, tierFilter, dispositionFilter, dispositions])

  const visible = useMemo(
    () => sections.flatMap(section => section.rows), [sections])

  // The query is capped server-side. Saying so is not cosmetic: without it a
  // truncated list reads as the complete set of findings to triage, and an
  // operator would work through it believing nothing was left.
  const truncated = total > findings.length

  /** Scored rows per tier. The facets count the whole project, past the cap;
   *  under a server filter they would count rows the filter hides, so the
   *  loaded (filtered) rows are counted instead. */
  const counts = useMemo(() => {
    if (!boardFilter && facets?.tiers) return facets.tiers
    const c: Record<string, number> = {}
    for (const f of findings) {
      if ((f.section ?? SECTION_NOT_TRIAGED) !== SECTION_RANKED) continue
      const t = tierOf(f)
      c[t] = (c[t] || 0) + 1
    }
    return c
  }, [findings, facets, boardFilter])

  // The panel closes when its finding leaves the board (a mute, or a filter
  // that no longer matches it), except when the panel itself found it gone.
  useEffect(() => {
    if (!selected || goneRef.current.has(rowKey(selected))) return
    if (!findings.some(f => f.id === selected.id && f.label === selected.label)) setSelected(null)
  }, [findings, selected])

  const selectedRow = useMemo(
    () => (selected
      ? findings.find(f => f.id === selected.id && f.label === selected.label) ?? null
      : null),
    [findings, selected],
  )

  /**
   * Real / False positive / Reset. The agent rescores the finding in the same
   * transaction and answers with the new row, which replaces the old one in
   * place: no reload, so the operator keeps their place on the board (U9).
   *
   * A reason always goes with it (B10): the typed one from the panel, '' from a
   * row button.
   */
  const postVerdict = useCallback(
    async (finding: TriageFinding, status: VerdictStatus, reason: string): Promise<VerdictResult> => {
      if (!projectId) return { ok: false, message: 'Select a project first.' }
      if (status === 'unreviewed') {
        const ok = await dangerConfirm(
          resetConfirmText(finding.name || finding.id), 'Reset your decision',
          { confirmLabel: 'Reset' })
        if (!ok) return { ok: false, cancelled: true, message: '' }
      }
      try {
        const res = await fetch('/api/triage/verdict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            projectId, nodeId: finding.id, label: finding.label, status, reason,
          }),
        })
        const body = await res.json().catch(() => ({}))
        if (!res.ok || body.updated !== true) {
          return {
            ok: false,
            status: res.status,
            code: typeof body.code === 'string' ? body.code : undefined,
            message: res.status === 404
              ? 'This finding is no longer on the board: a rescan or a version switch ' +
                'replaced it. Reload to see the current list.'
              : triageBodyErrorText(body, res.status, 'The verdict could not be saved.'),
          }
        }
        const row = body.row as TriageFinding | null | undefined
        if (row && row.id) {
          setFindings(prev => prev.map(x =>
            x.id === finding.id && x.label === finding.label ? { ...x, ...row } : x))
        } else {
          await load()
        }
        toast.success(VERDICT_TOASTS[status] +
          (body.rescored === false ? ' The score follows at the next run.' : ''))
        return { ok: true }
      } catch (e) {
        return { ok: false, message: toApiError(e, 'The verdict could not be saved: the server did not answer.').message }
      }
    },
    [projectId, dangerConfirm, toast, load],
  )

  const rowVerdict = useCallback(async (finding: TriageFinding, status: VerdictStatus) => {
    const key = rowKey(finding)
    setBusyId(finding.id)
    setRowErrors(prev => {
      if (!(key in prev)) return prev
      const { [key]: _dropped, ...rest } = prev
      return rest
    })
    try {
      const result = await postVerdict(finding, status, '')
      if (!result.ok && !result.cancelled) {
        setRowErrors(prev => ({
          ...prev,
          [key]: {
            message: result.message,
            reload: result.status === 404 || result.code === 'activation_changed',
          },
        }))
      }
    } finally {
      setBusyId(null)
    }
  }, [postVerdict])

  const openDetail = useCallback((f: TriageFinding) => {
    setSelected({ id: f.id, label: f.label, name: f.name || f.id })
  }, [])

  const closeDetail = useCallback(() => setSelected(null), [])

  const panelVerdict = useCallback(
    (status: VerdictStatus, reason: string) => {
      if (!selected) return Promise.resolve<VerdictResult>({ ok: false, message: 'Nothing selected.' })
      const finding = selectedRow ??
        ({ id: selected.id, label: selected.label, name: selected.name } as TriageFinding)
      return postVerdict(finding, status, reason)
    },
    [selected, selectedRow, postVerdict],
  )

  const dropSelected = useCallback(() => {
    if (!selected) return
    goneRef.current.add(rowKey(selected))
    setFindings(prev => prev.filter(x => !(x.id === selected.id && x.label === selected.label)))
  }, [selected])

  const filterValue = boardFilter ? `${boardFilter.param}:${boardFilter.value}` : ''
  const onFilterChange = useCallback((value: string) => {
    if (!value) {
      setBoardFilter(null)
      return
    }
    const [param, choice] = value.split(':') as [FilterParam, string]
    setBoardFilter({ param, value: choice })
  }, [])

  const facetCount = (param: FilterParam, value: string): string => {
    const n = facets?.[FACET_OF[param]] as Record<string, number> | undefined
    return typeof n?.[value] === 'number' ? ` (${n[value]})` : ''
  }

  if (!projectId) {
    return <div className={styles.empty}>Select a project to rank its findings.</div>
  }

  if (loading && findings.length === 0 && !error) {
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
        {boardFilter && (
          <button className={styles.button} onClick={() => setBoardFilter(null)}>Clear the filter</button>
        )}
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
          {loading && <Loader2 className={styles.spin} size={14} aria-label="Loading" />}
          <select
            className={`${styles.filterSelect} ${boardFilter ? styles.filterSelectActive : ''}`}
            aria-label="Decided by"
            value={filterValue}
            onChange={e => onFilterChange(e.target.value)}
            title="Filter the whole board by who decided each finding"
          >
            <option value="">
              Decided by: anyone{typeof facets?.total === 'number' ? ` (${facets.total})` : ''}
            </option>
            {FILTER_GROUPS.map(group => (
              <optgroup key={group.label} label={group.label}>
                {group.options.map(o => (
                  <option key={`${o.param}:${o.value}`} value={`${o.param}:${o.value}`}>
                    {o.label}{facetCount(o.param, o.value)}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
          <select
            className={`${styles.filterSelect} ${dispositionFilter !== 'all' ? styles.filterSelectActive : ''}`}
            aria-label="Disposition"
            value={dispositionFilter === 'all' ? '' : dispositionFilter}
            onChange={e => setDispositionFilter((e.target.value || 'all') as Disposition | 'all')}
            title={'Filter by whether a finding can go in a report. Applies to the findings ' +
              'loaded here, like the tier chips.'}
          >
            <option value="">Disposition: any ({findings.length})</option>
            {DISPOSITIONS.map(d => (
              <option key={d} value={d}>{DISPOSITION_LABELS[d]} ({dispositionCounts[d] ?? 0})</option>
            ))}
          </select>
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
              title="Ranked findings in this tier"
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
            // The server names the run the board shows, so this is
            // authoritative and costs nothing: the answer is already loaded.
            hasPreviousRun={latestRunId !== null}
            disabled={!userId || showProgress}
          />
          {onViewMuted && (
            <button className={styles.button} onClick={onViewMuted} title="Open Muted Nodes">
              <EyeOff size={14} /> Muted
            </button>
          )}
        </div>
      </div>

      <div className={styles.board}>
        {backgroundRun && (
          <TriageRunBanner
            projectId={projectId}
            label="Priority Board running"
            phase={triage.currentPhase}
            hint="The board updates when it publishes; you can leave this page"
            notice={triage.notice}
            onDetails={() => setShowProgress(true)}
            onStop={triage.stopTriage}
          />
        )}

        {truncated && (
          <div className={styles.truncationNotice} role="status">
            Showing the {findings.length} highest-ranked findings of {total}. Mute or resolve
            some, or narrow with Decided by, to see the rest.
          </div>
        )}

        {visible.length === 0 ? (
          <div className={styles.empty}>
            {findings.length === 0 && !boardFilter
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
                      <NodeIdTh />
                      <th>#</th>
                      <th>Finding</th>
                      <th>Type</th>
                      <th>Disposition</th>
                      <th>Score</th>
                      <th>Decided by</th>
                      <th>Signals</th>
                      <th>Where</th>
                      <th>Why</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {section.rows.map((f, i) => {
                      const factors = parseFactors(f.triage_factors)
                      const baseFactors = parseFactors(f.triage_base_factors)
                      const tier = tierOf(f)
                      const score = f.triage_priority_score
                      const base = baseLine(f)
                      const decision = decisionChip(f)
                      const review = reviewChip(f)
                      const decided = personDecided(f)
                      const why = whyText(f)
                      const key = rowKey(f)
                      const rowError = rowErrors[key]
                      const busy = busyId === f.id || mutingKey === f.id
                      const isSelected = selected !== null && rowKey(selected) === key
                      const stale =
                        section.key === SECTION_RANKED &&
                        latestRunId !== null &&
                        Boolean(f.triage_run_id) &&
                        f.triage_run_id !== latestRunId

                      return (
                        <tr
                          key={key}
                          className={`${styles.row} ${isSelected ? styles.rowSelected : ''}`}
                          onClick={() => openDetail(f)}
                        >
                          <td><NodeIdCell value={f.node_id} /></td>
                          <td className={styles.rank}>{i + 1}</td>
                          <td className={styles.name}>
                            <button
                              type="button"
                              className={styles.nameButton}
                              onClick={e => { e.stopPropagation(); openDetail(f) }}
                              title="Why it ranks here"
                            >
                              {f.name || f.id}
                            </button>
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
                          <td className={styles.dispositionCell}>
                            <DispositionChip result={dispositions.get(key) ?? null} />
                          </td>
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
                                {base && (
                                  <span className={styles.baseLine} title={base.title}>
                                    {base.text}{' '}
                                    <span className={base.up ? styles.deltaUp : styles.deltaDown}>
                                      {base.delta}
                                    </span>
                                  </span>
                                )}
                                {factors ? (
                                  <FactorLine factors={factors} base={baseFactors} />
                                ) : (
                                  <span className={styles.factorLine}>math only</span>
                                )}
                              </>
                            )}
                          </td>
                          <td className={styles.verdictCell}>
                            <div className={styles.chipStack}>
                              {decision && (
                                <span
                                  className={`${styles.verdictChip} ${styles.verdictHuman}`}
                                  title={decision.title}
                                >
                                  {decision.text}
                                </span>
                              )}
                              {review && (
                                <span
                                  className={`${styles.verdictChip} ${
                                    styles[REVIEW_TONE_CLASS[REVIEW_VERDICT_TONE[review.verdict]] ?? ''] ?? ''
                                  } ${review.stale ? styles.verdictStale : ''}`}
                                  title={review.title}
                                >
                                  {review.text}
                                </span>
                              )}
                              {review?.stale && (
                                <span className={styles.staleTag} title={review.title}>out of date</span>
                              )}
                              {!decision && !review && (
                                <span
                                  className={styles.verdictChip}
                                  title="No review and no decision: the rules alone rank it."
                                >
                                  Rules only
                                </span>
                              )}
                            </div>
                            {review && f.triage_ai_quote && (
                              <span className={styles.quote} title={f.triage_ai_quote}>
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
                            {why || '-'}
                            {f.triage_fix_lever && (
                              <span className={styles.fixLever}>{f.triage_fix_lever}</span>
                            )}
                          </td>
                          <td className={styles.rowActions} onClick={e => e.stopPropagation()}>
                            <button
                              className={styles.verdictButton}
                              disabled={busy || !!verdictRefusal || (decided && f.triage_status === 'confirmed')}
                              onClick={() => void rowVerdict(f, 'confirmed')}
                              title={verdictRefusal ? verdictRefusal : decided && f.triage_status === 'confirmed'
                                ? 'Already marked real'
                                : 'Mark this real. It counts as 100% real and no run changes it.'}
                            >
                              <Check size={13} /> Real
                            </button>
                            <button
                              className={styles.verdictButton}
                              disabled={busy || !!verdictRefusal || (decided && f.triage_status === 'likely_noise')}
                              onClick={() => void rowVerdict(f, 'likely_noise')}
                              title={verdictRefusal ? verdictRefusal : decided && f.triage_status === 'likely_noise'
                                ? 'Already marked a false positive'
                                : 'Mark this a false positive. It is not muted.'}
                            >
                              <X size={13} /> False
                            </button>
                            {decided && (
                              <button
                                className={styles.verdictButton}
                                disabled={busy || !!verdictRefusal}
                                onClick={() => void rowVerdict(f, 'unreviewed')}
                                title={verdictRefusal ?? 'Remove your decision; the rules and any review rank it again.'}
                              >
                                <RotateCcw size={13} /> Reset
                              </button>
                            )}
                            <MultiMuteButton
                              compact
                              seed={{ name: f.name || f.id, nodeId: f.id, graphId: f.node_id, label: f.label }}
                              onMuted={keys => setFindings(prev => prev.filter(x => !keys.includes(x.id)))}
                            />
                            <MuteButton
                              busy={busy}
                              disabled={!!muteRefusal}
                              title={muteRefusal ?? undefined}
                              onClick={() => void mute(f)}
                            />
                            {rowError && (
                              <div className={styles.rowError} role="alert">
                                {rowError.message}
                                {rowError.reload && (
                                  <button
                                    type="button"
                                    className={styles.rowErrorButton}
                                    onClick={() => void load()}
                                  >
                                    Reload
                                  </button>
                                )}
                              </div>
                            )}
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
      </div>

      {selected && (
        <TriageDetailPanel
          key={rowKey(selected)}
          projectId={projectId}
          target={selected}
          row={selectedRow}
          onClose={closeDetail}
          onVerdict={panelVerdict}
          onGone={dropSelected}
          onReload={() => void load()}
        />
      )}

      <TriageProgress
        isVisible={showProgress}
        title="Priority Board"
        phase={triage.currentPhase}
        progress={triage.progress}
        findings={triage.findings}
        thinking={triage.thinking}
        error={triage.error}
        notice={triage.notice}
        status={triage.status}
        onClose={closeProgress}
        onStop={triage.stopTriage}
      />
    </div>
  )
}

export default TriageTable
