'use client'

/**
 * The one Triage button, in all three places it appears.
 *
 * There used to be three buttons sending the same message under two different
 * names — "Rank Findings" on the Priority Board, "Start Vulnerability Triage"
 * and "Re-triage" on CypherFix — and only one of them asked for confirmation.
 * They ran the same job, so an operator could press one, see the other page
 * change, and have no idea the two were connected.
 *
 * One component, one label, one dialog.
 *
 * WHY THE DIALOG IS LONG. A triage run is not free and not invisible: it spends
 * LLM budget, replaces the board's order, rewrites the fix list, and blocks
 * version activation while it works. Every one of those is something an
 * operator would reasonably be annoyed to discover afterwards, so the dialog
 * says all of it with THIS project's numbers in it. The numbers come from
 * /api/triage/preflight, which is why the dialog is fetched rather than static.
 */

import { useCallback, useState } from 'react'
import { Loader2, ScanSearch } from 'lucide-react'
import { useAlertModal } from '@/components/ui'
import styles from './TriageRunButton.module.css'

export interface TriagePreflight {
  projectName: string
  model: string
  hasModelKey: boolean
  inScope: number
  newSinceLastRun: number
  openFindings: number
  reviewBudget: number
  estimatedAiCalls: number
  estimatedReviewed: number
  pendingRemediations: number
  inProgressRemediations: number
  lastRun: { id: string; finishedAt: string | null; model: string } | null
  liveRun: { id: string; startedAt: string } | null
  blockedReason: string | null
  defaultRepo: string
}

interface TriageRunButtonProps {
  projectId: string | null
  /** Called once the operator has confirmed. */
  onConfirm: () => void
  /** A run is already in flight (this tab's, or one we re-attached to). */
  running?: boolean
  /**
   * Has this project been triaged before? Decides "Re-triage" vs "Start
   * Triage" on FIRST paint. The preflight call answers this authoritatively,
   * but it is far too heavy to fire on mount (a Neo4j round trip plus the
   * liveness checks), so each page passes the answer it already holds and the
   * preflight response corrects it from the first click onwards.
   */
  hasPreviousRun?: boolean
  disabled?: boolean
  /** Layout only. Colour belongs to the component: see the CSS module. */
  className?: string
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const date = new Date(iso)
  return Number.isNaN(date.getTime())
    ? 'never'
    : date.toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
}

export function buildDialog(pre: TriagePreflight) {
  const isFirstRun = !pre.lastRun
  return (
    <div className={styles.dialog}>
      <p>
        This runs one analysis. Its results replace the ranking on the{' '}
        <strong>Priority Board</strong> and update the fix list in{' '}
        <strong>CypherFix</strong>, so both pages always show the same order.
      </p>

      {isFirstRun && <p className={styles.muted}>This is the first triage for this project.</p>}

      <div className={styles.dialogHeading}>What it does, in order</div>
      <ol>
        <li>
          <strong>Score.</strong> Every finding ({pre.inScope}
          {pre.newSinceLastRun > 0 && `, of which ${pre.newSinceLastRun} are new since the last run`})
          gets a 0-100 score from the facts in the graph: how likely it is to be
          real, how likely it is to be exploited, how bad it would be, and how
          reachable it is. No AI in this step.
        </li>
        <li>
          <strong>Group.</strong> Findings that share the same fix are grouped,
          for example one CVE on three hosts.
        </li>
        <li>
          {pre.hasModelKey ? (
            <>
              <strong>AI review.</strong> {pre.model || 'The configured model'} receives
              the evidence behind each score: the request and response, the file
              path, the validation result. It can confirm a finding, correct how
              likely it is to be real or how bad it would be, dispute a fact the
              evidence contradicts, or mark it as a likely false positive. Every
              quote it gives is checked, and the score is recalculated by the same
              rules. Up to {pre.reviewBudget} findings are reviewed; findings whose
              evidence has not changed since the last review cost nothing.
            </>
          ) : (
            <>
              <strong>AI review.</strong> No AI model key is configured, so the
              board will be ranked by the score alone and the fix items will use
              standard text. Everything else works as described.
            </>
          )}
        </li>
        <li>
          <strong>Fix items.</strong> One per group, in the same order as the board.
        </li>
      </ol>

      <p>
        <strong>On the Priority Board:</strong> every finding gets a new score,
        rank, verdict and explanation. Likely false positives move to their own
        section. Nothing is muted or deleted.
      </p>
      <p>
        <strong>In CypherFix:</strong> new fix items are created and the{' '}
        {pre.pendingRemediations} pending ones are updated. Items you are working
        on ({pre.inProgressRemediations} in progress or with a PR) keep their
        content. Dismissed items are never recreated.
      </p>
      <p>
        <strong>Your own decisions</strong> — findings you marked Real or False
        positive — are never changed.
      </p>

      <p className={styles.muted}>
        While it runs (usually a few minutes), version activation, project import
        and project delete wait for it. Scans can keep running; findings they
        change during the run are left for the next one.
      </p>

      {pre.hasModelKey && (
        <p className={styles.muted}>
          Estimated: up to {pre.estimatedAiCalls} AI call
          {pre.estimatedAiCalls === 1 ? '' : 's'}. Results appear when the run
          finishes. You can leave the page.
        </p>
      )}

      {pre.lastRun && (
        <p className={styles.muted}>
          Last triaged {formatDate(pre.lastRun.finishedAt)}
          {pre.lastRun.model ? ` with ${pre.lastRun.model}` : ''}.
        </p>
      )}
    </div>
  )
}

export function TriageRunButton({
  projectId,
  onConfirm,
  running = false,
  hasPreviousRun = false,
  disabled = false,
  className,
}: TriageRunButtonProps) {
  const { confirm, alertError } = useAlertModal()
  const [checking, setChecking] = useState(false)
  // null = nothing authoritative yet, so fall back to the caller's hint.
  const [lastRunSeen, setLastRunSeen] = useState<boolean | null>(null)

  const start = useCallback(async () => {
    if (!projectId) return
    setChecking(true)
    try {
      const res = await fetch(
        `/api/triage/preflight?projectId=${encodeURIComponent(projectId)}`
      )
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || 'The project could not be checked.')
      }
      const pre: TriagePreflight = await res.json()
      setLastRunSeen(Boolean(pre.lastRun))

      if (pre.blockedReason) {
        await alertError(pre.blockedReason, 'Triage cannot start yet')
        return
      }

      const ok = await confirm(
        buildDialog(pre),
        `Run triage on ${pre.projectName}?`,
        {
          confirmLabel: pre.lastRun ? 'Re-triage' : 'Start triage',
          // This dialog is a briefing, not a yes/no: headings, a numbered
          // list and a cost estimate. At the default alert width it reflowed
          // into a column barely wide enough for a few words per line.
          size: 'large',
        }
      )
      if (ok) onConfirm()
    } catch (e) {
      await alertError(
        e instanceof Error ? e.message : 'The project could not be checked.',
        'Triage'
      )
    } finally {
      setChecking(false)
    }
  }, [projectId, confirm, alertError, onConfirm])

  const busy = checking || running
  const previouslyRun = lastRunSeen ?? hasPreviousRun
  const label = running
    ? 'Triage running...'
    : previouslyRun
      ? 'Re-triage'
      : 'Start Triage'

  return (
    <button
      type="button"
      className={`${styles.button} ${className ?? ''}`}
      onClick={() => void start()}
      disabled={busy || disabled || !projectId}
      title="Score, group and review every finding, then rebuild the fix list"
    >
      {busy ? (
        <Loader2 className={styles.spin} size={14} />
      ) : (
        <ScanSearch size={14} />
      )}
      {label}
    </button>
  )
}

export default TriageRunButton
