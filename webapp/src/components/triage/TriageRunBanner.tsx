'use client'

/**
 * The strip a page shows while a triage run it did not start in view is live:
 * a run re-attached after a reload, or one an agent started over MCP.
 *
 * Deliberately a strip and not the blocking progress overlay: during a long
 * background run the page underneath stays readable. It names who started the
 * run, because a run nobody on this screen pressed is otherwise a mystery that
 * blocks version activation for minutes.
 */

import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import {
  PUBLISHING_STOP_REFUSAL,
  triagePhaseLabel,
  type TriagePhase,
} from '@/lib/cypherfix-types'
import styles from './TriageRunBanner.module.css'
import { useRefusal } from '@/hooks/useRefusal'

/** `liveRun` from GET /api/triage/preflight. */
export interface LiveTriageRun {
  id: string
  status: string
  startedAt: string
  trigger: string
  phase: string
  progress: number
  tokenPrefix: string | null
}

/**
 * Who started the live run. The socket streams the run's phases but not its
 * origin, so this reads the preflight once per run, not per phase: preflight
 * is a graph round trip. A preflight that fails (or answers `model_required`)
 * leaves the origin unknown and the banner says nothing about it.
 */
export function useLiveTriageRun(projectId: string | null, active: boolean): LiveTriageRun | null {
  const [run, setRun] = useState<LiveTriageRun | null>(null)
  useEffect(() => {
    if (!active || !projectId) {
      setRun(null)
      return
    }
    let live = true
    fetch(`/api/triage/preflight?projectId=${encodeURIComponent(projectId)}`)
      .then(res => (res.ok ? res.json() : null))
      .then(body => { if (live) setRun((body?.liveRun as LiveTriageRun | null) ?? null) })
      .catch(() => { if (live) setRun(null) })
    return () => { live = false }
  }, [projectId, active])
  return run
}

/** "Started over MCP · rdm_ab12", or '' for a run started in the app. */
export function runOrigin(run: Pick<LiveTriageRun, 'trigger' | 'tokenPrefix'> | null): string {
  if (run?.trigger !== 'mcp') return ''
  return run.tokenPrefix ? `Started over MCP · ${run.tokenPrefix}` : 'Started over MCP'
}

interface TriageRunBannerProps {
  projectId: string | null
  /** What is running, e.g. "Priority Board running". */
  label: string
  phase: TriagePhase | null
  /** The rest of the sentence: what the page does meanwhile. */
  hint?: string
  /** A Stop the agent refused, or anything else to read that is not a failure. */
  notice?: string | null
  onDetails?: () => void
  onStop?: () => void
}

export function TriageRunBanner({
  projectId, label, phase, hint, notice, onDetails, onStop,
}: TriageRunBannerProps) {
  const run = useLiveTriageRun(projectId, true)
  const origin = runOrigin(run)
  const publishing = phase === 'publishing'
  // Stopping is the run's own permission; a read share watches the owner's run (step 4.11).
  const stopRefusal = useRefusal('triage:run', projectId)?.text ?? null

  return (
    <div className={styles.banner} role="status">
      <Loader2 className={styles.spin} size={13} aria-hidden="true" />
      <span className={styles.text}>
        {label}
        {origin && <> · <span className={styles.origin}>{origin}</span></>}
        {phase ? ` — ${triagePhaseLabel(phase)}` : ''}
        {hint ? `. ${hint}` : ''}
        {notice && <span className={styles.notice}>{notice}</span>}
      </span>
      {onDetails && (
        <button type="button" className={styles.button} onClick={onDetails}>
          Details
        </button>
      )}
      {onStop && (
        <button
          type="button"
          className={styles.button}
          onClick={onStop}
          disabled={publishing || !!stopRefusal}
          title={stopRefusal ?? (publishing ? PUBLISHING_STOP_REFUSAL : 'Stop the run; nothing is published')}
        >
          Stop
        </button>
      )}
    </div>
  )
}

export default TriageRunBanner
