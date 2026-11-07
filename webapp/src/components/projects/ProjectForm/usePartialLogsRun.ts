'use client'

import { useCallback, useEffect, useState } from 'react'
import type { PartialReconState } from '@/lib/recon-types'

/**
 * The partial run the logs drawer shows, or null to close it.
 *
 * The orchestrator's list is the source: it keeps a finished run for 60 s (the
 * drawer shows Completed or Error), then drops it, and the drawer closes. A run
 * just started is not listed until a poll answers, so the start reply stands in
 * until then, and only until then: it says `running` for good, and falling back
 * to it once the run was dropped showed a finished run as still scanning.
 */
export function usePartialLogsRun(runs: PartialReconState[]) {
  const [runId, setRunId] = useState<string | null>(null)
  const [startReply, setStartReply] = useState<PartialReconState | null>(null)

  useEffect(() => {
    if (startReply && runs.some(r => r.run_id === startReply.run_id)) setStartReply(null)
  }, [runs, startReply])

  const showStarted = useCallback((reply: PartialReconState) => {
    setStartReply(reply)
    setRunId(reply.run_id)
  }, [])

  const listed = runId ? runs.find(r => r.run_id === runId) : undefined
  const run = listed ?? (startReply && startReply.run_id === runId ? startReply : null)

  return { runId, run, setRunId, showStarted }
}
