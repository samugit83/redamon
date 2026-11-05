/**
 * The MCP write tools: start_recon, stop_recon, update_recon_settings.
 *
 * These are the three places where an external agent changes something, so each
 * one is deliberately stricter than the equivalent button in the UI:
 *
 *  - start_recon refuses while a human is mid-session with the UI agent or a
 *    triage run. `describeScanWriters` excludes those on purpose, because a
 *    person running the agent alongside a scan is normal and they can see both.
 *    An UNATTENDED external caller has no way to know, and a full scan would
 *    wipe the graph underneath them.
 *  - update_recon_settings refuses while a scan is writing the graph, because
 *    recon reads its settings ONCE at container spawn. A mid-scan write is
 *    inert, and silently accepting it would report success for a change that
 *    does nothing.
 *  - mode:"overwrite" needs its own scope. Discarding the current graph is the
 *    only irreversible action on this surface, and an agent can be talked into
 *    it by data it reads (the graph is full of attacker-controlled text), so
 *    the containment is a code check rather than prompt wording.
 */
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'
import { describeLiveGraphWriters, describeScanWriters } from '@/lib/graphWriters'
import { startFullScan } from '@/lib/startFullScan'
import { writeAudit } from '@/lib/audit'
import { FINGERPRINT_FIELDS } from '@/lib/jobQueue'
import { currentFingerprintFor } from '@/lib/jobFingerprint'
import { assertMcpProjectAccess, requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import {
  auditableKey,
  filterReconSettings,
  projectReconSettings,
  reconSettingsSelect,
} from '@/lib/reconSettings/filter'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'
import { validateCrossFieldRules, writeFireteamAudit } from '@/lib/reconSettings/crossField'
import { validateJevEngineChange } from '@/lib/reconSettings/jevEngine'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

export type ScanStartMode = 'new' | 'overwrite'

export async function startRecon(
  ctx: McpContext,
  projectId: string,
  mode: ScanStartMode = 'new'
) {
  requireScope(ctx.token, 'recon:scan')
  // Split from recon:scan deliberately: 'overwrite' DISCARDS the current graph.
  if (mode === 'overwrite') requireScope(ctx.token, 'recon:overwrite')

  await assertMcpProjectAccess(ctx.token.userId, projectId)

  // Stricter than the button (see the file header). describeLiveGraphWriters
  // also covers Conversation.agentRunning and live TriageRuns.
  //
  // Checked BEFORE the rate limit: a start refused because the graph is busy
  // launched nothing and consumed no retention slot, so burning the 5-minute
  // window on it would punish an agent that did nothing wrong.
  const live = await describeLiveGraphWriters(projectId)
  if (live) {
    throw new McpToolError(
      `Cannot start a scan: ${live} for this project. A full scan would wipe the ` +
      'graph underneath it. Stop it first, or wait for it to finish.',
      'busy'
    )
  }

  // Strict, and keyed on the PROJECT alone (not the token): the limit exists
  // because a 'new' start consumes a retention slot and permanently deletes the
  // oldest unpinned version. A user holding N tokens would otherwise churn the
  // timeline N times faster than the documented one-per-5-minutes.
  enforceRate(ctx, 'start', projectId, { perProject: true })

  const result = await startFullScan({
    projectId,
    mode,
    trigger: 'manual',
    actorUserId: ctx.token.userId,
  })

  if (!result.ok) {
    // The audit record carries the channel, so the ScanTrigger union stays
    // 'manual' | 'scheduled' - the timeline UI renders it.
    void writeAudit({
      actorId: ctx.token.userId,
      action: 'mcp.start_recon.refused',
      targetType: 'project',
      targetId: projectId,
      after: {
        tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
        status: result.status, mode, scanJobId: result.scanJobId ?? null,
        startOutcome: result.startOutcome ?? null,
      },
      source: 'mcp',
    })
    if (result.startOutcome === 'unknown') {
      throw new McpToolError(
        `${result.error} Call get_recon_status before retrying.`,
        'start_outcome_unknown'
      )
    }
    throw new McpToolError(
      result.limit
        ? `${result.error} (${JSON.stringify(result.limit)})`
        : result.error,
      `start_refused_${result.status}`
    )
  }

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.start_recon',
    targetType: 'project',
    targetId: projectId,
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      mode, scanJobId: result.scanJobId, versionId: result.versionId,
    },
    source: 'mcp',
  })

  const state = result.state as Record<string, unknown>
  return {
    status: state.status ?? 'starting',
    currentPhase: state.current_phase ?? state.currentPhase ?? null,
    scanVersion: { id: result.versionId, seq: result.versionSeq, label: result.versionLabel },
    frozenVersionId: result.frozenVersionId,
    frozenNodeCount: result.frozenNodeCount,
    mode,
    scanJobId: result.scanJobId,
    ...(mode === 'new'
      ? { note: 'mode "new" saved the previous graph as a version, consuming a retention slot.' }
      : { note: 'mode "overwrite" DISCARDED the previous graph. It cannot be recovered.' }),
  }
}

/**
 * An agent that can start a scan must be able to stop one. Withholding that
 * forces a human to the UI to undo a machine's mistake.
 */
export async function stopRecon(ctx: McpContext, projectId: string) {
  requireScope(ctx.token, 'recon:scan')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'write')

  // The orchestrator answers a stop with the POST-stop state, which is `idle`
  // whether it just killed a scan or there was never one running. Returning
  // that verbatim left an agent unable to report what it had done - and left a
  // stray stop that really did kill a running scan looking like a no-op. So
  // observe first, and say so. `null` where the observation failed: on this
  // surface "I could not tell" is never reported as "nothing was running".
  let wasRunning: boolean | null = null
  try {
    const pre = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/status`)
    if (pre.ok) {
      const status = (await pre.json() as { status?: unknown })?.status
      wasRunning = status !== 'idle' && status !== 'completed' && status !== undefined
    }
  } catch (err) {
    console.error('[mcp] stop_recon pre-stop status unreadable:', err)
  }

  let resp: Response
  try {
    resp = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/recon/${projectId}/stop`, {
      method: 'POST',
    })
  } catch (err) {
    console.error('[mcp] stop_recon transport error:', err)
    throw new McpToolError(
      'The orchestrator is unreachable, so it is unknown whether the scan stopped.',
      'status_unknown'
    )
  }
  if (!resp.ok) {
    console.error(`[mcp] stop_recon returned ${resp.status}`)
    throw new McpToolError('The scan could not be stopped.', 'stop_failed')
  }

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.stop_recon',
    targetType: 'project',
    targetId: projectId,
    after: {
      tokenId: ctx.token.tokenId,
      tokenPrefix: ctx.token.tokenPrefix,
      // Distinguished in the log too: reading back "a token stopped a scan" for
      // a call that halted nothing is how an incident review reaches the wrong
      // conclusion about which agent ended a run.
      outcome: wasRunning === null ? 'ok_unverified'
        : wasRunning ? 'stopped' : 'nothing_running',
    },
    source: 'mcp',
  })
  return {
    ...(await resp.json() as Record<string, unknown>),
    stopped: wasRunning,
    note: wasRunning === null
      ? 'The stop was issued, but the scan state could not be read beforehand, so '
        + 'whether anything was actually running is unknown.'
      : wasRunning
        ? 'A scan was running and has been told to stop. Poll get_recon_status '
          + 'until it reports idle.'
        : 'Nothing was running, so nothing was stopped.',
  }
}

/** Queued scans whose settings fingerprint no longer matches, so the dispatcher will park them. */
export interface QueuedJobsNeedingReview {
  count: number
  jobIds: string[]
}

export interface UpdateSettingsResult {
  projectId: string
  updated: Record<string, unknown>
  changed: string[]
  queuedJobsNeedingReview: QueuedJobsNeedingReview
  /** Enabled schedules this change silently alters (plan 11.3). */
  affectedSchedules: { count: number; names: string[] }
  note: string
}

/**
 * The `updatedAt` a compare-and-swap write must still find: the caller's
 * `expectedUpdatedAt` when it passed one, otherwise the value this call read.
 */
export function casVersion(read: unknown, expectedUpdatedAt?: string): Date {
  if (!expectedUpdatedAt) {
    // Prisma drops an `undefined` filter, so a missing read would turn the
    // compare-and-swap into an unconditional write.
    if (!(read instanceof Date) || Number.isNaN(read.getTime())) {
      throw new Error('[mcp] the project updatedAt was not read; refusing an unconditional write')
    }
    return read
  }
  const expected = new Date(expectedUpdatedAt)
  if (Number.isNaN(expected.getTime())) {
    throw new McpToolError('expectedUpdatedAt is not a valid timestamp.', 'bad_args')
  }
  return expected
}

export async function updateReconSettings(
  ctx: McpContext,
  projectId: string,
  settings: unknown,
  expectedUpdatedAt?: string
): Promise<UpdateSettingsResult> {
  requireScope(ctx.token, 'recon:settings')
  await assertMcpProjectAccess(ctx.token.userId, projectId)
  enforceRate(ctx, 'write')

  // Recon reads its settings ONCE, at container spawn. A write after a start
  // does not affect the running scan, so accepting it would report success for
  // a change that does nothing. describeScanWriters fails closed on an
  // unverifiable status.
  const busy = await describeScanWriters(projectId)
  if (busy) {
    throw new McpToolError(
      `Cannot change settings while ${busy} for this project: the running scan read its ` +
      'settings when it started and will not see the change. Wait for it to finish.',
      'busy'
    )
  }

  const filtered = filterReconSettings(settings, { projectId })
  if (!filtered.ok) {
    // Named, never silently stripped: a caller who believes a setting applied
    // would act on a scan configured differently from the one they asked for.
    throw new McpToolError(filtered.error, 'setting_rejected', { rejectedKey: auditableKey(filtered.key) })
  }

  const before = await prisma.project.findUnique({
    where: { id: projectId },
    select: { ...reconSettingsSelect(), updatedAt: true, userId: true },
  })
  if (!before) throw new McpToolError('Project not found', 'not_found')

  // The rules over several fields that the project form's save enforces. Judged
  // on the stored row with this change applied, so a rule over two fields sees
  // both even when the caller sent one.
  const nextRow: Record<string, unknown> = { ...(before as Record<string, unknown>), ...filtered.data }
  const crossField = await validateCrossFieldRules(
    nextRow, Object.keys(filtered.data), ctx.token.userId, { ownerUserId: before.userId }
  )
  if (crossField) throw new McpToolError(crossField, 'setting_rejected')
  // The cross-field check normalized the user-skill toggles in nextRow (foreign ids dropped).
  if ('attackSkillConfig' in filtered.data) filtered.data.attackSkillConfig = nextRow.attackSkillConfig

  // A switch onto the Jev engine needs a selected Jev provider on the project OWNER's
  // account (not the token's user): the agent resolves the key from the owner.
  const jevError = await validateJevEngineChange(
    before as Record<string, unknown>, filtered.data, before.userId)
  if (jevError) throw new McpToolError(jevError, 'setting_rejected')

  // Always a compare-and-swap, on the caller's expectedUpdatedAt or else on the
  // value just read. Without the second, two agents writing at once each read,
  // then wrote, and the later one's audit `before` described a state that no
  // longer existed. Never retried here: a conflict is the caller's to resolve.
  const { count } = await prisma.project.updateMany({
    where: { id: projectId, updatedAt: casVersion(before.updatedAt, expectedUpdatedAt) },
    data: filtered.data,
  })
  if (count === 0) {
    throw new McpToolError(
      'The project changed since you read it. Re-read get_recon_settings and retry.',
      'conflict'
    )
  }

  const after = await prisma.project.findUnique({
    where: { id: projectId },
    select: reconSettingsSelect(),
  })
  const updated = projectReconSettings((after ?? {}) as Record<string, unknown>)
  const changed = Object.keys(filtered.data)
  await writeFireteamAudit(projectId, before as Record<string, unknown>, filtered.data, {
    userId: ctx.token.userId, source: 'mcp',
  })

  void writeAudit({
    actorId: ctx.token.userId,
    action: 'mcp.update_recon_settings',
    targetType: 'project',
    targetId: projectId,
    before: Object.fromEntries(
      changed.map(k => [k, (before as Record<string, unknown>)[k]])
    ),
    after: {
      tokenId: ctx.token.tokenId, tokenPrefix: ctx.token.tokenPrefix,
      changes: Object.fromEntries(changed.map(k => [k, updated[k]])),
    },
    source: 'mcp',
  })

  const [queuedJobsNeedingReview, affectedSchedules] = await Promise.all([
    countQueuedJobsNeedingReview(projectId),
    describeAffectedSchedules(projectId),
  ])

  return {
    projectId,
    updated,
    changed,
    queuedJobsNeedingReview,
    affectedSchedules,
    note: 'Settings apply to the NEXT scan. A scan already running read its settings when it started.',
  }
}

/**
 * A settings change can park a queued scan: the dispatcher compares a
 * fingerprint taken at enqueue and moves the row to needs_review when it moved,
 * and only a person can release it. An agent that was not told would sit
 * waiting for a scan that is now blocked on a human.
 *
 * Computed exactly as the dispatcher computes it. Hashing the row alone left
 * out the auth profile, so every queued full and partial recon read as parked.
 */
export async function countQueuedJobsNeedingReview(projectId: string): Promise<QueuedJobsNeedingReview> {
  try {
    const [project, queued] = await Promise.all([
      prisma.project.findUnique({ where: { id: projectId } }),
      prisma.jobQueue.findMany({
        where: { projectId, status: 'queued' },
        select: { id: true, kind: true, projectId: true, payload: true, settingsHash: true },
      }),
    ])
    if (!project || queued.length === 0) return { count: 0, jobIds: [] }
    const row = project as unknown as Record<string, unknown>
    const jobIds: string[] = []
    for (const job of queued) {
      if (!FINGERPRINT_FIELDS[job.kind]) continue
      if (await currentFingerprintFor(job, row) !== job.settingsHash) jobIds.push(job.id)
    }
    return { count: jobIds.length, jobIds }
  } catch (err) {
    console.error('[mcp] could not evaluate queued-job fingerprints:', err)
    return { count: 0, jobIds: [] }
  }
}

/**
 * Scheduled scans have NO fingerprint guard: the scheduler calls startFullScan
 * with whatever settings are current. So a settings change silently alters
 * every future scheduled run. Report-only for now; pausing them is a product
 * decision, not this tool's to make.
 */
/** What a caller refused as busy by describeLiveGraphWriters can do about it. */
export function busyHint(busy: string): string {
  // A flag the agent disowns is cleared before this is reached, so what is
  // left is a confirmed session or an agent that did not answer.
  if (busy.includes('could not be reached')) return 'The agent did not answer; check that its container is up, then retry.'
  if (busy.includes('agent session')) return 'A person can stop the session in the RedAmon UI, or wait for it to finish.'
  return 'Wait for it to finish.'
}

export async function describeAffectedSchedules(projectId: string) {
  try {
    const schedules = await prisma.scanSchedule.findMany({
      where: { projectId, enabled: true },
      select: { id: true, label: true },
    })
    return {
      count: schedules.length,
      names: schedules.map(s => s.label || s.id),
    }
  } catch (err) {
    console.error('[mcp] could not list affected schedules:', err)
    return { count: 0, names: [] }
  }
}
