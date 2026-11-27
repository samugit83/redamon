import prisma from '@/lib/prisma'
import { Prisma } from '@prisma/client'
import { computeReconDelta, type ReconDelta } from '@/lib/reconDelta'
import { SCOPE_SELECT, currentScanRoots } from '@/lib/scanCoverage'
import { captureGraphSnapshot, loadSnapshot, snapshotToGraphPayload } from '@/lib/scanSnapshot'
import { describeLiveGraphWriters } from '@/lib/graphWriters'
import type { FormattedGraphData } from '@/app/api/graph/format'
import { formatSafeEgressError, postWebhookSafe, type PostWebhookOptions } from './egress'
import {
  buildDedupKey,
  buildDeltaAlertPayload,
  computeBackoffMs,
  evaluateDeltaRelevance,
  formatSlackPayload,
  normalizeAlertSeverity,
} from './relevance'
import { parseStoredChannels } from './secrets'
import { signWebhookPayload } from './sign'
import type {
  DeltaAlertSummaryPayload,
  DeltaAlertThresholds,
  StoredDeltaAlertChannel,
} from './types'

export interface ChannelDeliveryResult {
  ok: boolean
  statusCode: number | null
  error?: string
}

export interface DeliverChannelDeps extends PostWebhookOptions {
  nowSec?: () => number
}

/**
 * Formats and delivers one alert payload to a configured webhook or Slack channel.
 * Errors and non-2xx summaries never echo secrets or full Slack webhook paths.
 */
export async function deliverToChannel(
  channel: StoredDeltaAlertChannel,
  payload: DeltaAlertSummaryPayload,
  deps: DeliverChannelDeps = {},
): Promise<ChannelDeliveryResult> {
  const rawBody =
    channel.type === 'slack'
      ? JSON.stringify(formatSlackPayload(payload))
      : JSON.stringify(payload)

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'RedAmon-delta-alerts/1',
    'X-RedAmon-Event': payload.event,
  }

  if (channel.type === 'webhook' && channel.secret) {
    const ts = deps.nowSec ? deps.nowSec() : Math.floor(Date.now() / 1000)
    headers['X-RedAmon-Timestamp'] = String(ts)
    headers['X-RedAmon-Signature-256'] = signWebhookPayload(channel.secret, ts, rawBody)
  }

  try {
    const res = await postWebhookSafe(channel.url, channel.type, rawBody, headers, deps)
    if (res.statusCode >= 200 && res.statusCode < 300) {
      return { ok: true, statusCode: res.statusCode }
    }
    return {
      ok: false,
      statusCode: res.statusCode,
      error: `Endpoint returned HTTP ${res.statusCode}`,
    }
  } catch (err) {
    return {
      ok: false,
      statusCode: null,
      error: formatSafeEgressError(err),
    }
  }
}

export interface EnqueueDeltaAlertsDeps {
  loadSnapshotFn?: (versionId: string) => Promise<Awaited<ReturnType<typeof loadSnapshot>>>
  captureLiveFn?: (projectId: string) => Promise<Awaited<ReturnType<typeof captureGraphSnapshot>>>
  describeLiveWritersFn?: (projectId: string) => Promise<string | null>
  computeDeltaFn?: (
    fromData: FormattedGraphData,
    toData: FormattedGraphData,
    scanRoots?: ReadonlySet<string> | null,
  ) => ReconDelta
}

export type EnqueueOutcome = {
  enqueued: number
  skipped?:
    | 'not_found'
    | 'not_eligible'
    | 'disabled'
    | 'no_channels'
    | 'no_version'
    | 'no_baseline'
    | 'graph_busy'
    | 'no_target_graph'
    | 'below_threshold'
}

function thresholdsFromConfig(config: {
  minVulnSeverity: string
  alertOnNewPorts: boolean
  alertOnNewHosts: boolean
}): DeltaAlertThresholds {
  return {
    minVulnSeverity: normalizeAlertSeverity(config.minVulnSeverity),
    alertOnNewPorts: config.alertOnNewPorts,
    alertOnNewHosts: config.alertOnNewHosts,
  }
}

function isUniqueConstraintError(err: unknown): boolean {
  if (err instanceof Prisma.PrismaClientKnownRequestError) return err.code === 'P2002'
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === 'P2002'
}

/**
 * Evaluates a newly completed scheduled `full_recon` ScanJob against the previous
 * baseline snapshot and writes idempotent `DeltaAlertOutbox` rows when enabled
 * thresholds match. Never throws to callers that fire-and-forget on scan close.
 */
export async function enqueueDeltaAlertsForScanJob(
  scanJobId: string,
  deps: EnqueueDeltaAlertsDeps = {},
): Promise<EnqueueOutcome> {
  const job = await prisma.scanJob.findUnique({
    where: { id: scanJobId },
    select: {
      id: true,
      projectId: true,
      scheduleId: true,
      kind: true,
      trigger: true,
      status: true,
      versionId: true,
      project: { select: { id: true, name: true, ...SCOPE_SELECT } },
    },
  })
  if (!job) return { enqueued: 0, skipped: 'not_found' }
  if (job.trigger !== 'scheduled' || job.kind !== 'full_recon' || job.status !== 'completed') {
    return { enqueued: 0, skipped: 'not_eligible' }
  }
  if (!job.versionId) return { enqueued: 0, skipped: 'no_version' }

  const config = await prisma.projectDeltaAlertConfig.findUnique({
    where: { projectId: job.projectId },
  })
  if (!config || !config.enabled) return { enqueued: 0, skipped: 'disabled' }

  const channels = parseStoredChannels(config.channels).filter((c) => c.enabled)
  if (channels.length === 0) return { enqueued: 0, skipped: 'no_channels' }

  const toVersion = await prisma.scanVersion.findFirst({
    where: { id: job.versionId, projectId: job.projectId },
    select: { id: true, seq: true, isCurrent: true },
  })
  if (!toVersion) return { enqueued: 0, skipped: 'no_version' }

  const fromVersion = await prisma.scanVersion.findFirst({
    where: {
      projectId: job.projectId,
      seq: { lt: toVersion.seq },
      snapshot: { not: null },
    },
    orderBy: { seq: 'desc' },
    select: { id: true, seq: true },
  })
  if (!fromVersion) return { enqueued: 0, skipped: 'no_baseline' }

  const loadSnap = deps.loadSnapshotFn ?? loadSnapshot
  const captureLive = deps.captureLiveFn ?? captureGraphSnapshot
  const checkWriters = deps.describeLiveWritersFn ?? describeLiveGraphWriters

  const fromSnap = await loadSnap(fromVersion.id)
  if (!fromSnap) return { enqueued: 0, skipped: 'no_baseline' }
  const fromData = snapshotToGraphPayload(fromSnap)

  let toData: FormattedGraphData | null = null
  if (toVersion.isCurrent) {
    const busy = await checkWriters(job.projectId)
    if (busy) return { enqueued: 0, skipped: 'graph_busy' }
    const captured = await captureLive(job.projectId)
    toData = snapshotToGraphPayload(captured)
  } else {
    const toSnap = await loadSnap(toVersion.id)
    if (toSnap) toData = snapshotToGraphPayload(toSnap)
  }
  if (!toData) return { enqueued: 0, skipped: 'no_target_graph' }

  const roots = job.project ? currentScanRoots(job.project) : null
  const delta = deps.computeDeltaFn
    ? deps.computeDeltaFn(fromData, toData, roots)
    : computeReconDelta(fromData, toData, undefined, roots)

  const thresholds = thresholdsFromConfig(config)
  const relevance = evaluateDeltaRelevance(delta, thresholds)
  if (!relevance.shouldAlert) return { enqueued: 0, skipped: 'below_threshold' }

  const payload = buildDeltaAlertPayload({
    event: 'recon.delta',
    projectId: job.projectId,
    projectName: job.project?.name || job.projectId,
    scanJobId: job.id,
    scheduleId: job.scheduleId ?? null,
    fromVersionId: fromVersion.id,
    toVersionId: toVersion.id,
    relevance,
  })

  let enqueued = 0
  for (const ch of channels) {
    const dedupKey = buildDedupKey(job.projectId, toVersion.id, relevance.deltaHash, ch.id)
    try {
      await prisma.deltaAlertOutbox.create({
        data: {
          projectId: job.projectId,
          scanJobId: job.id,
          scheduleId: job.scheduleId ?? null,
          fromVersionId: fromVersion.id,
          toVersionId: toVersion.id,
          channelId: ch.id,
          channelType: ch.type,
          channelName: ch.name,
          dedupKey,
          status: 'pending',
          payload: payload as unknown as Prisma.InputJsonValue,
        },
      })
      enqueued += 1
    } catch (err) {
      if (isUniqueConstraintError(err)) continue
      throw err
    }
  }

  return { enqueued }
}

export interface ProcessOutboxResult {
  processed: number
  sent: number
  retried: number
  failed: number
}

/**
 * Delivers due pending rows from `DeltaAlertOutbox`. Live channel URLs and
 * secrets are read from `ProjectDeltaAlertConfig` at delivery time so secrets
 * are never duplicated in outbox rows.
 */
export async function processAlertOutbox(opts: {
  limit?: number
  now?: Date
  deliverDeps?: DeliverChannelDeps
} = {}): Promise<ProcessOutboxResult> {
  const now = opts.now ?? new Date()
  const limit = Math.max(1, Math.min(opts.limit ?? 25, 100))

  const due = await prisma.deltaAlertOutbox.findMany({
    where: {
      status: 'pending',
      nextAttemptAt: { lte: now },
    },
    orderBy: { nextAttemptAt: 'asc' },
    take: limit,
  })

  if (due.length === 0) {
    return { processed: 0, sent: 0, retried: 0, failed: 0 }
  }

  const projectIds = [...new Set(due.map((r) => r.projectId))]
  const configs = await prisma.projectDeltaAlertConfig.findMany({
    where: { projectId: { in: projectIds } },
    select: { projectId: true, enabled: true, channels: true },
  })
  const channelMap = new Map<string, StoredDeltaAlertChannel>()
  for (const cfg of configs) {
    if (!cfg.enabled) continue
    for (const ch of parseStoredChannels(cfg.channels)) {
      if (ch.enabled) channelMap.set(`${cfg.projectId}:${ch.id}`, ch)
    }
  }

  let sent = 0
  let retried = 0
  let failed = 0

  for (const row of due) {
    const channel = channelMap.get(`${row.projectId}:${row.channelId}`)
    if (!channel) {
      await prisma.deltaAlertOutbox.update({
        where: { id: row.id },
        data: {
          status: 'failed',
          attempts: row.attempts + 1,
          lastStatusCode: null,
          lastError: 'Alert channel is missing or disabled',
        },
      })
      failed += 1
      continue
    }

    const payload = row.payload as unknown as DeltaAlertSummaryPayload
    const res = await deliverToChannel(channel, payload, opts.deliverDeps)
    const nextAttempts = row.attempts + 1

    if (res.ok) {
      await prisma.deltaAlertOutbox.update({
        where: { id: row.id },
        data: {
          status: 'sent',
          attempts: nextAttempts,
          lastStatusCode: res.statusCode,
          lastError: null,
          sentAt: now,
        },
      })
      sent += 1
    } else if (nextAttempts >= row.maxAttempts) {
      await prisma.deltaAlertOutbox.update({
        where: { id: row.id },
        data: {
          status: 'failed',
          attempts: nextAttempts,
          lastStatusCode: res.statusCode,
          lastError: (res.error ?? 'Delivery failed').slice(0, 300),
        },
      })
      failed += 1
    } else {
      const backoffMs = computeBackoffMs(nextAttempts)
      await prisma.deltaAlertOutbox.update({
        where: { id: row.id },
        data: {
          status: 'pending',
          attempts: nextAttempts,
          nextAttemptAt: new Date(now.getTime() + backoffMs),
          lastStatusCode: res.statusCode,
          lastError: (res.error ?? 'Delivery failed').slice(0, 300),
        },
      })
      retried += 1
    }
  }

  return { processed: due.length, sent, retried, failed }
}
