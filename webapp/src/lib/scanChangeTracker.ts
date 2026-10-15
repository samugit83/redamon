/**
 * Scheduled-scan change pipeline (help-wanted: baseline diff + alerts).
 *
 * Called best-effort after a full_recon ScanJob closes as `completed`:
 * diff the frozen snapshots of this run vs the previous completed run,
 * persist the delta as ScanChange (baseline storage for the timeline UI),
 * and fan out to the project's configured Slack / generic webhooks.
 *
 * Never throws: history and alerts are side effects of closing a scan, and a
 * failure here must not fail the status poll that called it. Webhook URLs are
 * never logged or returned to the browser (bearer secrets).
 */
import prisma from '@/lib/prisma'
import { diffSnapshots, summarizeDiff, type ScanDiff } from './scanDiff'
import {
  formatScanAlertText,
  sendGenericWebhook,
  sendSlackAlert,
} from './scanAlerts'
import { loadSnapshot } from './scanSnapshot'

export interface TrackResult {
  /** False when there was nothing to compare (first scan) or on any error. */
  tracked: boolean
  empty?: boolean
}

function capList(items: string[], max = 500): string[] {
  return items.length > max ? items.slice(0, max) : items
}

/**
 * Compute, store and alert on the changes for a freshly completed ScanJob.
 * Safe to call for any job: non-full_recon or non-completed jobs are ignored.
 */
export async function trackCompletedScan(scanJobId: string): Promise<TrackResult> {
  try {
    const job = await prisma.scanJob.findUnique({
      where: { id: scanJobId },
      select: {
        id: true, projectId: true, kind: true, status: true,
        versionId: true, scheduleId: true,
      },
    })
    if (!job || job.kind !== 'full_recon' || job.status !== 'completed' || !job.versionId) {
      return { tracked: false }
    }

    // Previous completed full_recon run with a frozen snapshot (not this job).
    const prev = await prisma.scanJob.findFirst({
      where: {
        projectId: job.projectId,
        kind: 'full_recon',
        status: 'completed',
        id: { not: job.id },
        versionId: { not: null },
      },
      orderBy: { finishedAt: 'desc' },
      select: { id: true, versionId: true },
    })

    const [project, schedule] = await Promise.all([
      prisma.project.findUnique({ where: { id: job.projectId }, select: { id: true, name: true } }),
      job.scheduleId
        ? prisma.scanSchedule.findUnique({ where: { id: job.scheduleId }, select: { label: true } })
        : Promise.resolve(null),
    ])
    if (!project) return { tracked: false }

    // First-ever scan: nothing to diff against. Record an empty baseline row so
    // the timeline shows "baseline" instead of "unknown".
    if (!prev?.versionId) {
      await prisma.scanChange.upsert({
        where: { scanJobId: job.id },
        create: { projectId: job.projectId, scanJobId: job.id, newVersionId: job.versionId },
        update: {},
      })
      return { tracked: true, empty: true }
    }

    const [oldSnap, newSnap] = await Promise.all([
      loadSnapshot(prev.versionId),
      loadSnapshot(job.versionId),
    ])
    if (!oldSnap || !newSnap) return { tracked: false }

    const d: ScanDiff = diffSnapshots(oldSnap.nodes, newSnap.nodes)

    await prisma.scanChange.upsert({
      where: { scanJobId: job.id },
      create: {
        projectId: job.projectId,
        scanJobId: job.id,
        oldVersionId: prev.versionId,
        newVersionId: job.versionId,
        newSubdomains: capList(d.newSubdomains),
        removedSubdomains: capList(d.removedSubdomains),
        newPorts: d.newPorts.slice(0, 500) as object,
        removedPorts: d.removedPorts.slice(0, 500) as object,
        newCves: capList(d.newCves),
        newVulnCount: d.newVulnCount,
      },
      update: {
        oldVersionId: prev.versionId,
        newVersionId: job.versionId,
        newSubdomains: capList(d.newSubdomains),
        removedSubdomains: capList(d.removedSubdomains),
        newPorts: d.newPorts.slice(0, 500) as object,
        removedPorts: d.removedPorts.slice(0, 500) as object,
        newCves: capList(d.newCves),
        newVulnCount: d.newVulnCount,
      },
    })

    if (!d.empty) {
      await fanOutAlerts({
        projectId: job.projectId,
        projectName: project.name,
        scanJobId: job.id,
        scheduleId: job.scheduleId,
        scheduleLabel: schedule?.label ?? null,
        diff: d,
      }).catch(err => console.error('[scanChanges] alert fan-out failed (continuing):', err))
    }

    return { tracked: true, empty: d.empty }
  } catch (err) {
    console.error('[scanChanges] trackCompletedScan failed (continuing):', err)
    return { tracked: false }
  }
}

async function fanOutAlerts(opts: {
  projectId: string
  projectName: string
  scanJobId: string
  scheduleId: string | null
  scheduleLabel: string | null
  diff: ScanDiff
}): Promise<void> {
  const cfg = await prisma.scanAlertConfig.findUnique({
    where: { projectId: opts.projectId },
  })
  if (!cfg || !cfg.enabled) return

  const hasNew =
    opts.diff.newSubdomains.length > 0 ||
    opts.diff.newPorts.length > 0 ||
    opts.diff.newCves.length > 0 ||
    opts.diff.newVulnCount > 0
  const hasRemoved =
    opts.diff.removedSubdomains.length > 0 || opts.diff.removedPorts.length > 0
  if (hasNew && !cfg.notifyOnNew) return
  if (!hasNew && hasRemoved && !cfg.notifyOnRemoved) return
  if (!hasNew && !hasRemoved) return

  const summary = summarizeDiff(opts.diff)
  const text = formatScanAlertText({
    projectName: opts.projectName,
    scheduleLabel: opts.scheduleLabel ?? undefined,
    diff: opts.diff,
  })

  const sends: Array<Promise<{ channel: string; ok: boolean; error?: string }>> = []
  if (cfg.slackWebhookUrl) {
    sends.push(
      sendSlackAlert(cfg.slackWebhookUrl, text).then(r => ({ channel: 'slack', ...r }))
    )
  }
  if (cfg.genericWebhookUrl) {
    sends.push(
      sendGenericWebhook(cfg.genericWebhookUrl, {
        event: 'scan.changes',
        projectId: opts.projectId,
        projectName: opts.projectName,
        scanJobId: opts.scanJobId,
        scheduleId: opts.scheduleId,
        summary,
        newSubdomains: opts.diff.newSubdomains.slice(0, 500),
        removedSubdomains: opts.diff.removedSubdomains.slice(0, 500),
        newPorts: opts.diff.newPorts.slice(0, 500),
        removedPorts: opts.diff.removedPorts.slice(0, 500),
        newCves: opts.diff.newCves.slice(0, 500),
        newVulnCount: opts.diff.newVulnCount,
        at: new Date().toISOString(),
      }).then(r => ({ channel: 'webhook', ...r }))
    )
  }
  if (sends.length === 0) return

  const results = await Promise.all(sends)
  await Promise.all(
    results.map(r =>
      prisma.scanAlert
        .create({
          data: {
            projectId: opts.projectId,
            scanJobId: opts.scanJobId,
            channel: r.channel,
            status: r.ok ? 'sent' : 'failed',
            error: r.ok ? '' : (r.error ?? 'send failed').slice(0, 500),
          },
        })
        .catch(err => console.error('[scanChanges] could not record alert outcome:', err))
    )
  )
}
