import { NextRequest, NextResponse } from 'next/server'
import { Prisma } from '@prisma/client'
import { z } from 'zod'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { secretReentryResponse } from '@/lib/authz/secretEndpointRebind'
import { writeAudit } from '@/lib/audit'
import { auditActorOf } from '@/lib/auditActor'
import { internalError, withRouteErrors } from '@/lib/routeErrors'
import {
  assertWebhookEgressAllowed,
  DeltaAlertEgressError,
  maskChannelForApi,
  mergeChannelsForSave,
  normalizeAlertSeverity,
  parseStoredChannels,
} from '@/lib/deltaAlerts'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

const ConfigUpdateSchema = z.object({
  enabled: z.boolean(),
  minVulnSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  alertOnNewPorts: z.boolean(),
  alertOnNewHosts: z.boolean(),
  channels: z.unknown(),
})

function extractDeltaPath(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null
  const p = (payload as { deltaPath?: unknown }).deltaPath
  return typeof p === 'string' && p.startsWith('/graph') ? p : null
}

function serializeConfig(
  projectId: string,
  row: {
    enabled: boolean
    minVulnSeverity: string
    alertOnNewPorts: boolean
    alertOnNewHosts: boolean
    channels: unknown
    updatedAt?: Date
  } | null,
) {
  const stored = row ? parseStoredChannels(row.channels) : []
  return {
    projectId,
    enabled: row?.enabled ?? false,
    minVulnSeverity: normalizeAlertSeverity(row?.minVulnSeverity ?? 'high'),
    alertOnNewPorts: row?.alertOnNewPorts ?? true,
    alertOnNewHosts: row?.alertOnNewHosts ?? true,
    channels: stored.map(maskChannelForApi),
    updatedAt: row?.updatedAt ? row.updatedAt.toISOString() : null,
  }
}

export const GET = withRouteErrors('Failed to load delta alert settings', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId: id })
  if (auth instanceof NextResponse) return auth

  try {
    const [config, history] = await Promise.all([
      prisma.projectDeltaAlertConfig.findUnique({
        where: { projectId: id },
      }),
      prisma.deltaAlertOutbox.findMany({
        where: { projectId: id },
        orderBy: { createdAt: 'desc' },
        take: 25,
        select: {
          id: true,
          scanJobId: true,
          scheduleId: true,
          fromVersionId: true,
          toVersionId: true,
          channelId: true,
          channelType: true,
          channelName: true,
          status: true,
          attempts: true,
          maxAttempts: true,
          nextAttemptAt: true,
          lastStatusCode: true,
          lastError: true,
          sentAt: true,
          createdAt: true,
          payload: true,
        },
      }),
    ])

    return NextResponse.json(
      {
        config: serializeConfig(id, config),
        history: history.map((row) => ({
          id: row.id,
          scanJobId: row.scanJobId,
          scheduleId: row.scheduleId,
          fromVersionId: row.fromVersionId,
          toVersionId: row.toVersionId,
          channelId: row.channelId,
          channelType: row.channelType,
          channelName: row.channelName,
          status: row.status,
          attempts: row.attempts,
          maxAttempts: row.maxAttempts,
          nextAttemptAt: row.nextAttemptAt.toISOString(),
          lastStatusCode: row.lastStatusCode,
          lastError: row.lastError,
          sentAt: row.sentAt ? row.sentAt.toISOString() : null,
          createdAt: row.createdAt.toISOString(),
          deltaPath: extractDeltaPath(row.payload),
        })),
      },
      { headers: { 'Cache-Control': 'private, no-cache' } },
    )
  } catch (err) {
    return internalError(err, 'Failed to load delta alert settings', { log: '[deltaAlerts] GET failed' })
  }
})

export const PUT = withRouteErrors('Failed to save delta alert settings', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const auth = await requirePermission(request, 'recon:schedule', { projectId: id })
  if (auth instanceof NextResponse) return auth

  let body: unknown
  try {
    body = await request.json()
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  const parsed = ConfigUpdateSchema.safeParse(body)
  if (!parsed.success) {
    return NextResponse.json(
      { error: parsed.error.issues[0]?.message || 'Invalid delta alert configuration' },
      { status: 400 },
    )
  }

  try {
    const existing = await prisma.projectDeltaAlertConfig.findUnique({
      where: { projectId: id },
    })
    const existingChannels = existing ? parseStoredChannels(existing.channels) : []
    const merged = mergeChannelsForSave(existingChannels, parsed.data.channels)

    if (!merged.ok) {
      if ('secretReentry' in merged) {
        return secretReentryResponse(merged.secretReentry)
      }
      return NextResponse.json({ error: merged.error }, { status: 400 })
    }

    for (const ch of merged.channels) {
      try {
        await assertWebhookEgressAllowed(ch.url, ch.type)
      } catch (err) {
        if (err instanceof DeltaAlertEgressError) {
          return NextResponse.json({ error: err.message, code: err.code }, { status: 400 })
        }
        throw err
      }
    }

    const saved = await prisma.projectDeltaAlertConfig.upsert({
      where: { projectId: id },
      create: {
        projectId: id,
        enabled: parsed.data.enabled,
        minVulnSeverity: parsed.data.minVulnSeverity,
        alertOnNewPorts: parsed.data.alertOnNewPorts,
        alertOnNewHosts: parsed.data.alertOnNewHosts,
        channels: merged.channels as unknown as Prisma.InputJsonValue,
      },
      update: {
        enabled: parsed.data.enabled,
        minVulnSeverity: parsed.data.minVulnSeverity,
        alertOnNewPorts: parsed.data.alertOnNewPorts,
        alertOnNewHosts: parsed.data.alertOnNewHosts,
        channels: merged.channels as unknown as Prisma.InputJsonValue,
      },
    })

    const actor = auth.principal
      ? auditActorOf(auth.principal, auth.effective.userId)
      : { actorId: auth.effective.userId }

    await writeAudit({
      ...actor,
      projectId: id,
      permission: 'recon:schedule',
      action: 'delta_alert.update',
      targetType: 'projectDeltaAlertConfig',
      targetId: id,
      after: {
        enabled: saved.enabled,
        minVulnSeverity: saved.minVulnSeverity,
        alertOnNewPorts: saved.alertOnNewPorts,
        alertOnNewHosts: saved.alertOnNewHosts,
        channelCount: merged.channels.length,
      },
    })

    return NextResponse.json({
      ok: true,
      config: serializeConfig(id, saved),
    })
  } catch (err) {
    return internalError(err, 'Failed to save delta alert settings', { log: '[deltaAlerts] PUT failed' })
  }
})
