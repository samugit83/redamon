import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requirePermission } from '@/lib/authz/guards'
import { writeAudit } from '@/lib/audit'
import { auditActorOf } from '@/lib/auditActor'
import { internalError, withRouteErrors } from '@/lib/routeErrors'
import {
  buildDeltaAlertPayload,
  deliverToChannel,
  parseStoredChannels,
} from '@/lib/deltaAlerts'

export const runtime = 'nodejs'

interface RouteParams {
  params: Promise<{ id: string }>
}

export const POST = withRouteErrors('Failed to test delta alert channel', async (request: NextRequest, { params }: RouteParams) => {
  const { id } = await params
  const auth = await requirePermission(request, 'recon:schedule', { projectId: id })
  if (auth instanceof NextResponse) return auth

  let channelId: string | undefined
  try {
    const raw = await request.text()
    if (raw.trim().length > 0) {
      const parsed = JSON.parse(raw) as { channelId?: unknown }
      if (typeof parsed?.channelId === 'string' && parsed.channelId.trim().length > 0) {
        channelId = parsed.channelId.trim()
      }
    }
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
  }

  try {
    const [project, config] = await Promise.all([
      prisma.project.findUnique({ where: { id }, select: { id: true, name: true } }),
      prisma.projectDeltaAlertConfig.findUnique({ where: { projectId: id } }),
    ])

    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const stored = config ? parseStoredChannels(config.channels) : []
    const targets = channelId
      ? stored.filter((c) => c.id === channelId)
      : stored.filter((c) => c.enabled)

    if (channelId && targets.length === 0) {
      return NextResponse.json({ error: 'Alert channel not found' }, { status: 404 })
    }
    if (targets.length === 0) {
      return NextResponse.json(
        { error: 'No enabled alert channels configured for this project' },
        { status: 400 },
      )
    }

    const payload = buildDeltaAlertPayload({
      event: 'recon.delta.test',
      projectId: id,
      projectName: project.name,
      scanJobId: null,
      scheduleId: null,
      fromVersionId: null,
      toVersionId: 'current',
      relevance: {
        shouldAlert: true,
        counts: {
          newVulnerabilities: 1,
          newCves: 0,
          newlyExposedPorts: 1,
          newHosts: 1,
        },
        topItems: [
          {
            category: 'vulnerability',
            severity: 'high',
            title: 'Test Alert Verification (no real finding)',
            target: 'https://test.example',
          },
          {
            category: 'port',
            severity: 'medium',
            title: 'Exposed port 203.0.113.10:8443/tcp',
            target: '203.0.113.10',
          },
        ],
        deltaHash: 'test-notification',
      },
    })

    const results = []
    for (const ch of targets) {
      const delivery = await deliverToChannel(ch, payload)
      results.push({
        channelId: ch.id,
        channelName: ch.name,
        type: ch.type,
        ok: delivery.ok,
        statusCode: delivery.statusCode,
        error: delivery.error ?? null,
      })
    }

    const actor = auth.principal
      ? auditActorOf(auth.principal, auth.effective.userId)
      : { actorId: auth.effective.userId }

    await writeAudit({
      ...actor,
      projectId: id,
      permission: 'recon:schedule',
      action: 'delta_alert.test',
      targetType: 'projectDeltaAlertConfig',
      targetId: id,
      after: {
        testedChannelIds: targets.map((t) => t.id),
        succeeded: results.filter((r) => r.ok).length,
        failed: results.filter((r) => !r.ok).length,
      },
    })

    return NextResponse.json({
      ok: results.every((r) => r.ok),
      results,
    })
  } catch (err) {
    return internalError(err, 'Failed to test delta alert channel', { log: '[deltaAlerts] test POST failed' })
  }
})
