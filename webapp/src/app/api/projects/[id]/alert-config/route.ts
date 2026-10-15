/**
 * Scheduled-scan alert preferences (help-wanted: configuration UI for alerts).
 *
 * GET  /api/projects/[id]/alert-config  masked config + recent alert outcomes
 * PUT  /api/projects/[id]/alert-config  set Slack / generic webhook URLs + toggles
 *
 * Webhook URLs are bearer secrets: GET never returns them (only
 * `{ configured: true/false }`), and PUT stores https-only URLs after
 * validation. A `"••••"`-prefixed value keeps the stored secret (same masked
 * convention as the user-settings secret fields).
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'
import { writeAudit } from '@/lib/audit'
import { isValidWebhookUrl } from '@/lib/scanAlerts'

interface RouteParams {
  params: Promise<{ id: string }>
}

function masked(raw: string): string {
  return raw ? '••••••' : ''
}

export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  try {
    const [cfg, recent] = await Promise.all([
      prisma.scanAlertConfig.findUnique({ where: { projectId: id } }),
      prisma.scanAlert.findMany({
        where: { projectId: id },
        orderBy: { createdAt: 'desc' },
        take: 20,
        select: { id: true, channel: true, status: true, error: true, createdAt: true, scanJobId: true },
      }),
    ])
    return NextResponse.json({
      config: {
        enabled: cfg?.enabled ?? true,
        slackConfigured: Boolean(cfg?.slackWebhookUrl),
        slackMasked: masked(cfg?.slackWebhookUrl ?? ''),
        webhookConfigured: Boolean(cfg?.genericWebhookUrl),
        webhookMasked: masked(cfg?.genericWebhookUrl ?? ''),
        notifyOnNew: cfg?.notifyOnNew ?? true,
        notifyOnRemoved: cfg?.notifyOnRemoved ?? false,
      },
      recentAlerts: recent,
    })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to load alert config' },
      { status: 500 }
    )
  }
}

function resolveUrl(input: unknown, stored: string): string | { error: string } {
  if (input === undefined) return stored
  if (typeof input !== 'string') return { error: 'webhook URL must be a string' }
  const v = input.trim()
  if (!v) return ''
  if (v.startsWith('••••')) return stored
  if (!isValidWebhookUrl(v)) return { error: 'webhook URL must be a valid https:// URL' }
  return v
}

export async function PUT(request: NextRequest, { params }: RouteParams) {
  const { id } = await params
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const access = await requireProjectAccess(eff, id)
  if (access instanceof NextResponse) return access

  const body = await request.json().catch(() => null)
  if (!body || typeof body !== 'object') {
    return NextResponse.json({ error: 'invalid request body' }, { status: 400 })
  }
  const b = body as Record<string, unknown>

  try {
    const stored = await prisma.scanAlertConfig.findUnique({ where: { projectId: id } })
    const slack = resolveUrl(b.slackWebhookUrl, stored?.slackWebhookUrl ?? '')
    if (typeof slack === 'object') return NextResponse.json({ error: `slack: ${slack.error}` }, { status: 400 })
    const webhook = resolveUrl(b.genericWebhookUrl, stored?.genericWebhookUrl ?? '')
    if (typeof webhook === 'object') return NextResponse.json({ error: `webhook: ${webhook.error}` }, { status: 400 })

    const enabled = b.enabled === undefined ? (stored?.enabled ?? true) : Boolean(b.enabled)
    const notifyOnNew = b.notifyOnNew === undefined ? (stored?.notifyOnNew ?? true) : Boolean(b.notifyOnNew)
    const notifyOnRemoved =
      b.notifyOnRemoved === undefined ? (stored?.notifyOnRemoved ?? false) : Boolean(b.notifyOnRemoved)

    const saved = await prisma.scanAlertConfig.upsert({
      where: { projectId: id },
      create: {
        projectId: id, enabled, slackWebhookUrl: slack, genericWebhookUrl: webhook,
        notifyOnNew, notifyOnRemoved,
      },
      update: {
        enabled, slackWebhookUrl: slack, genericWebhookUrl: webhook,
        notifyOnNew, notifyOnRemoved,
      },
    })

    await writeAudit({
      actorId: eff.userId,
      action: 'scan-alert-config.update',
      targetType: 'project',
      targetId: id,
      after: {
        enabled: saved.enabled,
        slackConfigured: Boolean(saved.slackWebhookUrl),
        webhookConfigured: Boolean(saved.genericWebhookUrl),
        notifyOnNew: saved.notifyOnNew,
        notifyOnRemoved: saved.notifyOnRemoved,
      },
    })

    return NextResponse.json({
      config: {
        enabled: saved.enabled,
        slackConfigured: Boolean(saved.slackWebhookUrl),
        webhookConfigured: Boolean(saved.genericWebhookUrl),
        notifyOnNew: saved.notifyOnNew,
        notifyOnRemoved: saved.notifyOnRemoved,
      },
    })
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to save alert config' },
      { status: 500 }
    )
  }
}
