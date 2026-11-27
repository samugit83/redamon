/**
 * Project Delta Alerts routes — /api/projects/[id]/delta-alerts and /test.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { SECRET_REENTRY_CODE } from '@/lib/authz/secretEndpointRebind'

const h = vi.hoisted(() => ({
  requirePermission: vi.fn(),
  configFindUnique: vi.fn(),
  configUpsert: vi.fn(),
  outboxFindMany: vi.fn(),
  projectFindUnique: vi.fn(),
  audit: vi.fn(),
  deliverToChannel: vi.fn(),
  assertWebhookEgressAllowed: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => ({
  requirePermission: (...a: unknown[]) => h.requirePermission(...a),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    projectDeltaAlertConfig: {
      findUnique: (...a: unknown[]) => h.configFindUnique(...a),
      upsert: (...a: unknown[]) => h.configUpsert(...a),
    },
    deltaAlertOutbox: {
      findMany: (...a: unknown[]) => h.outboxFindMany(...a),
    },
    project: {
      findUnique: (...a: unknown[]) => h.projectFindUnique(...a),
    },
  },
}))

vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/deltaAlerts', async (orig) => {
  const actual = await orig<typeof import('@/lib/deltaAlerts')>()
  return {
    ...actual,
    deliverToChannel: (...a: unknown[]) => h.deliverToChannel(...a),
    assertWebhookEgressAllowed: (...a: unknown[]) => h.assertWebhookEgressAllowed(...a),
  }
})

import { DeltaAlertEgressError } from '@/lib/deltaAlerts'
import { GET, PUT } from './route'
import { POST as TEST_POST } from './test/route'

const params = (id = 'p1') => ({ params: Promise.resolve({ id }) })
const getReq = () => new NextRequest('http://x/api/projects/p1/delta-alerts')
const putReq = (body: unknown) =>
  new NextRequest('http://x/api/projects/p1/delta-alerts', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
const postTestReq = (body?: unknown) =>
  new NextRequest('http://x/api/projects/p1/delta-alerts/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  })

describe('GET/PUT /api/projects/[id]/delta-alerts and POST /test', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    h.requirePermission.mockResolvedValue({
      effective: { userId: 'u1' },
      principal: { id: 'u1', email: 'owner@example.invalid' },
    })
    h.configFindUnique.mockResolvedValue(null)
    h.outboxFindMany.mockResolvedValue([])
    h.projectFindUnique.mockResolvedValue({ id: 'p1', name: 'Test Project' })
    h.audit.mockResolvedValue(undefined)
    h.assertWebhookEgressAllowed.mockImplementation(async (rawUrl: string) => new URL(rawUrl))
  })

  test('passes auth refusals straight through', async () => {
    h.requirePermission.mockResolvedValueOnce(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await GET(getReq(), params())
    expect(res.status).toBe(403)
    expect(h.requirePermission).toHaveBeenCalledWith(expect.any(NextRequest), 'recon:read', { projectId: 'p1' })
  })

  test('GET masks stored webhook secrets and Slack webhook tokens', async () => {
    h.configFindUnique.mockResolvedValue({
      projectId: 'p1',
      enabled: true,
      minVulnSeverity: 'high',
      alertOnNewPorts: true,
      alertOnNewHosts: false,
      channels: [
        { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://soc.example/in', enabled: true, secret: 'whsec_1234567890' },
        { id: 'c2', type: 'slack', name: 'Slack', url: 'https://hooks.slack.com/services/T1/B2/SECRETTOKEN99', enabled: true },
      ],
      updatedAt: new Date('2026-11-26T10:00:00.000Z'),
    })

    const res = await GET(getReq(), params())
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.config.channels[0].maskedSecret).toBe('••••••••7890')
    expect(body.config.channels[0].secret).toBeUndefined()
    expect(body.config.channels[1].url).toBe('https://hooks.slack.com/services/••••EN99')
    expect(JSON.stringify(body)).not.toContain('whsec_1234567890')
    expect(JSON.stringify(body)).not.toContain('SECRETTOKEN99')
  })

  test('PUT enforces SecretReentry when changing webhook URL with masked secret, and audits saves', async () => {
    h.configFindUnique.mockResolvedValue({
      projectId: 'p1',
      enabled: true,
      minVulnSeverity: 'high',
      alertOnNewPorts: true,
      alertOnNewHosts: true,
      channels: [
        { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://soc.example/in', enabled: true, secret: 'whsec_real' },
      ],
    })

    const refused = await PUT(
      putReq({
        enabled: true,
        minVulnSeverity: 'high',
        alertOnNewPorts: true,
        alertOnNewHosts: true,
        channels: [
          { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://other.example/steal', enabled: true, secret: '••••••••real' },
        ],
      }),
      params(),
    )
    expect(refused.status).toBe(400)
    const errBody = await refused.json()
    expect(errBody.code).toBe(SECRET_REENTRY_CODE)
    expect(h.configUpsert).not.toHaveBeenCalled()

    h.configUpsert.mockResolvedValue({
      projectId: 'p1',
      enabled: true,
      minVulnSeverity: 'critical',
      alertOnNewPorts: false,
      alertOnNewHosts: false,
      channels: [{ id: 'c1', type: 'webhook', name: 'SOC', url: 'https://soc.example/in', enabled: true, secret: 'whsec_real' }],
      updatedAt: new Date('2026-11-26T10:05:00.000Z'),
    })
    const ok = await PUT(
      putReq({
        enabled: true,
        minVulnSeverity: 'critical',
        alertOnNewPorts: false,
        alertOnNewHosts: false,
        channels: [
          { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://soc.example/in', enabled: true, secret: '••••••••real' },
        ],
      }),
      params(),
    )
    expect(ok.status).toBe(200)
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'delta_alert.update', projectId: 'p1' }))
  })

  test('PUT rejects loopback webhook URLs and DNS-resolved non-public hosts', async () => {
    const res = await PUT(
      putReq({
        enabled: true,
        minVulnSeverity: 'high',
        alertOnNewPorts: true,
        alertOnNewHosts: true,
        channels: [{ id: 'c1', type: 'webhook', name: 'Local', url: 'http://127.0.0.1:8080/hook', enabled: true }],
      }),
      params(),
    )
    expect(res.status).toBe(400)
    expect(h.configUpsert).not.toHaveBeenCalled()

    h.assertWebhookEgressAllowed.mockRejectedValueOnce(
      new DeltaAlertEgressError('address_not_public', 'Webhook host https://rebind.example resolved to a non-public address.'),
    )
    const dnsRes = await PUT(
      putReq({
        enabled: true,
        minVulnSeverity: 'high',
        alertOnNewPorts: true,
        alertOnNewHosts: true,
        channels: [{ id: 'c1', type: 'webhook', name: 'Rebind', url: 'https://rebind.example/hook', enabled: true }],
      }),
      params(),
    )
    expect(dnsRes.status).toBe(400)
    expect(await dnsRes.json()).toMatchObject({ code: 'address_not_public' })
    expect(h.configUpsert).not.toHaveBeenCalled()
  })

  test('POST /test delivers synthetic alert and records delta_alert.test audit', async () => {
    h.configFindUnique.mockResolvedValue({
      projectId: 'p1',
      enabled: true,
      minVulnSeverity: 'high',
      alertOnNewPorts: true,
      alertOnNewHosts: true,
      channels: [
        { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://soc.example/in', enabled: true, secret: 'whsec_real' },
      ],
    })
    h.deliverToChannel.mockResolvedValue({ ok: true, statusCode: 202 })

    const res = await TEST_POST(postTestReq({ channelId: 'c1' }), params())
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(true)
    expect(body.results).toEqual([
      { channelId: 'c1', channelName: 'SOC', type: 'webhook', ok: true, statusCode: 202, error: null },
    ])
    expect(h.audit).toHaveBeenCalledWith(expect.objectContaining({ action: 'delta_alert.test', projectId: 'p1' }))
  })
})
