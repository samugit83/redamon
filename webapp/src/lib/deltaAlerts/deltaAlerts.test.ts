/** @vitest-environment node */
import { PassThrough } from 'node:stream'
import type { ClientRequest, IncomingMessage, RequestOptions } from 'node:http'
import { describe, test, expect, beforeEach, vi } from 'vitest'
import type { FormattedGraphData } from '@/app/api/graph/format'
import type { ReconDelta } from '@/lib/reconDelta'
import { SECRET_REENTRY_CODE } from '@/lib/authz/secretEndpointRebind'

const prismaMock = vi.hoisted(() => ({
  scanJob: { findUnique: vi.fn() },
  projectDeltaAlertConfig: { findUnique: vi.fn(), findMany: vi.fn() },
  scanVersion: { findFirst: vi.fn() },
  deltaAlertOutbox: { create: vi.fn(), findMany: vi.fn(), update: vi.fn() },
}))

vi.mock('@/lib/prisma', () => ({ default: prismaMock }))

import {
  assertWebhookEgressAllowed,
  buildDedupKey,
  computeBackoffMs,
  deliverToChannel,
  enqueueDeltaAlertsForScanJob,
  evaluateDeltaRelevance,
  maskChannelForApi,
  mergeChannelsForSave,
  postWebhookSafe,
  processAlertOutbox,
  signWebhookPayload,
  validateAlertWebhookUrl,
  verifyWebhookSignature,
} from './index'

function makeDelta(over: Partial<ReconDelta> = {}): ReconDelta {
  return {
    addedNodes: [],
    removedNodes: [],
    changedNodes: [],
    addedLinks: [],
    removedLinks: [],
    scorecard: [],
    totals: {
      fromNodes: 0,
      toNodes: 0,
      added: 0,
      removed: 0,
      changed: 0,
      stable: 0,
      addedLinks: 0,
      removedLinks: 0,
    },
    lenses: {
      newlyExposedPorts: [],
      closedPorts: [],
      newVulnerabilities: [],
      resolvedVulnerabilities: [],
      newCves: [],
      technologyVersionChanges: [],
      certificateChanges: [],
      newParameters: [],
    },
    coverage: null,
    ...over,
  }
}

function fakeTransport(handler: (opts: RequestOptions) => { statusCode: number; headers?: Record<string, string>; body?: string }) {
  return (opts: RequestOptions, cb: (res: IncomingMessage) => void): ClientRequest => {
    const pt = new PassThrough()
    const req = pt as unknown as ClientRequest
    req.setTimeout = (() => req) as unknown as ClientRequest['setTimeout']
    const origEnd = pt.end.bind(pt)
    req.end = ((...args: unknown[]) => {
      origEnd(...(args as []))
      queueMicrotask(() => {
        const reply = handler(opts)
        const res = new PassThrough() as unknown as IncomingMessage & PassThrough
        res.statusCode = reply.statusCode
        res.headers = reply.headers ?? {}
        cb(res)
        if (reply.body) res.write(Buffer.from(reply.body, 'utf8'))
        res.end()
      })
      return req
    }) as unknown as ClientRequest['end']
    return req
  }
}

describe('deltaAlerts relevance & sanitization', () => {
  test('filters by severity threshold, ports, hosts, caps topItems at 10, and excludes secrets', () => {
    const vulns = Array.from({ length: 12 }, (_, i) => ({
      key: `Vulnerability::t${i}`,
      type: 'Vulnerability',
      name: `Vuln ${i}`,
      nodeId: null,
      properties: {
        severity: i < 2 ? 'critical' : i < 10 ? 'high' : 'low',
        matched_at: `https://app${i}.example/path`,
        raw_context: 'SUPER_SECRET_RAW_CONTEXT_DO_NOT_LEAK',
        unmasked_token: 'SECRET_TOKEN_12345',
      },
    }))
    const delta = makeDelta({
      addedNodes: [
        { key: 'Subdomain::api.example', type: 'Subdomain', name: 'api.example', nodeId: null, properties: { name: 'api.example' } },
        { key: 'Secret::s1', type: 'Secret', name: 'Secret', nodeId: null, properties: { value: 'ghp_real_secret_value_999' } },
      ],
      lenses: {
        newlyExposedPorts: [
          { key: 'Port::203.0.113.10:8443/tcp', type: 'Port', name: '8443', nodeId: null, properties: { ip_address: '203.0.113.10', number: 8443, protocol: 'tcp' } },
        ],
        closedPorts: [],
        newVulnerabilities: vulns,
        resolvedVulnerabilities: [],
        newCves: [
          { key: 'CVE::CVE-2026-0001', type: 'CVE', name: 'CVE-2026-0001', nodeId: null, properties: { id: 'CVE-2026-0001', cvss: 9.8 } },
        ],
        technologyVersionChanges: [],
        certificateChanges: [],
        newParameters: [],
      },
    })

    const res = evaluateDeltaRelevance(delta, {
      minVulnSeverity: 'high',
      alertOnNewPorts: true,
      alertOnNewHosts: true,
    })

    expect(res.shouldAlert).toBe(true)
    expect(res.counts).toEqual({
      newVulnerabilities: 10,
      newCves: 1,
      newlyExposedPorts: 1,
      newHosts: 1,
    })
    expect(res.topItems).toHaveLength(10)
    expect(res.topItems[0].severity).toBe('critical')

    const serialized = JSON.stringify(res)
    expect(serialized).not.toContain('SUPER_SECRET_RAW_CONTEXT_DO_NOT_LEAK')
    expect(serialized).not.toContain('SECRET_TOKEN_12345')
    expect(serialized).not.toContain('ghp_real_secret_value_999')
  })

  test('produces deterministic deltaHash and dedupKey', () => {
    const delta = makeDelta({
      lenses: {
        newlyExposedPorts: [
          { key: 'Port::203.0.113.10:443/tcp', type: 'Port', name: '443', nodeId: null, properties: { ip_address: '203.0.113.10', number: 443, protocol: 'tcp' } },
        ],
        closedPorts: [],
        newVulnerabilities: [],
        resolvedVulnerabilities: [],
        newCves: [],
        technologyVersionChanges: [],
        certificateChanges: [],
        newParameters: [],
      },
    })
    const a = evaluateDeltaRelevance(delta, { minVulnSeverity: 'high', alertOnNewPorts: true, alertOnNewHosts: false })
    const b = evaluateDeltaRelevance(delta, { minVulnSeverity: 'high', alertOnNewPorts: true, alertOnNewHosts: false })
    expect(a.deltaHash).toBe(b.deltaHash)
    expect(buildDedupKey('p1', 'v2', a.deltaHash, 'ch1')).toBe(`p1:v2:${a.deltaHash}:ch1`)
  })
})

describe('deltaAlerts signing', () => {
  test('signs and verifies HMAC-SHA256 in constant time', () => {
    const body = JSON.stringify({ event: 'recon.delta' })
    const sig = signWebhookPayload('top-secret', 1732636800, body)
    expect(sig.startsWith('sha256=')).toBe(true)
    expect(verifyWebhookSignature('top-secret', 1732636800, body, sig)).toBe(true)
    expect(verifyWebhookSignature('wrong-secret', 1732636800, body, sig)).toBe(false)
    expect(verifyWebhookSignature('top-secret', 1732636801, body, sig)).toBe(false)
    expect(verifyWebhookSignature('top-secret', 1732636800, `${body} `, sig)).toBe(false)
  })
})

describe('deltaAlerts egress SSRF guard & redirect refusal', () => {
  test('blocks private, loopback, link-local, credentialed, and non-HTTPS Slack URLs', async () => {
    expect(() => validateAlertWebhookUrl('http://hooks.slack.com/services/T/B/X', 'slack')).toThrow(/https/i)
    expect(() => validateAlertWebhookUrl('https://user:pass@alerts.example/hook', 'webhook')).toThrow(/credentials/i)
    expect(() => validateAlertWebhookUrl('http://127.0.0.1:8080/hook', 'webhook')).toThrow(/not a public/i)
    expect(() => validateAlertWebhookUrl('http://169.254.169.254/latest', 'webhook')).toThrow(/not a public/i)
    expect(() => validateAlertWebhookUrl('http://10.0.0.5/hook', 'webhook')).toThrow(/not a public/i)
    expect(() => validateAlertWebhookUrl('http://[::1]/hook', 'webhook')).toThrow(/not a public/i)

    await expect(
      assertWebhookEgressAllowed('https://internal.example/hook', 'webhook', async () => [{ address: '192.168.1.20', family: 4 }]),
    ).rejects.toThrow(/non-public/i)
  })

  test('allows public RFC 5737 resolution and refuses 3xx redirects without leaking secret path', async () => {
    const secretSlackUrl = 'https://hooks.slack.com/services/T00000000/B00000000/VERYSECRETTOKENXYZ'
    await expect(
      postWebhookSafe(
        secretSlackUrl,
        'slack',
        '{"text":"hi"}',
        { 'Content-Type': 'application/json' },
        {
          resolve: async () => [{ address: '203.0.113.10', family: 4 }],
          request: fakeTransport(() => ({
            statusCode: 302,
            headers: { location: 'http://127.0.0.1/admin' },
          })),
        },
      ),
    ).rejects.toSatisfy((err: Error) => {
      return /redirect/i.test(err.message) && !err.message.includes('VERYSECRETTOKENXYZ')
    })
  })
})

describe('deltaAlerts secret masking & endpoint rebinding', () => {
  test('masks webhook secrets and Slack incoming-webhook URLs', () => {
    const maskedWebhook = maskChannelForApi({
      id: 'c1',
      type: 'webhook',
      name: 'SOC',
      url: 'https://soc.example/hook',
      enabled: true,
      secret: 'whsec_1234567890abcd',
    })
    expect(maskedWebhook.hasSecret).toBe(true)
    expect(maskedWebhook.maskedSecret).toBe('••••••••abcd')
    expect((maskedWebhook as unknown as Record<string, unknown>).secret).toBeUndefined()

    const maskedSlack = maskChannelForApi({
      id: 'c2',
      type: 'slack',
      name: 'SecOps',
      url: 'https://hooks.slack.com/services/T111/B222/SECRETPATH9999',
      enabled: true,
    })
    expect(maskedSlack.url).toBe('https://hooks.slack.com/services/••••9999')
    expect(maskedSlack.url).not.toContain('SECRETPATH')
  })

  test('preserves masked secrets on same endpoint, enforces SecretReentry on URL change, allows explicit clear', () => {
    const existing = [
      {
        id: 'c1',
        type: 'webhook' as const,
        name: 'SOC',
        url: 'https://soc.example/hook',
        enabled: true,
        secret: 'whsec_real_secret',
      },
      {
        id: 'c2',
        type: 'slack' as const,
        name: 'Slack',
        url: 'https://hooks.slack.com/services/T1/B2/REALTOKEN',
        enabled: true,
      },
    ]

    const sameUrl = mergeChannelsForSave(existing, [
      { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://soc.example/hook', enabled: true, secret: '••••••••cret' },
      { id: 'c2', type: 'slack', name: 'Slack', url: 'https://hooks.slack.com/services/••••OKEN', enabled: true },
    ])
    expect(sameUrl.ok).toBe(true)
    if (sameUrl.ok) {
      expect(sameUrl.channels[0].secret).toBe('whsec_real_secret')
      expect(sameUrl.channels[1].url).toBe('https://hooks.slack.com/services/T1/B2/REALTOKEN')
    }

    const rebound = mergeChannelsForSave(existing, [
      { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://attacker.example/steal', enabled: true, secret: '••••••••cret' },
    ])
    expect(rebound.ok).toBe(false)
    if (!rebound.ok && 'secretReentry' in rebound) {
      expect(rebound.secretReentry.endpoint).toBe('url')
      expect(SECRET_REENTRY_CODE).toBe('secret_reentry_required')
    } else {
      throw new Error('Expected secretReentry refusal')
    }

    const cleared = mergeChannelsForSave(existing, [
      { id: 'c1', type: 'webhook', name: 'SOC', url: 'https://new.example/hook', enabled: true, secret: '' },
    ])
    expect(cleared.ok).toBe(true)
    if (cleared.ok) {
      expect(cleared.channels[0].secret).toBeUndefined()
    }
  })
})

describe('deltaAlerts outbox enqueue & delivery retries', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  test('enqueues idempotent outbox rows for scheduled full_recon completion above threshold', async () => {
    prismaMock.scanJob.findUnique.mockResolvedValue({
      id: 'job-1',
      projectId: 'p1',
      scheduleId: 'sched-1',
      kind: 'full_recon',
      trigger: 'scheduled',
      status: 'completed',
      versionId: 'v2',
      project: { id: 'p1', name: 'Demo', targetDomain: 'app.example', ipMode: false, domainBatchMode: false, domainBatchHosts: [], subdomainList: [] },
    })
    prismaMock.projectDeltaAlertConfig.findUnique.mockResolvedValue({
      projectId: 'p1',
      enabled: true,
      minVulnSeverity: 'high',
      alertOnNewPorts: true,
      alertOnNewHosts: false,
      channels: [{ id: 'ch-1', type: 'webhook', name: 'SOC', url: 'https://soc.example/hook', enabled: true, secret: 'sec' }],
    })
    prismaMock.scanVersion.findFirst
      .mockResolvedValueOnce({ id: 'v2', seq: 2, isCurrent: false })
      .mockResolvedValueOnce({ id: 'v1', seq: 1 })
    prismaMock.deltaAlertOutbox.create.mockResolvedValue({ id: 'out-1' })

    const emptyGraph: FormattedGraphData = { nodes: [], links: [] }
    const fakeDelta = makeDelta({
      lenses: {
        newlyExposedPorts: [{ key: 'Port::203.0.113.10:80/tcp', type: 'Port', name: '80', nodeId: null, properties: { ip_address: '203.0.113.10', number: 80, protocol: 'tcp' } }],
        closedPorts: [],
        newVulnerabilities: [],
        resolvedVulnerabilities: [],
        newCves: [],
        technologyVersionChanges: [],
        certificateChanges: [],
        newParameters: [],
      },
    })

    const out = await enqueueDeltaAlertsForScanJob('job-1', {
      loadSnapshotFn: async () => ({ version: 1, exportedAt: '', projectId: 'p1', nodeCount: 0, nodes: [], relationships: [], referenceLinks: [] }),
      computeDeltaFn: () => fakeDelta,
    })

    expect(out).toEqual({ enqueued: 1 })
    expect(prismaMock.deltaAlertOutbox.create).toHaveBeenCalledTimes(1)
    expect(emptyGraph.nodes).toHaveLength(0)

    prismaMock.scanVersion.findFirst
      .mockResolvedValueOnce({ id: 'v2', seq: 2, isCurrent: true })
      .mockResolvedValueOnce({ id: 'v1', seq: 1 })
    const busyOut = await enqueueDeltaAlertsForScanJob('job-1', {
      loadSnapshotFn: async () => ({ version: 1, exportedAt: '', projectId: 'p1', nodeCount: 0, nodes: [], relationships: [], referenceLinks: [] }),
      describeLiveWritersFn: async () => 'a triage run is in progress',
    })
    expect(busyOut).toEqual({ enqueued: 0, skipped: 'graph_busy' })
  })

  test('processAlertOutbox delivers, schedules backoff retry, and fails at maxAttempts', async () => {
    const now = new Date('2026-11-26T12:00:00.000Z')
    prismaMock.deltaAlertOutbox.findMany.mockResolvedValue([
      {
        id: 'o1',
        projectId: 'p1',
        channelId: 'ch1',
        attempts: 0,
        maxAttempts: 5,
        payload: {
          event: 'recon.delta',
          projectId: 'p1',
          projectName: 'Demo',
          scanJobId: 'j1',
          scheduleId: 's1',
          fromVersionId: 'v1',
          toVersionId: 'v2',
          triggeredAt: now.toISOString(),
          summary: { newVulnerabilities: 1, newCves: 0, newlyExposedPorts: 0, newHosts: 0 },
          topItems: [],
          deltaPath: '/graph?projectId=p1',
        },
      },
      {
        id: 'o2',
        projectId: 'p1',
        channelId: 'ch1',
        attempts: 4,
        maxAttempts: 5,
        payload: {
          event: 'recon.delta',
          projectId: 'p1',
          projectName: 'Demo',
          scanJobId: 'j2',
          scheduleId: 's1',
          fromVersionId: 'v1',
          toVersionId: 'v2',
          triggeredAt: now.toISOString(),
          summary: { newVulnerabilities: 1, newCves: 0, newlyExposedPorts: 0, newHosts: 0 },
          topItems: [],
          deltaPath: '/graph?projectId=p1',
        },
      },
    ])
    prismaMock.projectDeltaAlertConfig.findMany.mockResolvedValue([
      {
        projectId: 'p1',
        enabled: true,
        channels: [{ id: 'ch1', type: 'webhook', name: 'SOC', url: 'https://soc.example/hook', enabled: true, secret: 's' }],
      },
    ])
    prismaMock.deltaAlertOutbox.update.mockResolvedValue({})

    let callCount = 0
    const result = await processAlertOutbox({
      now,
      deliverDeps: {
        resolve: async () => [{ address: '203.0.113.10', family: 4 }],
        request: fakeTransport(() => {
          callCount += 1
          return callCount === 1 ? { statusCode: 200, body: 'ok' } : { statusCode: 502, body: 'bad gw' }
        }),
      },
    })

    expect(result).toEqual({ processed: 2, sent: 1, retried: 0, failed: 1 })
    expect(computeBackoffMs(1)).toBe(30_000)
    expect(computeBackoffMs(2)).toBe(60_000)
    expect(prismaMock.deltaAlertOutbox.update.mock.calls[0][0].data).toMatchObject({ status: 'sent', lastStatusCode: 200 })
    expect(prismaMock.deltaAlertOutbox.update.mock.calls[1][0].data).toMatchObject({ status: 'failed', attempts: 5, lastStatusCode: 502 })
  })

  test('deliverToChannel attaches signed headers on webhook', async () => {
    let seenHeaders: Record<string, unknown> = {}
    const res = await deliverToChannel(
      { id: 'c1', type: 'webhook', name: 'W', url: 'https://hooks.example/in', enabled: true, secret: 'abc' },
      {
        event: 'recon.delta',
        projectId: 'p1',
        projectName: 'P1',
        scanJobId: null,
        scheduleId: null,
        fromVersionId: null,
        toVersionId: 'current',
        triggeredAt: '2026-11-26T00:00:00.000Z',
        summary: { newVulnerabilities: 1, newCves: 0, newlyExposedPorts: 0, newHosts: 0 },
        topItems: [],
        deltaPath: '/graph?projectId=p1',
      },
      {
        nowSec: () => 1700000000,
        resolve: async () => [{ address: '203.0.113.10', family: 4 }],
        request: fakeTransport((opts) => {
          seenHeaders = (opts.headers ?? {}) as Record<string, unknown>
          return { statusCode: 204 }
        }),
      },
    )
    expect(res).toEqual({ ok: true, statusCode: 204 })
    expect(seenHeaders['X-RedAmon-Event']).toBe('recon.delta')
    expect(seenHeaders['X-RedAmon-Timestamp']).toBe('1700000000')
    expect(String(seenHeaders['X-RedAmon-Signature-256'])).toMatch(/^sha256=[0-9a-f]{64}$/)
  })
})
