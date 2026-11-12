/**
 * `/api/roe/parse` on an existing project: a REPLACE review against the stored
 * row with every side effect previewed, and a re-diff that rebuilds it with no
 * document and no model.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  row: null as Record<string, unknown> | null,
  ownerId: 'owner',
  eff: { userId: 'owner' } as unknown,
  agentFetch: vi.fn(),
  audit: vi.fn(),
  schedules: [] as Array<{ id: string; label: string; nextRunAt: Date | null }>,
  scanBusy: null as string | null,
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: async () => h.eff }
})
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findUnique: async () => ({ featureModels: { roe_parse: 'gpt-5' } }) },
    project: {
      findUnique: async (args: { select?: Record<string, boolean> }) =>
        args?.select ? (h.row ? { id: 'proj-1', userId: h.ownerId } : null) : h.row,
    },
    scanSchedule: { findMany: async () => h.schedules },
    jobQueue: { findMany: async () => [] },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))
vi.mock('@/lib/graphWriters', () => ({
  describeScanWriters: async () => h.scanBusy,
  describeSecondaryScanWriters: async () => null,
}))
vi.mock('@/lib/reconPresets/server', () => ({ fetchBackendDefaults: async () => ({}) }))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))

import { POST } from './route'
import { REGISTRY_DIGEST } from '@/lib/reconSettings/registryDigest.generated'
import { fieldsWhere } from '@/lib/reconSettings/registry'

const VERSION = '2026-10-14T12:00:00.000Z'

function freshRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  const row: Record<string, unknown> = {}
  for (const f of fieldsWhere(() => true)) {
    row[f.key] = f.type === 'json' && typeof f.default === 'string' ? JSON.parse(f.default) : f.default
  }
  return {
    ...row, id: 'proj-1', userId: 'owner', engagementKind: 'internal', updatedAt: new Date(VERSION),
    roeDocumentName: '', roeRawText: '', roeParsedJson: null, ...over,
  }
}

function uploadFor(projectId: string) {
  const form = new FormData()
  form.append('file', new File(['RoE B: max 20 rps'], 'roe-B.txt', { type: 'text/plain' }))
  form.append('projectId', projectId)
  return POST(new NextRequest('http://localhost:3000/api/roe/parse', {
    method: 'POST', body: form, headers: { host: 'localhost:3000' },
  }))
}

function rediff(body: Record<string, unknown>) {
  return POST(new NextRequest('http://localhost:3000/api/roe/parse', {
    method: 'POST', body: JSON.stringify(body),
    headers: { host: 'localhost:3000', 'content-type': 'application/json' },
  }))
}

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  h.ownerId = 'owner'
  h.eff = { userId: 'owner' }
  h.scanBusy = null
  h.schedules = [{ id: 's1', label: 'nightly', nextRunAt: null }]
  // Document A applied a 5 rps ceiling over a project that had none.
  h.row = freshRow({
    roeGlobalMaxRps: 5, roeDocumentName: 'A.pdf', roeRawText: 'A',
    roeParsedJson: { version: 2, applied: { roeGlobalMaxRps: 5 }, before: { roeGlobalMaxRps: 0 }, appliedAt: '2026-10-01T00:00:00.000Z' },
  })
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify({
    fields: { roeGlobalMaxRps: 20 }, unknownKeys: ['agentLhost'], registryDigest: REGISTRY_DIGEST, model_used: 'gpt-5',
  }), { status: 200 }))
})

describe('a replace review', () => {
  test('another user\'s project is 404 and reaches no model', async () => {
    h.ownerId = 'victim'
    h.eff = { userId: 'attacker' }
    const res = await uploadFor('proj-1')
    expect(res.status).toBe(404)
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('carries the row version, the model output, per-row widening and the previews', async () => {
    const res = await uploadFor('proj-1')
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.mode).toBe('replace')
    expect(body.rowVersion).toBe(VERSION)
    expect(body.parsedFields).toEqual({ roeGlobalMaxRps: 20 })
    expect(body.changes).toEqual([expect.objectContaining({ key: 'roeGlobalMaxRps', kind: 'set', before: 5, after: 20, widening: 'raises a rate ceiling' })])
    expect(body.widening).toBe(true)
    expect(body.currentDocument).toEqual({ name: 'A.pdf', appliedAt: '2026-10-01T00:00:00.000Z' })
    expect(body.previews.schedulesToPause).toEqual([expect.objectContaining({ id: 's1' })])
    expect(body.previews.busy).toEqual({ busy: false })
    expect(body.unknownKeys).toEqual(['agentLhost'])
    expect(body.bytesSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(h.audit.mock.calls[0][0]).toMatchObject({ action: 'roe.parse', targetType: 'project', targetId: 'proj-1' })
  }, 30_000)

  test('running work is previewed, so the person knows confirm will be refused', async () => {
    h.scanBusy = 'a full recon scan is running'
    const body = await (await uploadFor('proj-1')).json()
    expect(body.previews.busy).toEqual({ busy: true, verified: true, what: 'a full recon scan is running' })
  }, 30_000)

  test('a third-party widening is previewed as needing an authorization', async () => {
    h.row = { ...h.row!, engagementKind: 'third_party' }
    const body = await (await uploadFor('proj-1')).json()
    expect(body.previews.thirdParty).toEqual({ ceilingMissing: false, needsAuthorization: true })
    expect(body.warnings.join(' ')).toMatch(/attach_engagement_authorization/)
  }, 30_000)
})

describe('re-diff', () => {
  test('rebuilds the review against the current row with no extraction and no model', async () => {
    h.row = { ...h.row!, roeGlobalMaxRps: 7, updatedAt: new Date('2026-10-14T13:00:00.000Z') }
    const res = await rediff({ projectId: 'proj-1', parsedFields: { roeGlobalMaxRps: 20 }, bytesSha256: 'a'.repeat(64) })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(body.rowVersion).toBe('2026-10-14T13:00:00.000Z')
    expect(body.changes[0]).toMatchObject({ key: 'roeGlobalMaxRps', before: 7, after: 20 })
    expect(body.bytesSha256).toBe('a'.repeat(64))
  })

  test('remove is a review of an empty document', async () => {
    const body = await (await rediff({ projectId: 'proj-1', remove: true })).json()
    expect(body.mode).toBe('remove')
    expect(body.changes).toEqual([expect.objectContaining({ key: 'roeGlobalMaxRps', kind: 'restore', after: 0 })])
  })

  test('another user\'s project is 404', async () => {
    h.ownerId = 'victim'
    h.eff = { userId: 'attacker' }
    expect((await rediff({ projectId: 'proj-1', remove: true })).status).toBe(404)
  })

  test('a deleted project is 404 with a code the review can show', async () => {
    h.row = null
    expect((await rediff({ projectId: 'proj-1', remove: true })).status).toBe(404)
  })

  test('a cross-origin re-diff is refused', async () => {
    const res = await POST(new NextRequest('http://localhost:3000/api/roe/parse', {
      method: 'POST', body: JSON.stringify({ projectId: 'proj-1', remove: true }),
      headers: { host: 'localhost:3000', 'content-type': 'application/json', origin: 'http://evil.example' },
    }))
    expect(res.status).toBe(403)
  })
})
