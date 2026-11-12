/**
 * POST /api/users/[id]/settings — capture-proxy recreate gating (follow-up #2).
 *
 * Egress toggles + body-storage policy are hot-reloaded live from the DB->file, so
 * a save touching ONLY those must NOT restart the proxy. A container recreate is
 * driven ONLY by the master enable toggle or a spawn-baked field (port / redact).
 * Verifies the orchestrator start/stop call fires exactly when it should.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockUpsert = vi.fn()
const mockRotFindMany = vi.fn()
const mockRotFindUnique = vi.fn()
const mockRotUpsert = vi.fn()
const mockRotUpdate = vi.fn()
const mockRotDeleteMany = vi.fn()
const mockRequireUserAccess = vi.fn()
const mockOrchestratorFetch = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => mockFindUnique(...a),
      upsert: (...a: unknown[]) => mockUpsert(...a),
    },
    apiKeyRotationConfig: {
      findMany: (...a: unknown[]) => mockRotFindMany(...a),
      findUnique: (...a: unknown[]) => mockRotFindUnique(...a),
      upsert: (...a: unknown[]) => mockRotUpsert(...a),
      update: (...a: unknown[]) => mockRotUpdate(...a),
      deleteMany: (...a: unknown[]) => mockRotDeleteMany(...a),
    },
  },
}))
// The internal key by default; the NF-02 case is a member's cookie with the scanner key.
const caller = vi.hoisted(() => ({
  internal: true, scanner: false, session: { userId: 'admin-1', role: 'admin' } as { userId: string; role: string },
}))
vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  isInternalRequest: () => caller.internal,
  isScannerRequest: () => caller.scanner,
  getSession: () => Promise.resolve(caller.session),
}))
vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: (...a: unknown[]) => mockOrchestratorFetch(...a),
}))
vi.mock('@/lib/captureBodyRules', () => ({
  sanitizeBodyRules: (v: unknown) => v,
}))

import { PUT } from './route'

// Baseline existing row: capture ON, port 8888, redact on, block_private on.
const EXISTING = {
  userId: 'admin-1', captureProxyEnabled: true, captureProxyPort: 8888,
  captureProxyRedactSecrets: true, captureEgressBlockPrivate: true,
  captureProxyStoreBodies: true, captureProxyMaxBodyKb: 64,
}

function post(bodyObj: Record<string, unknown>) {
  const req = new NextRequest('http://webapp/api/users/admin-1/settings', {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(bodyObj),
  })
  return PUT(req, { params: Promise.resolve({ id: 'admin-1' }) })
}

function startStopUrls() {
  return mockOrchestratorFetch.mock.calls.map((c) => String(c[0]))
}

beforeEach(() => {
  Object.assign(caller, { internal: true, scanner: false, session: { userId: 'admin-1', role: 'admin' } })
  mockRequireUserAccess.mockReset().mockResolvedValue(null) // allow
  mockFindUnique.mockReset().mockResolvedValue({ ...EXISTING })
  // upsert echoes the resulting enabled state (default: stays enabled).
  mockUpsert.mockReset().mockImplementation(({ update }: { update: Record<string, unknown> }) =>
    Promise.resolve({ ...EXISTING, ...update }))
  mockRotFindMany.mockReset().mockResolvedValue([])
  mockRotFindUnique.mockReset().mockResolvedValue(null)
  mockRotUpsert.mockReset().mockResolvedValue({})
  mockRotUpdate.mockReset().mockResolvedValue({})
  mockRotDeleteMany.mockReset().mockResolvedValue({})
  mockOrchestratorFetch.mockReset().mockResolvedValue({ ok: true })
})

describe('capture-proxy recreate gating', () => {
  test('egress-toggle-only save does NOT restart the proxy', async () => {
    await post({ captureEgressBlockPrivate: false })
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('body-storage-only save does NOT restart the proxy', async () => {
    await post({ captureProxyMaxBodyKb: 128, captureProxyStoreBodies: false })
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('changing the listen PORT restarts the proxy (spawn-baked)', async () => {
    await post({ captureProxyPort: 9999 })
    expect(startStopUrls().some((u) => u.endsWith('/capture-proxy/start'))).toBe(true)
  })

  test('changing REDACT restarts the proxy (ingest env)', async () => {
    await post({ captureProxyRedactSecrets: false })
    expect(startStopUrls().some((u) => u.endsWith('/capture-proxy/start'))).toBe(true)
  })

  test('port set to the SAME value does not restart', async () => {
    await post({ captureProxyPort: 8888 })       // unchanged
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('enabling capture starts the proxy', async () => {
    mockFindUnique.mockResolvedValue({ ...EXISTING, captureProxyEnabled: false })
    await post({ captureProxyEnabled: true })
    expect(startStopUrls().some((u) => u.endsWith('/capture-proxy/start'))).toBe(true)
  })

  test('disabling capture stops the proxy', async () => {
    await post({ captureProxyEnabled: false })
    expect(startStopUrls().some((u) => u.endsWith('/capture-proxy/stop'))).toBe(true)
  })
})

describe('the scanner key grants nothing on a write (NF-02, step 1.9)', () => {
  test('scanner key with a member cookie is refused the capture settings: ignored, named, nothing restarted', async () => {
    Object.assign(caller, { internal: false, scanner: true, session: { userId: 'member-1', role: 'standard' } })
    const res = await post({ captureProxyEnabled: false, captureEgressBlockPrivate: false })
    expect(res.status).toBe(200)
    const update = mockUpsert.mock.calls[0][0].update as Record<string, unknown>
    expect(update).not.toHaveProperty('captureProxyEnabled')
    expect(update).not.toHaveProperty('captureEgressBlockPrivate')
    expect((await res.json()).ignoredFields).toEqual(['captureProxyEnabled', 'captureEgressBlockPrivate'])
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })

  test('the same member without the scanner key gets the same answer', async () => {
    Object.assign(caller, { internal: false, scanner: false, session: { userId: 'member-1', role: 'standard' } })
    const res = await post({ captureProxyEnabled: false })
    expect((await res.json()).ignoredFields).toEqual(['captureProxyEnabled'])
    expect(mockOrchestratorFetch).not.toHaveBeenCalled()
  })
})
