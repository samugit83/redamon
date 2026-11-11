/**
 * PUT /api/users/[id]/settings: a new GitHub Enterprise host or chisel server URL must
 * come with its secret typed again (HD-24). The settings form sends every field back on
 * every save, secrets masked; without the rule, re-pointing the endpoint alone sends the
 * kept token to the new host at the next supply-chain scan or tunnel start.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  upsert: vi.fn(),
  executeRaw: vi.fn(),
  rotationFindMany: vi.fn(),
  requireUserAccess: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      upsert: (...a: unknown[]) => h.upsert(...a),
    },
    apiKeyRotationConfig: { findMany: (...a: unknown[]) => h.rotationFindMany(...a) },
    $executeRaw: (...a: unknown[]) => h.executeRaw(...a),
  },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => h.requireUserAccess(...a),
  isInternalRequest: () => false,
  isScannerRequest: () => false,
  getSession: async () => ({ userId: 'u1', role: 'standard' }),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { PUT } from './route'

const STORED = {
  userId: 'u1',
  githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: 'ghp_STORED_ENTERPRISE_1234',
  chiselServerUrl: 'http://vps.example.com:9090', chiselAuth: 'user:STORED-pass',
  tunnelsEnabled: true, tavilyApiKey: 'tvly-stored',
}
const put = (body: unknown) =>
  PUT(new NextRequest('http://x', { method: 'PUT', body: JSON.stringify(body) }), { params: Promise.resolve({ id: 'u1' }) })

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', h.fetch)
  h.fetch.mockResolvedValue(new Response('{}', { status: 200 }))
  h.requireUserAccess.mockResolvedValue(null)
  h.findUnique.mockResolvedValue(STORED)
  h.rotationFindMany.mockResolvedValue([])
  h.upsert.mockImplementation(async ({ update }: { update: Record<string, unknown> }) => ({ ...STORED, ...update }))
})

describe('settings PUT: re-entry when an endpoint changes', () => {
  test('the write rule guards the PUT (HD-23)', async () => {
    await put({ tavilyApiKey: 'tvly-new' })
    expect(h.requireUserAccess).toHaveBeenCalledWith(expect.anything(), 'u1', { mode: 'write' })
  })

  test('a new GitHub Enterprise host with the masked token is 400 naming githubEnterpriseToken; nothing is written', async () => {
    const res = await put({ githubEnterpriseHost: 'evil.example.net', githubEnterpriseToken: '••••••••1234', tavilyApiKey: 'tvly-new' })
    expect(res.status).toBe(400)
    const text = await res.text()
    expect(JSON.parse(text)).toMatchObject({ code: 'secret_reentry_required', field: 'githubEnterpriseToken', endpoint: 'githubEnterpriseHost' })
    expect(text).not.toContain('STORED')
    expect(h.upsert).not.toHaveBeenCalled()
  })

  test('a new GitHub Enterprise host with the token typed again is saved', async () => {
    const res = await put({ githubEnterpriseHost: 'https://GHE2.example.com/', githubEnterpriseToken: 'ghp_typed_again' })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update).toMatchObject({ githubEnterpriseHost: 'ghe2.example.com', githubEnterpriseToken: 'ghp_typed_again' })
  })

  test('the same host pasted as a URL is no change: the masked token is kept', async () => {
    const res = await put({ githubEnterpriseHost: 'https://ghe.example.com/orgs/acme', githubEnterpriseToken: '••••••••1234' })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update.githubEnterpriseToken).toBe(STORED.githubEnterpriseToken)
  })

  test('a new chisel URL with the masked auth is 400 naming chiselAuth; no tunnel is configured', async () => {
    const res = await put({ chiselServerUrl: 'http://evil.example.net:9090', chiselAuth: '••••••••pass' })
    expect(res.status).toBe(400)
    expect((await res.json()).field).toBe('chiselAuth')
    expect(h.upsert).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('a new chisel URL with the auth typed again is saved and pushed', async () => {
    const res = await put({ chiselServerUrl: 'http://vps2.example.com:9090', chiselAuth: 'user:typed' })
    expect(res.status).toBe(200)
    const pushed = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(pushed).toMatchObject({ chiselServerUrl: 'http://vps2.example.com:9090', chiselAuth: 'user:typed' })
  })

  test('a whole-form save with nothing re-pointed keeps every masked secret', async () => {
    const res = await put({ ...STORED, githubEnterpriseToken: '••••••••1234', chiselAuth: '••••••••pass', tavilyApiKey: '••••ored' })
    expect(res.status).toBe(200)
  })
})
