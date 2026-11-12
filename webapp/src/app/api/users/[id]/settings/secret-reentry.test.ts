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
  session: { userId: 'u1', role: 'standard' },
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
  getSession: async () => h.session,
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
// The step-up's own outcomes are proved in stepUp.test.ts; here the double answers as
// requireStepUp does: no password 403 step_up_required, a wrong one 403 step_up_failed.
const mockStepUp = vi.hoisted(() => vi.fn(async (_req: unknown, password: unknown) => {
  const { NextResponse } = await import('next/server')
  if (password === 'right-password') return null
  return password
    ? NextResponse.json({ error: 'Password is incorrect', code: 'step_up_failed' }, { status: 403 })
    : NextResponse.json({ error: 'Enter your password to confirm this action.', code: 'step_up_required' }, { status: 403 })
}))
vi.mock('@/lib/authz/stepUp', () => ({ requireStepUp: mockStepUp }))

import { PUT } from './route'

const STORED = {
  userId: 'u1',
  githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: 'ghp_STORED_ENTERPRISE_1234',
  chiselServerUrl: 'http://vps.example.com:9090', chiselAuth: 'user:STORED-pass',
  tunnelsEnabled: true, tavilyApiKey: 'tvly-stored',
}
const put = (body: unknown) =>
  PUT(new NextRequest('http://x', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }), { params: Promise.resolve({ id: 'u1' }) })

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', h.fetch)
  h.fetch.mockResolvedValue(new Response('{}', { status: 200 }))
  h.requireUserAccess.mockResolvedValue(null)
  h.findUnique.mockResolvedValue(STORED)
  h.rotationFindMany.mockResolvedValue([])
  h.upsert.mockImplementation(async ({ update }: { update: Record<string, unknown> }) => ({ ...STORED, ...update }))
  h.session = { userId: 'u1', role: 'standard' }
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
    // ID-25: re-pointing also takes the signed-in user's password (review of 1.6)
    const res = await put({ githubEnterpriseHost: 'https://GHE2.example.com/', githubEnterpriseToken: 'ghp_typed_again', stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update).toMatchObject({ githubEnterpriseHost: 'ghe2.example.com', githubEnterpriseToken: 'ghp_typed_again' })
  })

  test('the same host pasted as a URL is no change: the masked token is kept', async () => {
    const res = await put({ githubEnterpriseHost: 'https://ghe.example.com/orgs/acme', githubEnterpriseToken: '••••••••1234' })
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].update.githubEnterpriseToken).toBe(STORED.githubEnterpriseToken)
  })

  // Re-pointing the tunnel is for an account that may change it (HD-06, tunnel-gating.test.ts):
  // u1 signs in as an admin here, so the re-entry rule is what answers.
  test('a new chisel URL with the masked auth is 400 naming chiselAuth; no tunnel is configured', async () => {
    h.session = { userId: 'u1', role: 'admin' }
    const res = await put({ chiselServerUrl: 'http://evil.example.net:9090', chiselAuth: '••••••••pass' })
    expect(res.status).toBe(400)
    expect((await res.json()).field).toBe('chiselAuth')
    expect(h.upsert).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('a new chisel URL with the auth typed again is saved and pushed', async () => {
    h.session = { userId: 'u1', role: 'admin' }
    // ID-25: re-pointing also takes the signed-in user's password (review of 1.6)
    const res = await put({ chiselServerUrl: 'http://vps2.example.com:9090', chiselAuth: 'user:typed', stepUpPassword: 'right-password' })
    expect(res.status).toBe(200)
    const pushed = JSON.parse(h.fetch.mock.calls[0][1].body)
    expect(pushed).toMatchObject({ chiselServerUrl: 'http://vps2.example.com:9090', chiselAuth: 'user:typed' })
  })

  test('a whole-form save with nothing re-pointed keeps every masked secret', async () => {
    const res = await put({ ...STORED, githubEnterpriseToken: '••••••••1234', chiselAuth: '••••••••pass', tavilyApiKey: '••••ored' })
    expect(res.status).toBe(200)
  })
})

describe('settings PUT: re-pointing a configured endpoint takes the password too (ID-25, review of 1.6)', () => {
  test('a new GitHub Enterprise host with a new token and no password: 403 step_up_required, nothing written', async () => {
    const res = await put({ githubEnterpriseHost: 'collector.example.net', githubEnterpriseToken: 'ghp_junk' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_required')
    expect(h.upsert).not.toHaveBeenCalled()
  })

  test('a wrong password: 403 step_up_failed, nothing written', async () => {
    const res = await put({ githubEnterpriseHost: 'collector.example.net', githubEnterpriseToken: 'ghp_junk', stepUpPassword: 'guess' })
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('step_up_failed')
    expect(h.upsert).not.toHaveBeenCalled()
  })

  test('a new chisel URL with new auth and no password: refused, no tunnel is configured; the password is never written', async () => {
    h.session = { userId: 'u1', role: 'admin' }
    const res = await put({ chiselServerUrl: 'http://collector.example.net:9090', chiselAuth: 'user:junk' })
    expect(res.status).toBe(403)
    expect(h.upsert).not.toHaveBeenCalled()
    expect(h.fetch).not.toHaveBeenCalled()
    await put({ chiselServerUrl: 'http://collector.example.net:9090', chiselAuth: 'user:junk', stepUpPassword: 'right-password' })
    expect('stepUpPassword' in h.upsert.mock.calls[0][0].update).toBe(false)
  })

  test('re-entry is asked first: a masked token with a new host is 400 before any password', async () => {
    const res = await put({ githubEnterpriseHost: 'collector.example.net', githubEnterpriseToken: '••••••••1234' })
    expect(res.status).toBe(400)
    expect(mockStepUp).not.toHaveBeenCalled()
  })

  test('a first host on an empty row, clearing the host, or a save that keeps it ask for no password', async () => {
    h.findUnique.mockResolvedValue({ userId: 'u1', githubEnterpriseHost: '', githubEnterpriseToken: '' })
    expect((await put({ githubEnterpriseHost: 'ghe.example.com', githubEnterpriseToken: 'ghp_first' })).status).toBe(200)
    h.findUnique.mockResolvedValue(STORED)
    expect((await put({ githubEnterpriseHost: '', githubEnterpriseToken: '' })).status).toBe(200)
    expect((await put({ ...STORED, githubEnterpriseToken: '••••••••1234', chiselAuth: '••••••••pass' })).status).toBe(200)
    expect(mockStepUp).not.toHaveBeenCalled()
  })
})
