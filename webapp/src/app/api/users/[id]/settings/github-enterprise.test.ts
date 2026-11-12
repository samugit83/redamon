/**
 * GitHub Enterprise credential pair on PUT /api/users/[id]/settings.
 *
 * The host is the ALLOWLIST every supply-chain host check is made against, so it
 * is normalized and validated here rather than at each use; the token beside it
 * is a secret and must be masked on the way out like every other credential.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  findUnique: vi.fn(),
  upsert: vi.fn(),
  rotationFindMany: vi.fn(),
  requireUserAccess: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      upsert: (...a: unknown[]) => h.upsert(...a),
    },
    apiKeyRotationConfig: { findMany: (...a: unknown[]) => h.rotationFindMany(...a) },
  },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => h.requireUserAccess(...a),
  isInternalRequest: () => false,
  isScannerRequest: () => false,
  getSession: async () => ({ role: 'admin' }),
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { PUT } from './route'

const put = (body: unknown) =>
  new NextRequest('http://x', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.requireUserAccess.mockResolvedValue(null)
  h.findUnique.mockResolvedValue(null)
  h.rotationFindMany.mockResolvedValue([])
  h.upsert.mockImplementation(async ({ create, update }: Record<string, Record<string, unknown>>) => ({
    userId: 'u1', githubAccessToken: '', githubEnterpriseHost: '', githubEnterpriseToken: '',
    tavilyApiKey: '', shodanApiKey: '', serpApiKey: '', nvdApiKey: '', vulnersApiKey: '',
    urlscanApiKey: '', censysApiToken: '', censysOrgId: '', fofaApiKey: '', otxApiKey: '',
    netlasApiKey: '', virusTotalApiKey: '', zoomEyeApiKey: '', criminalIpApiKey: '', quakeApiKey: '',
    hunterApiKey: '', publicWwwApiKey: '', hunterHowApiKey: '', googleApiKey: '', googleApiCx: '',
    onypheApiKey: '', driftnetApiKey: '', wpscanApiToken: '', pdcpApiKey: '', ngrokAuthtoken: '',
    chiselServerUrl: '', chiselAuth: '',
    ...(create ?? {}), ...(update ?? {}),
  }))
})

describe('githubEnterpriseHost', () => {
  test('a pasted URL is normalized down to the bare hostname', async () => {
    const res = await PUT(put({ githubEnterpriseHost: 'HTTPS://GHE.Example.com/orgs/acme' }), params('u1'))
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].create.githubEnterpriseHost).toBe('ghe.example.com')
  })

  test('an unusable host is a 400, and nothing is written', async () => {
    for (const host of ['localhost', '169.254.169.254', 'ghe.example.com:8443', 'not a host']) {
      h.upsert.mockClear()
      const res = await PUT(put({ githubEnterpriseHost: host }), params('u1'))
      expect(res.status, host).toBe(400)
      expect(h.upsert, host).not.toHaveBeenCalled()
    }
  })

  test('empty clears the allowlist entry', async () => {
    const res = await PUT(put({ githubEnterpriseHost: '' }), params('u1'))
    expect(res.status).toBe(200)
    expect(h.upsert.mock.calls[0][0].create.githubEnterpriseHost).toBe('')
  })
})

describe('githubEnterpriseToken', () => {
  test('is persisted and masked in the response, never echoed in cleartext', async () => {
    const res = await PUT(put({ githubEnterpriseToken: 'ghp_ENTERPRISE_SECRET_1234' }), params('u1'))
    const body = await res.json()
    expect(h.upsert.mock.calls[0][0].create.githubEnterpriseToken).toBe('ghp_ENTERPRISE_SECRET_1234')
    expect(body.githubEnterpriseToken).not.toContain('ENTERPRISE_SECRET')
    expect(body.githubEnterpriseToken).toMatch(/^••••/)
  })

  test('a masked value sent back preserves the stored token (no wipe on re-save)', async () => {
    h.findUnique.mockResolvedValue({ githubEnterpriseToken: 'ghp_STORED', githubAccessToken: '' })
    await PUT(put({ githubEnterpriseToken: '••••••••1234' }), params('u1'))
    expect(h.upsert.mock.calls[0][0].update.githubEnterpriseToken).toBe('ghp_STORED')
  })

  test('a denied caller writes nothing', async () => {
    h.requireUserAccess.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await PUT(put({ githubEnterpriseToken: 'ghp_x' }), params('victim'))
    expect(res.status).toBe(403)
    expect(h.upsert).not.toHaveBeenCalled()
  })
})
