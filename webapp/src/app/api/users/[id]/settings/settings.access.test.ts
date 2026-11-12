/**
 * STRIDE I1 (single-item closure) — GET /api/users/[id]/settings ownership +
 * secret-unmask gating.
 *
 * Before this fix, `GET /api/users/<victim>/settings?internal=true` returned every
 * OSINT key / GitHub token / tunnel credential in CLEARTEXT to ANY logged-in user
 * (unmask keyed off the client `?internal=true` param, no ownership check). The
 * fix routes the ownership decision through requireUserAccess (unit-tested in
 * session.userAccess.test.ts) and gates unmasking on isInternalRequest (header).
 * Here we verify the ROUTE wires those correctly: a guard denial short-circuits
 * before any DB read, and unmasking follows the header, not the query param.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockSettingsFindUnique = vi.fn()
const mockRotationFindMany = vi.fn()
const mockRequireUserAccess = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findUnique: (...a: unknown[]) => mockSettingsFindUnique(...a) },
    apiKeyRotationConfig: { findMany: (...a: unknown[]) => mockRotationFindMany(...a) },
  },
}))

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
  isScannerRequest: () => false,  // S3/E6: browser/agent cases are not scanners
}))

import { GET } from './route'

const GH_TOKEN = 'ghp_SUPERSECRETTOKEN9999'
const SETTINGS = {
  userId: 'victim', githubAccessToken: GH_TOKEN, tavilyApiKey: '', shodanApiKey: 'shodanKEY12345',
  serpApiKey: '', nvdApiKey: '', vulnersApiKey: '', urlscanApiKey: '', censysApiToken: '', censysOrgId: '',
  fofaApiKey: '', otxApiKey: '', netlasApiKey: '', virusTotalApiKey: '', zoomEyeApiKey: '', criminalIpApiKey: '',
  quakeApiKey: '', hunterApiKey: '', publicWwwApiKey: '', hunterHowApiKey: '', googleApiKey: '', googleApiCx: '',
  onypheApiKey: '', driftnetApiKey: '', wpscanApiToken: '', pdcpApiKey: '', ngrokAuthtoken: 'ngrok-AUTH-7777',
  chiselServerUrl: '', chiselAuth: 'chisel-AUTH-8888', tunnelsEnabled: false,
}
const FORBIDDEN = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
const UNAUTH = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

function req(url: string): NextRequest { return new NextRequest(url) }
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  mockSettingsFindUnique.mockReset().mockResolvedValue({ ...SETTINGS })
  mockRotationFindMany.mockReset().mockResolvedValue([])
  mockRequireUserAccess.mockReset()
  mockIsInternal.mockReset()
})

describe('GET /api/users/[id]/settings — I1 leak closure', () => {
  test('EXPLOIT: guard denies (cross-user) → 403 before any DB read, no cleartext', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    const res = await GET(req('http://x/api/users/victim/settings?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(403)
    expect(text).not.toContain(GH_TOKEN)
    expect(mockSettingsFindUnique).not.toHaveBeenCalled()
  })

  test('owner with ?internal=true but NO internal-key header → 200 MASKED', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    const res = await GET(req('http://x/api/users/victim/settings?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(200)
    expect(text).not.toContain(GH_TOKEN)
    expect(text).toContain('9999') // masked tail
  })

  test('internal-key header + ?internal=true → 200 UNMASKED (agent path preserved)', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/settings?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(200)
    expect(text).toContain(GH_TOKEN)
    expect(text).toContain('ngrok-AUTH-7777')
  })

  test('internal-key header WITHOUT ?internal=true → masked', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/settings'), params('victim'))
    expect(await res.text()).not.toContain(GH_TOKEN)
  })

  test('no session → 401 before any DB read', async () => {
    mockRequireUserAccess.mockResolvedValue(UNAUTH)
    const res = await GET(req('http://x/api/users/victim/settings'), params('victim'))
    expect(res.status).toBe(401)
    expect(mockSettingsFindUnique).not.toHaveBeenCalled()
  })
})
