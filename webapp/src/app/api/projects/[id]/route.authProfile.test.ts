/**
 * ProjectAuthProfile read boundary on /api/projects/[id].
 *
 * The stored session is write-only from the UI: recon and the agent
 * (X-Internal-Key / scanner key) receive authValue + extraHeaders, a browser
 * gets metadata + hasValue and never the bytes.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockProjectFindUnique = vi.fn()
const mockProjectUpdate = vi.fn()
const mockGetEffectiveUser = vi.fn()
const mockIsInternal = vi.fn()
const mockIsScanner = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => mockProjectFindUnique(...a),
      update: (...a: unknown[]) => mockProjectUpdate(...a),
    },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/session', () => ({
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
  isScannerRequest: (...a: unknown[]) => mockIsScanner(...a),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { GET, PUT } from './route'
import { mintJobCredential } from '@/lib/authz/machineCredential'

// Step 1.16: a scan reads its project with the scanner key AND its job credential.
function scanJob(projectId = 'proj-1', tenant = 'owner'): Record<string, string> {
  vi.stubEnv('INTERNAL_API_KEY', 'internal-key-for-tests-0000000000000')
  return { 'x-redamon-job': mintJobCredential({ tenant, projectId }) }
}

const SECRET = 'sid=super-secret-session-value'
const CSRF = 'csrf-secret-token'
const PROFILE = {
  id: 'ap1', projectId: 'proj-1', userId: 'owner',
  authType: 'cookie', authHeaderName: '', authValue: SECRET,
  extraHeaders: { 'X-CSRF-Token': CSRF },
  scopeHosts: ['app.example.test'], source: 'recorded', status: 'active',
  lastValidatedAt: null, createdAt: new Date(), updatedAt: new Date(),
}

function wireProject(authProfile: unknown) {
  mockProjectFindUnique.mockImplementation((args: { select?: unknown }) =>
    args?.select
      ? Promise.resolve({ id: 'proj-1', userId: 'owner' })
      : Promise.resolve({ id: 'proj-1', userId: 'owner', name: 'p', targetDomain: 'example.test',
          roeDocumentData: Buffer.from('pdf'), user: { id: 'owner' }, authProfile }),
  )
}
const params = { params: Promise.resolve({ id: 'proj-1' }) }
const get = (headers: Record<string, string> = {}) => new NextRequest('http://x/api/projects/proj-1', { headers })

beforeEach(() => {
  vi.clearAllMocks()
  delete process.env.ACCESS_ENFORCE
  mockIsInternal.mockReturnValue(false)
  mockIsScanner.mockReturnValue(false)
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner' })
})

describe('GET /api/projects/[id] — auth profile boundary', () => {
  test('browser caller gets metadata + hasValue, never the secret', async () => {
    wireProject(PROFILE)
    const res = await GET(get(), params)
    expect(res.status).toBe(200)
    const raw = await res.text()
    expect(raw).not.toContain(SECRET)
    expect(raw).not.toContain(CSRF)
    const body = JSON.parse(raw)
    expect(body.authProfile).toEqual({
      authType: 'cookie', authHeaderName: '', extraHeaderNames: ['X-CSRF-Token'],
      scopeHosts: ['app.example.test'], reconEnabled: true, agentEnabled: true,
      source: 'recorded', status: 'active',
      lastValidatedAt: null, updatedAt: expect.any(String), hasValue: true,
    })
    expect(body.roeDocumentData).toBeUndefined()
  })

  test('the payload query includes the relation (else the service caller would get none)', async () => {
    wireProject(PROFILE)
    await GET(get(), params)
    const payloadCall = mockProjectFindUnique.mock.calls.find(([a]) => !a?.select)
    expect(payloadCall?.[0].include.authProfile).toBe(true)
  })

  test('hasValue reflects extras alone and an empty profile', async () => {
    wireProject({ ...PROFILE, authValue: '', extraHeaders: {} })
    expect((await (await GET(get(), params)).json()).authProfile.hasValue).toBe(false)
    wireProject({ ...PROFILE, authValue: '' })
    expect((await (await GET(get(), params)).json()).authProfile.hasValue).toBe(true)
  })

  test('no profile → null for the browser', async () => {
    wireProject(null)
    expect((await (await GET(get(), params)).json()).authProfile).toBeNull()
  })

  test.each([
    ['internal (agent/orchestrator)', () => mockIsInternal.mockReturnValue(true), () => ({})],
    ['scanner (recon)', () => mockIsScanner.mockReturnValue(true), () => scanJob()],
  ])('%s caller receives the full profile', async (_label, arrange, headers) => {
    arrange()
    wireProject(PROFILE)
    const body = await (await GET(get(headers()), params)).json()
    expect(body.authProfile.authValue).toBe(SECRET)
    expect(body.authProfile.extraHeaders).toEqual({ 'X-CSRF-Token': CSRF })
    expect(mockGetEffectiveUser).not.toHaveBeenCalled()
  })
})

describe('PUT /api/projects/[id] — auth profile is not writable through the row', () => {
  test('an authProfile echoed back by the form is dropped before prisma.update', async () => {
    wireProject(PROFILE)
    mockProjectUpdate.mockResolvedValue({ id: 'proj-1', userId: 'owner', ipMode: true, targetDomain: '' })
    const req = new NextRequest('http://x/api/projects/proj-1', {
      method: 'PUT',
      body: JSON.stringify({ name: 'renamed', authProfile: { authType: 'cookie', hasValue: true } }),
    })
    const res = await PUT(req, params)
    expect(res.status).toBe(200)
    const data = mockProjectUpdate.mock.calls[0][0].data
    expect(data).toEqual({ name: 'renamed', updatedById: 'owner' })
  })
})

test('a saved source keeps only its four fields, and a blank row is not a source', async () => {
  wireProject(PROFILE)
  const body = {
    openapiSources: [
      { id: 's1', url: 'https://example.test/spec', headers: ['Authorization: extra-secret'] },
      { id: 's2', url: '' },
    ],
  }
  mockProjectUpdate.mockImplementation(async (args: { data: Record<string, unknown> }) =>
    ({ id: 'proj-1', userId: 'owner', ipMode: true, ...args.data }))
  const res = await PUT(new NextRequest('http://x/api/projects/proj-1', {
    method: 'PUT', body: JSON.stringify(body),
  }), params)
  expect(res.status).toBe(200)
  const stored = mockProjectUpdate.mock.calls[0][0].data
  expect(stored).toEqual({ openapiSources: [{ id: 's1', url: 'https://example.test/spec' }], updatedById: 'owner' })
  expect(await res.text()).not.toContain('extra-secret')
})
