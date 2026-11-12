/**
 * TruffleHog scan-profile CRUD: access control, tenant scoping, and the rules
 * that keep a credential out of a row that gets exported.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => {
  class P2002 extends Error {
    code = 'P2002'
    constructor() { super('Unique constraint failed') }
  }
  return {
    guard: vi.fn(),
    projectFindUnique: vi.fn(),
    findMany: vi.fn(),
    findUnique: vi.fn(),
    findFirst: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    del: vi.fn(),
    settingsFindUnique: vi.fn(),
    P2002,
  }
})

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@prisma/client', () => ({
  Prisma: { PrismaClientKnownRequestError: h.P2002 },
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    userSettings: { findUnique: (...a: unknown[]) => h.settingsFindUnique(...a) },
    trufflehogScanProfile: {
      findMany: (...a: unknown[]) => h.findMany(...a),
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      findFirst: (...a: unknown[]) => h.findFirst(...a),
      create: (...a: unknown[]) => h.create(...a),
      update: (...a: unknown[]) => h.update(...a),
      delete: (...a: unknown[]) => h.del(...a),
    },
  },
}))

const list = await import('./route')
const item = await import('./[profileId]/route')

const req = (body?: unknown) => ({ json: async () => body ?? {} }) as never
const params = { params: Promise.resolve({ projectId: 'p1' }) }
const itemParams = { params: Promise.resolve({ projectId: 'p1', profileId: 'prof1' }) }

beforeEach(() => {
  vi.clearAllMocks()
  h.guard.mockResolvedValue(null)
  h.projectFindUnique.mockResolvedValue({ userId: 'u1' })
  h.findMany.mockResolvedValue([])
  h.findUnique.mockResolvedValue(null)
  h.findFirst.mockResolvedValue({ id: 'prof1', source: 'docker' })
  h.settingsFindUnique.mockResolvedValue({})
  h.create.mockImplementation(async (a: { data: Record<string, unknown> }) => ({ id: 'new', ...a.data }))
})

describe('GET /profiles', () => {
  test('reports which mandatory key each source is missing, never its value', async () => {
    h.findMany.mockResolvedValue([
      { id: 'a', source: 'github', label: '', config: { orgs: ['acme'] } },
    ])
    h.settingsFindUnique.mockResolvedValue({ trufflehogGithubToken: '' })
    const body = await (await list.GET(req(), params)).json()
    expect(body.profiles[0].missingCredentials)
      .toEqual([{ settingsKey: 'trufflehogGithubToken', label: 'Secret Multiscanner GitHub Token' }])
    // The response must not carry any credential VALUE.
    expect(JSON.stringify(body)).not.toContain('trufflehogGithubToken":"g')
  })

  test('a configured key clears the gate', async () => {
    h.findMany.mockResolvedValue([{ id: 'a', source: 'github', label: '', config: { orgs: ['x'] } }])
    h.settingsFindUnique.mockResolvedValue({ trufflehogGithubToken: 'ghp_x' })
    const body = await (await list.GET(req(), params)).json()
    expect(body.profiles[0].missingCredentials).toEqual([])
  })

  test('an incomplete config is reported, not hidden', async () => {
    h.findMany.mockResolvedValue([{ id: 'a', source: 'docker', label: '', config: {} }])
    const body = await (await list.GET(req(), params)).json()
    expect(body.profiles[0].validationErrors.length).toBeGreaterThan(0)
  })

  test('access control is enforced', async () => {
    h.guard.mockResolvedValue(new Response('no', { status: 404 }))
    expect((await list.GET(req(), params)).status).toBe(404)
    expect(h.findMany).not.toHaveBeenCalled()
  })

  test('404 for a project that does not exist', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    expect((await list.GET(req(), params)).status).toBe(404)
  })
})

describe('POST /profiles', () => {
  test('creates a profile for a known source', async () => {
    const res = await list.POST(req({ source: 'docker', config: { images: ['nginx:1.25'] } }), params)
    expect(res.status).toBe(201)
    expect(h.create.mock.calls[0][0].data.source).toBe('docker')
  })

  test('the dash spelling is normalised to the stored id', async () => {
    await list.POST(req({ source: 'github-experimental', config: {} }), params)
    expect(h.create.mock.calls[0][0].data.source).toBe('github_experimental')
  })

  test('an unknown source is a 400', async () => {
    expect((await list.POST(req({ source: 'slack' }), params)).status).toBe(400)
  })

  test('a field that is not in the registry is refused', async () => {
    const res = await list.POST(req({ source: 'docker', config: { madeUp: 'x' } }), params)
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('not a field')
  })

  test('a credential-looking key is refused rather than silently stripped', async () => {
    // A profile row is exported verbatim into project.json; a token in `config`
    // would leave with the export zip.
    const res = await list.POST(req({ source: 'docker', config: { dockerToken: 'x' } }), params)
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('credential')
    expect(h.create).not.toHaveBeenCalled()
  })

  test('a second profile for the same source is a 409', async () => {
    h.findUnique.mockResolvedValue({ id: 'existing' })
    expect((await list.POST(req({ source: 'docker' }), params)).status).toBe(409)
  })

  test('a double submit that loses the unique-index race is also a 409, not a 500', async () => {
    // The pre-check is not atomic with the insert.
    h.create.mockRejectedValue(new h.P2002())
    const res = await list.POST(req({ source: 'docker', config: { images: ['nginx:1.25'] } }), params)
    expect(res.status).toBe(409)
  })

  test('an empty config is accepted (the start gate reports what is missing)', async () => {
    expect((await list.POST(req({ source: 'docker', config: {} }), params)).status).toBe(201)
  })

  test('a long label is truncated rather than rejected', async () => {
    await list.POST(req({ source: 'docker', label: 'x'.repeat(500) }), params)
    expect(h.create.mock.calls[0][0].data.label).toHaveLength(200)
  })

  test('unicode in a label and config survives', async () => {
    await list.POST(req({ source: 'docker', label: 'prod 🐷 ünïcode', config: { namespace: 'acmé' } }), params)
    expect(h.create.mock.calls[0][0].data.label).toBe('prod 🐷 ünïcode')
    expect(h.create.mock.calls[0][0].data.config).toEqual({ namespace: 'acmé' })
  })

  test('access control is enforced before any write', async () => {
    h.guard.mockResolvedValue(new Response('no', { status: 404 }))
    expect((await list.POST(req({ source: 'docker' }), params)).status).toBe(404)
    expect(h.create).not.toHaveBeenCalled()
  })
})

describe('PATCH / DELETE /profiles/[profileId]', () => {
  test('TENANT ISOLATION: a profile id from another project is a 404, not an update', async () => {
    // findFirst is scoped {id, projectId}; another tenant's id must not resolve.
    h.findFirst.mockResolvedValue(null)
    expect((await item.PATCH(req({ label: 'x' }), itemParams)).status).toBe(404)
    expect(h.update).not.toHaveBeenCalled()
    expect((await item.DELETE(req(), itemParams)).status).toBe(404)
    expect(h.del).not.toHaveBeenCalled()
  })

  test('the lookup is always scoped by projectId', async () => {
    await item.PATCH(req({ label: 'x' }), itemParams)
    expect(h.findFirst.mock.calls[0][0].where).toEqual({ id: 'prof1', projectId: 'p1' })
  })

  test('the source cannot be changed under an existing run history', async () => {
    const res = await item.PATCH(req({ source: 'github' }), itemParams)
    expect(res.status).toBe(400)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('re-sending the same source is not treated as a change', async () => {
    h.update.mockResolvedValue({ id: 'prof1' })
    expect((await item.PATCH(req({ source: 'docker', label: 'y' }), itemParams)).status).toBe(200)
  })

  test('a credential-looking key is refused on update too', async () => {
    const res = await item.PATCH(req({ config: { dockerToken: 'x' } }), itemParams)
    expect(res.status).toBe(400)
    expect(h.update).not.toHaveBeenCalled()
  })

  test('access control is enforced', async () => {
    h.guard.mockResolvedValue(new Response('no', { status: 404 }))
    expect((await item.PATCH(req({}), itemParams)).status).toBe(404)
    expect((await item.DELETE(req(), itemParams)).status).toBe(404)
    expect(h.findFirst).not.toHaveBeenCalled()
  })
})

describe('a DB failure', () => {
  // A Prisma message can quote the row it was writing: the config holds bucket
  // names, org names and image references, all target data.
  const dbError = () => Object.assign(
    new Error('Invalid `prisma.trufflehogScanProfile` invocation: config { bucket: "s3://acme-secrets" }'),
    { name: 'PrismaClientKnownRequestError', code: 'P2024' },
  )

  beforeEach(() => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  test('GET answers {error, code} instead of an empty 500 read as "no sources"', async () => {
    h.findMany.mockRejectedValue(dbError())
    const res = await list.GET(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to list sources', code: 'P2024' })
  })

  test.each([
    ['POST', () => { h.create.mockRejectedValue(dbError()); return list.POST(req({ source: 'docker' }), params) }, 'Failed to add the source'],
    ['PATCH', () => { h.update.mockRejectedValue(dbError()); return item.PATCH(req({ label: 'x' }), itemParams) }, 'Failed to save the source'],
    ['DELETE', () => { h.del.mockRejectedValue(dbError()); return item.DELETE(req(), itemParams) }, 'Failed to delete the source'],
  ])('%s answers the Prisma code, never the message', async (_method, call, message) => {
    const res = await call()
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: message, code: 'P2024' })
    expect(JSON.stringify(body)).not.toContain('acme')
  })

  test('the unique-index race is still a 409, not a 500', async () => {
    h.create.mockRejectedValue(new h.P2002())
    expect((await list.POST(req({ source: 'docker' }), params)).status).toBe(409)
  })
})
