/**
 * Integration tests for /api/users/[id] GET + PUT.
 *
 * Run: npx vitest run "src/app/api/users/[id]/route.test.ts"
 *
 * Focus: the per-user remembered-model defaults (defaultAgentModel /
 * defaultAiPipelineModel) added for the project model-gate feature — that GET
 * returns them, PUT persists them, the typeof-string guard holds, and a
 * standard user can update their OWN defaults without admin rights.
 *
 * @/lib/prisma and @/lib/session are mocked so handlers run without a DB or
 * a real auth cookie.
 */

import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockFindUnique = vi.fn()
const mockUpdate = vi.fn()
const mockDelete = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()
const mockProjectFindMany = vi.fn()
const mockPurge = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: (...args: unknown[]) => mockFindUnique(...args),
      update: (...args: unknown[]) => mockUpdate(...args),
      delete: (...args: unknown[]) => mockDelete(...args),
    },
    capturedHttpTransaction: { findMany: vi.fn().mockResolvedValue([]) },
    project: { findMany: (...args: unknown[]) => mockProjectFindMany(...args) },
  },
}))

vi.mock('@/lib/workspacePurge', () => ({
  purgeProjectWorkspace: (...args: unknown[]) => mockPurge(...args),
}))

vi.mock('@/lib/session', () => ({
  getSession: (...args: unknown[]) => mockGetSession(...args),
  isInternalRequest: (...args: unknown[]) => mockIsInternal(...args),
}))

import { GET, PUT, DELETE } from './route'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeSession(userId = 'user-1', role: 'admin' | 'standard' = 'standard') {
  return { userId, role }
}

function makeParams(id: string) {
  return { params: Promise.resolve({ id }) }
}

function getReq() {
  return new Request('http://localhost/api/users/user-1') as never
}

function putReq(body: unknown) {
  return new Request('http://localhost/api/users/user-1', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }) as never
}

beforeEach(() => {
  mockFindUnique.mockReset()
  mockUpdate.mockReset()
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
  mockIsInternal.mockReturnValue(false)
  mockProjectFindMany.mockReset()
  mockProjectFindMany.mockResolvedValue([])
  mockPurge.mockReset()
  mockPurge.mockResolvedValue(undefined)
})

// ---------------------------------------------------------------------------
// GET
// ---------------------------------------------------------------------------

describe('GET /api/users/[id]', () => {
  test('401 when no session (not internal)', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(401)
  })

  test('403 when a standard user requests another user', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await GET(getReq(), makeParams('user-2'))
    expect(res.status).toBe(403)
  })

  test('returns the user including the new default-model fields (self)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({
      id: 'user-1',
      name: 'Sam',
      email: 's@example.com',
      role: 'standard',
      defaultAgentModel: 'deepseek/deepseek-chat',
      defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      projects: [],
    })
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect(body.defaultAiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('each project names its target from its scope, a batch included', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({ id: 'user-1', projects: [
      { id: 'p1', name: 'Batch', targetDomain: '', ipMode: false, domainBatchMode: true,
        domainBatchHosts: ['www.acme.co.uk', 'shop.acme.co.uk'], subdomainList: [], targetIps: [] },
      { id: 'p2', name: 'Single', targetDomain: 'api.example.com', ipMode: false, domainBatchMode: false,
        domainBatchHosts: [], subdomainList: [], targetIps: [] },
    ] })
    const body = await (await GET(getReq(), makeParams('user-1'))).json()
    expect(body.projects.map((p: { targetLabel: string }) => p.targetLabel)).toEqual(
      ['acme.co.uk: www, shop (listed)', 'api.example.com'])
    // The scope columns are read for the label, not passed through.
    expect(body.projects[0]).not.toHaveProperty('domainBatchHosts')
  })

  test('select clause requests the new default-model fields', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue({ id: 'user-1', projects: [] })
    await GET(getReq(), makeParams('user-1'))
    const select = mockFindUnique.mock.calls[0][0].select
    expect(select.defaultAgentModel).toBe(true)
    expect(select.defaultAiPipelineModel).toBe(true)
  })

  test('internal request bypasses session checks', async () => {
    mockIsInternal.mockReturnValue(true)
    mockFindUnique.mockResolvedValue({ id: 'user-9', defaultAgentModel: null, projects: [] })
    const res = await GET(getReq(), makeParams('user-9'))
    expect(res.status).toBe(200)
    expect(mockGetSession).not.toHaveBeenCalled()
  })

  test('404 when user not found', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockResolvedValue(null)
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(404)
  })

  test('500 when prisma throws', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockRejectedValue(new Error('db down'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET(getReq(), makeParams('user-1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })

  test('the 500 names the Prisma code, never the message', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockFindUnique.mockRejectedValue(Object.assign(new Error("Can't reach database server at db:5432"), { code: 'P1001' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await GET(getReq(), makeParams('user-1'))
    expect(await res.json()).toEqual({ error: 'Failed to fetch user', code: 'P1001' })
    errSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// PUT
// ---------------------------------------------------------------------------

describe('PUT /api/users/[id]', () => {
  test('401 when no session', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(401)
  })

  test('403 when a standard user updates another user', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-2'))
    expect(res.status).toBe(403)
  })

  test('standard user persists their OWN default models (no admin needed)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1', 'standard'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({
      id: 'user-1',
      ...data,
    }))
    const res = await PUT(
      putReq({
        defaultAgentModel: 'deepseek/deepseek-chat',
        defaultAiPipelineModel: 'deepseek/deepseek-reasoner',
      }),
      makeParams('user-1'),
    )
    expect(res.status).toBe(200)
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect(data.defaultAiPipelineModel).toBe('deepseek/deepseek-reasoner')
  })

  test('only the provided default field is written (partial update)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    await PUT(putReq({ defaultAgentModel: 'deepseek/deepseek-chat' }), makeParams('user-1'))
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
    expect('defaultAiPipelineModel' in data).toBe(false)
  })

  test('non-string default values are ignored (typeof guard)', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    // numbers / objects must not reach the DB write
    await PUT(
      putReq({ defaultAgentModel: 123, defaultAiPipelineModel: { nope: true } }),
      makeParams('user-1'),
    )
    const data = mockUpdate.mock.calls[0][0].data
    expect('defaultAgentModel' in data).toBe(false)
    expect('defaultAiPipelineModel' in data).toBe(false)
  })

  test('the new default fields are returned in the select clause', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockResolvedValue({ id: 'user-1' })
    await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    const select = mockUpdate.mock.calls[0][0].select
    expect(select.defaultAgentModel).toBe(true)
    expect(select.defaultAiPipelineModel).toBe(true)
  })

  test('updating name/email still works alongside the new fields', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => ({ id: 'user-1', ...data }))
    await PUT(
      putReq({ name: 'New Name', defaultAgentModel: 'deepseek/deepseek-chat' }),
      makeParams('user-1'),
    )
    const data = mockUpdate.mock.calls[0][0].data
    expect(data.name).toBe('New Name')
    expect(data.defaultAgentModel).toBe('deepseek/deepseek-chat')
  })

  test('404 (P2025) when user not found', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(Object.assign(new Error('not found'), { code: 'P2025' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(404)
    errSpy.mockRestore()
  })

  test('500 on other prisma errors', async () => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    mockUpdate.mockRejectedValue(new Error('write failed'))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await PUT(putReq({ defaultAgentModel: 'x' }), makeParams('user-1'))
    expect(res.status).toBe(500)
    errSpy.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// DELETE
// ---------------------------------------------------------------------------

describe('DELETE /api/users/[id]', () => {
  const delReq = () => new Request('http://localhost/api/users/user-2', { method: 'DELETE' }) as never

  test('a cascade the database refused names its code, never its message', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockDelete.mockRejectedValue(Object.assign(new Error('Foreign key constraint failed on the field: `user_id`'), { code: 'P2003' }))
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete user', code: 'P2003' })
    errSpy.mockRestore()
  })

  test("deleting a user purges each of their projects' workspaces, after the delete", async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockProjectFindMany.mockResolvedValue([{ id: 'proj-a' }, { id: 'proj-b' }])
    const order: string[] = []
    mockDelete.mockImplementation(async () => { order.push('delete') })
    mockPurge.mockImplementation(async (pid: string) => { order.push(`purge ${pid}`) })
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(200)
    expect(mockProjectFindMany).toHaveBeenCalledWith({ where: { userId: 'user-2' }, select: { id: true } })
    // The agent refuses a purge while the web app still answers for the project.
    expect(order).toEqual(['delete', 'purge proj-a', 'purge proj-b'])
  })

  test('a failed purge never fails the user delete', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockProjectFindMany.mockResolvedValue([{ id: 'proj-a' }])
    mockDelete.mockResolvedValue({})
    mockPurge.mockRejectedValue(new Error('agent down'))
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(200)
  })

  test('a user already gone is still a 404', async () => {
    mockGetSession.mockResolvedValue(makeSession('admin-1', 'admin'))
    mockDelete.mockRejectedValue(Object.assign(new Error('Record to delete does not exist.'), { code: 'P2025' }))
    const res = await DELETE(delReq(), makeParams('user-2'))
    expect(res.status).toBe(404)
  })
})


describe('PUT /api/users/[id]: Agent in the Loop is never a default model', () => {
  test.each([
    [{ defaultAgentModel: 'loop/mcp', defaultAiPipelineModel: 'gpt-5' }],
    [{ defaultAiPipelineModel: 'loop/mcp' }],
  ])('%j -> 400, nothing written', async (body) => {
    mockGetSession.mockResolvedValue(makeSession('user-1'))
    const res = await PUT(putReq(body), makeParams('user-1'))
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({
      error: 'Agent in the Loop cannot be a default model; pick it per project.',
      code: 'loop_model_not_allowed',
    })
    expect(mockUpdate).not.toHaveBeenCalled()
  })
})
