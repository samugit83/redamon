/**
 * POST /api/users/[id]/attack-skills/batch: the upload dialog's one write. A same-origin
 * request of the effective owner only, JSON only, refused at 413 above the byte cap before the
 * body is read, and every refusal of the batch writer answered by its code.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  eff: { userId: 'alice' } as unknown,
  session: { userId: 'alice', role: 'standard' } as { userId: string; role: string } | null,
  batch: vi.fn(),
}))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/session', async () => {
  const { NextResponse } = await import('next/server')
  return {
    getSession: async () => h.session,
    // session.ts requireAccountWrite (the write rule), over the account the test lets this
    // request write, h.eff: a response is that refusal, another account than the path's is 403.
    requireAccountWrite: async (id: string) => h.eff instanceof NextResponse ? h.eff
      : (h.eff as { userId: string }).userId === id ? null
        : NextResponse.json({ error: 'Forbidden', code: 'own_account_only' }, { status: 403 }),
  }
})
vi.mock('@/lib/access', async (orig) => ({
  ...(await orig<typeof import('@/lib/access')>()),
  requireEffectiveUser: async () => h.eff,
}))
vi.mock('@/lib/userSkillWrites', async (orig) => ({
  ...(await orig<typeof import('@/lib/userSkillWrites')>()),
  createUserSkillsBatch: (...a: unknown[]) => h.batch(...a),
}))

import { POST } from './route'
import { MAX_SKILL_BATCH_BYTES, UserSkillError } from '@/lib/userSkills'

const params = (id: string) => ({ params: Promise.resolve({ id }) })

function post(body: unknown, { id = 'alice', headers = {} as Record<string, string> } = {}) {
  return POST(new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills/batch`, {
    method: 'POST',
    headers: { host: 'localhost:3000', 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }), params(id))
}

const ITEMS = [{ name: 'A', content: '# A' }]

beforeEach(() => {
  h.eff = { userId: 'alice' }
  h.session = { userId: 'alice', role: 'standard' }
  h.batch.mockReset()
  h.batch.mockResolvedValue({ created: [{ id: 's1', name: 'A' }], enabled: ['s1'], leftOff: [] })
})

describe('POST /attack-skills/batch', () => {
  test('201 with the writer\'s result; the body fields and the audit actor are passed explicitly', async () => {
    const res = await post({ items: ITEMS, enableInProjectId: 'p1', userId: 'mallory' })
    expect(res.status).toBe(201)
    expect(await res.json()).toEqual({ created: [{ id: 's1', name: 'A' }], enabled: ['s1'], leftOff: [] })
    expect(h.batch).toHaveBeenCalledWith(
      { userId: 'alice', items: ITEMS, enableInProjectId: 'p1' },
      { actorId: 'alice', source: 'ui' },
    )
  })

  test('409 batch_refused carries every refused item', async () => {
    const items = [{ index: 1, code: 'name_taken', error: 'taken', suggestion: 'A v2' }]
    h.batch.mockRejectedValue(new UserSkillError(409, 'batch_refused', '1 of 2 skills cannot be saved; nothing was saved.', { items }))
    const res = await post({ items: ITEMS })
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: '1 of 2 skills cannot be saved; nothing was saved.', code: 'batch_refused', items })
  })

  test('413 batch_too_large for a content-length above 8 MiB, before the body or the session is read', async () => {
    h.eff = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    const req = new NextRequest('http://localhost:3000/api/users/alice/attack-skills/batch', {
      method: 'POST', headers: { 'content-type': 'application/json', 'content-length': String(MAX_SKILL_BATCH_BYTES + 1) }, body: '{}',
    })
    const json = vi.spyOn(req, 'json')
    const text = vi.spyOn(req, 'text')
    const res = await POST(req, params('alice'))
    expect(res.status).toBe(413)
    expect((await res.json()).code).toBe('batch_too_large')
    expect(json).not.toHaveBeenCalled()
    expect(text).not.toHaveBeenCalled()
    expect(h.batch).not.toHaveBeenCalled()
  })

  test('415 for a non-JSON body', async () => {
    const res = await post('items=1', { headers: { 'content-type': 'application/x-www-form-urlencoded' } })
    expect(res.status).toBe(415)
    expect(h.batch).not.toHaveBeenCalled()
  })

  test.each([
    ['a foreign Origin', () => ({ headers: { origin: 'https://evil.example.com' } }), 403],
    ['no session', () => { h.eff = NextResponse.json({ error: 'Unauthorized' }, { status: 401 }); return {} }, 401],
    ["another user's id", () => ({ id: 'bob' }), 403],
    ['an admin not simulating the owner', () => { h.eff = { userId: 'root' }; return {} }, 403],
  ])('%s is refused and the writer is never called', async (_label, setup, status) => {
    const res = await post({ items: ITEMS }, setup() as { id?: string; headers?: Record<string, string> })
    expect(res.status).toBe(status)
    expect(h.batch).not.toHaveBeenCalled()
  })

  test('an admin acting as a passwordless managed owner is audited on behalf of the owner (HD-23: the only admin who writes)', async () => {
    h.session = { userId: 'root', role: 'admin' }
    await post({ items: ITEMS })
    expect(h.batch.mock.calls[0][1]).toEqual({ actorId: 'root', onBehalfOf: 'alice', source: 'ui' })
  })

  test('an unexpected error is 500 and logs no item text', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.batch.mockRejectedValue(new Error('Invalid value: SECRET-SKILL-TEXT'))
    const res = await post({ items: ITEMS })
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to upload the skills', code: 'internal_error' })
    expect(JSON.stringify(log.mock.calls)).not.toContain('SECRET-SKILL-TEXT')
    log.mockRestore()
  })

  test('a database failure answers its Prisma code, and still logs no item text', async () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.batch.mockRejectedValue(Object.assign(new Error('Transaction failed: SECRET-SKILL-TEXT'), {
      name: 'PrismaClientKnownRequestError', code: 'P2028',
    }))
    const res = await post({ items: ITEMS })
    expect(res.status).toBe(500)
    const text = await res.text()
    expect(JSON.parse(text)).toEqual({ error: 'Failed to upload the skills', code: 'P2028' })
    expect(text).not.toContain('SECRET-SKILL-TEXT')
    expect(JSON.stringify(log.mock.calls)).not.toContain('SECRET-SKILL-TEXT')
    log.mockRestore()
  })
})
