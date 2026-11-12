/**
 * POST /api/projects with a Rules of Engagement document: the document's text
 * and parse are the server's, never the body's.
 *
 * The extractor runs for real on a .txt document.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const mockProjectCreate = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: async () => ({ id: 'user-1' }) },
    project: { create: (...a: unknown[]) => mockProjectCreate(...a), update: async () => ({}) },
    userLlmProvider: { count: async () => 0 },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() }),
}))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'user-1' }),
  ownerScope: (eff: { userId: string }) => ({ userId: eff.userId }),
}))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))

import { NextRequest } from 'next/server'
import { POST } from './route'
import { digestScopeDocument } from '@/lib/engagement'
import { MAX_REQUEST_BYTES } from '@/lib/roe/limits'

const DOC = 'Rules of Engagement\nMaximum 5 requests per second.'
const base = { name: 'roe test', targetDomain: 'roe-e2e.example', targetGuardrailEnabled: false }

function multipart(data: Record<string, unknown>, file: File | null, headers: Record<string, string> = {}) {
  const form = new FormData()
  form.append('data', JSON.stringify(data))
  if (file) form.append('roeDocument', file)
  return POST(new NextRequest('http://localhost:3000/api/projects', {
    method: 'POST', body: form, headers: { host: 'localhost:3000', ...headers },
  }))
}

const created = () => mockProjectCreate.mock.calls[0][0].data as Record<string, unknown>

beforeEach(() => {
  vi.clearAllMocks()
  mockProjectCreate.mockResolvedValue({ id: 'p1', name: 'roe test', userId: 'user-1', targetDomain: 'roe-e2e.example' })
})

describe('a create with a RoE document', () => {
  test('stores the server\'s extraction, not the client\'s text', async () => {
    const res = await multipart(
      { ...base, roeGlobalMaxRps: 5, roeRawText: 'a different text the client made up' },
      new File([DOC], 'roe.txt', { type: 'text/plain' }),
    )
    expect(res.status).toBeLessThan(400)
    expect(created().roeRawText).toBe(DOC)
    expect(created().roeDocumentName).toBe('roe.txt')
    expect(created().roeDocumentMimeType).toBe('text/plain')
  }, 30_000)

  test('rebuilds roeParsedJson: hashes from the server, planted scope keys dropped', async () => {
    await multipart(
      {
        ...base, roeGlobalMaxRps: 5,
        roeParsedJson: {
          applied: { roeGlobalMaxRps: 5, targetDomain: 'evil.example', agentLhost: '203.0.113.9', agentRequireToolConfirmation: false },
          before: { roeGlobalMaxRps: 0, targetDomain: 'x' },
          modelUsed: 'test/model',
          textSha256: '0'.repeat(64),
        },
      },
      new File([DOC], 'roe.txt', { type: 'text/plain' }),
    )
    const parsed = created().roeParsedJson as Record<string, unknown>
    expect(parsed).toMatchObject({
      version: 2, textSha256: digestScopeDocument(DOC), modelUsed: 'test/model',
      applied: { roeGlobalMaxRps: 5 }, before: { roeGlobalMaxRps: 0 }, appliedById: 'user-1',
    })
    expect(parsed.bytesSha256).toMatch(/^[0-9a-f]{64}$/)
  }, 30_000)

  test('an unsupported type is refused before anything is created', async () => {
    const res = await multipart(base, new File(['<html>'], 'roe.html', { type: 'text/html' }))
    expect(res.status).toBe(400)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a declared body over the cap is refused before it is parsed', async () => {
    const res = await multipart(base, new File([DOC], 'roe.txt'), { 'content-length': String(MAX_REQUEST_BYTES + 1) })
    expect(res.status).toBe(413)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })

  test('a cross-origin multipart create is refused', async () => {
    const res = await multipart(base, new File([DOC], 'roe.txt'), { origin: 'http://guinea-pig.localhost:8080' })
    expect(res.status).toBe(403)
    expect(mockProjectCreate).not.toHaveBeenCalled()
  })
})

describe('a create without a document', () => {
  test('stores no RoE artefact at all, whatever the body says', async () => {
    const res = await POST(new NextRequest('http://localhost:3000/api/projects', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ...base, roeRawText: 'planted', roeDocumentName: 'fake.pdf',
        roeParsedJson: { applied: { targetDomain: 'evil.example' } },
      }),
    }))
    expect(res.status).toBeLessThan(400)
    for (const key of ['roeRawText', 'roeDocumentName', 'roeDocumentMimeType', 'roeParsedJson', 'roeDocumentData']) {
      expect(created(), key).not.toHaveProperty(key)
    }
  })
})

describe('a create that fails', () => {
  test('answers the fixed sentence and the Prisma code, never the Prisma message', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mockProjectCreate.mockRejectedValue(Object.assign(
      new Error('Unique constraint failed on the fields: (`id`) value roe-e2e.example'),
      { code: 'P2002', name: 'PrismaClientKnownRequestError' },
    ))
    const res = await POST(new NextRequest('http://localhost:3000/api/projects', {
      method: 'POST',
      headers: { host: 'localhost:3000', 'content-type': 'application/json' },
      body: JSON.stringify(base),
    }))
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to create project', code: 'P2002' })
  })
})
