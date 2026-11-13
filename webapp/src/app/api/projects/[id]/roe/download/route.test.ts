/**
 * GET /api/projects/[id]/roe/download: the document is the owner's, on a shared project too
 * (OQ-53: a read collaborator reaches roe:read but never the document).
 *
 * Before this the route had no object-level check at all: any signed-in user
 * holding a project id downloaded another user's signed Rules of Engagement,
 * client contacts included. The filename and the media type were also served as
 * the client sent them at upload.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindUnique = vi.fn()
const mockGetEffectiveUser = vi.fn()
const mockAudit = vi.fn()
// The access level the guard grants; null keeps the double's answer (the owner). Until step 4.3
// projectAccess() only ever answers the owner, so a read collaborator is this level.
const h = vi.hoisted(() => ({ level: null as string | null }))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => mockFindUnique(...a) } },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => mockAudit(...a) }))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))
vi.mock('@/lib/authz/guards', async () => {
  const guards = await import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser())
  return {
    ...guards,
    requirePermission: async (...a: Parameters<typeof guards.requirePermission>) => {
      const ctx = await guards.requirePermission(...a)
      if (h.level === null || ctx instanceof Response || !ctx.access) return ctx
      return { ...ctx, access: { ...ctx.access, level: h.level } } as unknown as typeof ctx
    },
  }
})
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { GET } from './route'
import { attachmentDisposition, downloadContentType } from '@/lib/roe/limits'

const BYTES = Buffer.from('%PDF-1.4 synthetic')

function wire(ownerId: string, row: Record<string, unknown> = {}) {
  mockFindUnique.mockImplementation((args: { select?: Record<string, boolean> }) =>
    args?.select?.userId
      ? Promise.resolve({ id: 'proj-Y', userId: ownerId })
      : Promise.resolve({
          roeDocumentData: BYTES,
          roeDocumentName: 'roe.pdf',
          roeDocumentMimeType: 'application/pdf',
          ...row,
        }),
  )
}

const get = () =>
  GET(new NextRequest('http://x/api/projects/proj-Y/roe/download'), { params: Promise.resolve({ id: 'proj-Y' }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.level = null
  delete process.env.ACCESS_ENFORCE
})

const documentRead = () =>
  mockFindUnique.mock.calls.some(([args]) => Boolean((args as { select?: Record<string, boolean> })?.select?.roeDocumentData))

describe('owner only (OQ-53)', () => {
  test('read collaborator 403', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'reader' })
    wire('reader')
    h.level = 'read'
    const res = await get()
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({
      error: "Only the project's owner can download the rules of engagement document.",
      code: 'owner_only',
      permission: 'roe:read',
    })
    expect(documentRead()).toBe(false)
    expect(mockAudit).not.toHaveBeenCalled()
  })

  test('owner unchanged', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'victim' })
    wire('victim')
    h.level = 'owner'
    const res = await get()
    expect(res.status).toBe(200)
    expect(Buffer.from(await res.arrayBuffer()).equals(BYTES)).toBe(true)
    expect(mockAudit).toHaveBeenCalledTimes(1)
  })
})

describe('BOLA', () => {
  test('another user gets a 404 and no bytes', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'attacker' })
    wire('victim')
    const res = await get()
    expect(res.status).toBe(404)
    expect(await res.text()).not.toContain('PDF')
    expect(mockAudit).not.toHaveBeenCalled()
  })

  test('no session is a 401', async () => {
    const { NextResponse } = await import('next/server')
    mockGetEffectiveUser.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    wire('victim')
    expect((await get()).status).toBe(401)
  })

  test('the owner gets the bytes, and the download is audited', async () => {
    mockGetEffectiveUser.mockResolvedValue({ userId: 'victim' })
    wire('victim')
    const res = await get()
    expect(res.status).toBe(200)
    expect(Buffer.from(await res.arrayBuffer()).equals(BYTES)).toBe(true)
    expect(mockAudit).toHaveBeenCalledWith(expect.objectContaining({
      action: 'project.roe.download', targetId: 'proj-Y', actorId: 'victim',
    }))
  })
})

describe('headers', () => {
  beforeEach(() => mockGetEffectiveUser.mockResolvedValue({ userId: 'victim' }))

  test('nosniff, and the stored type only when it is one of ours', async () => {
    wire('victim', { roeDocumentMimeType: 'text/html' })
    const res = await get()
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('content-type')).toBe('application/octet-stream')
  })

  test('a filename with a quote and CR/LF cannot inject a header parameter', async () => {
    wire('victim', { roeDocumentName: 'a";\r\nSet-Cookie: x=1.pdf' })
    const res = await get()
    const cd = res.headers.get('content-disposition') || ''
    expect(cd.startsWith('attachment; filename="')).toBe(true)
    expect(cd).not.toMatch(/[\r\n]/)
    // One quoted parameter only: the injected quote is replaced, not echoed.
    expect(cd.match(/"/g)?.length).toBe(2)
  })

  test('a non-ASCII name survives through filename*', () => {
    const cd = attachmentDisposition('Règles d’engagement.pdf')
    expect(cd).toContain(`filename*=UTF-8''R%C3%A8gles%20d%E2%80%99engagement.pdf`)
    expect(cd).toContain('filename="R_gles d_engagement.pdf"')
  })

  test('the allowlist maps each kind and nothing else', () => {
    expect(downloadContentType('application/pdf')).toBe('application/pdf')
    expect(downloadContentType('text/plain')).toBe('text/plain; charset=utf-8')
    expect(downloadContentType('image/svg+xml')).toBe('application/octet-stream')
    expect(downloadContentType(null)).toBe('application/octet-stream')
  })
})

test('a database failure answers the fixed sentence and the Prisma code', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner' })
  mockFindUnique.mockImplementation((args: { select?: Record<string, boolean> }) =>
    args?.select?.userId
      ? Promise.resolve({ id: 'proj-Y', userId: 'owner' })
      : Promise.reject(Object.assign(new Error('Timed out fetching a new connection'), { code: 'P2024' })),
  )
  const res = await get()
  expect(res.status).toBe(500)
  expect(await res.json()).toEqual({ error: 'Failed to download RoE document', code: 'P2024' })
})
