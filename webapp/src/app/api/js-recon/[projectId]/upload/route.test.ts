/**
 * JS Recon uploads say why they failed: the size refusal runs before the body is
 * read (a 10 MB file plus its multipart envelope is still accepted), and a
 * filesystem failure answers its errno. The same size check guards custom files.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/js-recon/[projectId]/upload/route.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterAll } from 'vitest'
import { NextRequest } from 'next/server'
import { mkdir, rm, writeFile } from 'fs/promises'
import path from 'path'

const h = vi.hoisted(() => {
  const root = `${process.env.TMPDIR || '/tmp'}/redamon-jsrecon-test-${process.pid}-${Date.now()}`
  process.env.JS_RECON_UPLOAD_PATH = `${root}/uploads`
  process.env.JS_RECON_CUSTOM_PATH = `${root}/custom`
  return { root, findUnique: vi.fn(), update: vi.fn() }
})

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: async () => null }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findUnique(...a),
      update: (...a: unknown[]) => h.update(...a),
    },
  },
}))

import { POST, DELETE } from './route'
import { POST as POST_CUSTOM } from '../custom-files/route'

const params = { params: Promise.resolve({ projectId: 'p1' }) }

function upload(url: string, file: File, fields: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const form = new FormData()
  form.append('file', file)
  for (const [k, v] of Object.entries(fields)) form.append(k, v)
  return new NextRequest(url, { method: 'POST', body: form, headers })
}

beforeEach(async () => {
  vi.clearAllMocks()
  await rm(h.root, { recursive: true, force: true })
  await mkdir(h.root, { recursive: true })
  h.findUnique.mockResolvedValue({ id: 'p1', jsReconUploadedFiles: [] })
  h.update.mockResolvedValue({ updatedAt: new Date('2026-10-01T00:00:00.000Z') })
})

afterAll(async () => {
  await rm(h.root, { recursive: true, force: true })
})

describe('POST /upload', () => {
  test('a declared body over 10 MB plus the envelope is 413 body_too_large, before the body is read', async () => {
    const req = upload('http://localhost/api/js-recon/p1/upload', new File(['x'], 'a.js'), {},
      { 'content-length': String(11 * 1024 * 1024) })
    const formData = vi.spyOn(req, 'formData')
    const res = await POST(req, params)
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({ error: 'The upload is larger than 10 MB.', code: 'body_too_large', limitBytes: 10 * 1024 * 1024 })
    expect(formData).not.toHaveBeenCalled()
  })

  test('a 10 MB file inside its multipart envelope is not refused for size', async () => {
    const req = upload('http://localhost/api/js-recon/p1/upload', new File(['var a = 1'], 'a.js'), {},
      { 'content-length': String(10 * 1024 * 1024 + 4096) })
    const res = await POST(req, params)
    expect(res.status).toBe(200)
  })

  test('a filesystem failure answers its errno, not the path', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await writeFile(path.join(h.root, 'uploads'), 'a file where the upload directory should be')
    const res = await POST(upload('http://localhost/api/js-recon/p1/upload', new File(['var a = 1'], 'a.js')), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.error).toBe('Failed to upload file')
    expect(body.code).toMatch(/^E[A-Z]+$/)
    expect(JSON.stringify(body)).not.toContain(h.root)
  })
})

describe('DELETE /upload', () => {
  test('a database failure answers its Prisma code', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.findUnique.mockRejectedValue(Object.assign(new Error('Can\'t reach database server'), { code: 'P1001' }))
    const res = await DELETE(new NextRequest('http://localhost/api/js-recon/p1/upload?name=a.js', { method: 'DELETE' }), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete file', code: 'P1001' })
  })
})

describe('POST /custom-files', () => {
  test('a declared body over the 2 MB cap is 413 body_too_large', async () => {
    const req = upload('http://localhost/api/js-recon/p1/custom-files', new File(['{}'], 'p.json'), { type: 'patterns' },
      { 'content-length': String(3 * 1024 * 1024) })
    const res = await POST_CUSTOM(req, params)
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({ error: 'The upload is larger than 2 MB.', code: 'body_too_large', limitBytes: 2 * 1024 * 1024 })
  })
})
