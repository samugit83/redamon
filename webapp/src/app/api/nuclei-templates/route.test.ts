/**
 * /api/nuclei-templates failures name their cause: an oversized body is refused
 * with the limit before it is read, and a filesystem failure on the shared
 * templates volume answers its errno (EACCES, ENOSPC, EROFS).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/nuclei-templates/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterAll } from 'vitest'
import { NextRequest } from 'next/server'
import { mkdir, rm, writeFile } from 'fs/promises'
import path from 'path'
// The route reads the session first (HD-10); these tests are about a signed-in account.
vi.mock('@/lib/session', () => ({ requireSession: async () => ({ userId: 'u1', role: 'standard' }) }))

const h = vi.hoisted(() => {
  const root = `${process.env.TMPDIR || '/tmp'}/redamon-nuclei-test-${process.pid}-${Date.now()}`
  process.env.NUCLEI_TEMPLATES_PATH = root
  return { root }
})

import { POST, DELETE } from './route'

const TEMPLATE = 'id: demo\ninfo:\n  name: Demo\n  severity: low\n'

function upload(file: File, fields: Record<string, string> = {}, headers: Record<string, string> = {}) {
  const form = new FormData()
  form.append('file', file)
  for (const [k, v] of Object.entries(fields)) form.append(k, v)
  return new NextRequest('http://localhost/api/nuclei-templates', { method: 'POST', body: form, headers })
}

beforeEach(async () => {
  await rm(h.root, { recursive: true, force: true })
  await mkdir(h.root, { recursive: true })
})

afterAll(async () => {
  await rm(h.root, { recursive: true, force: true })
})

describe('POST', () => {
  test('a declared body over the 1 MB cap is 413 body_too_large, before the body is read', async () => {
    const req = upload(new File([TEMPLATE], 't.yaml'), {}, { 'content-length': String(2 * 1024 * 1024) })
    const formData = vi.spyOn(req, 'formData')
    const res = await POST(req)
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({ error: 'The upload is larger than 1 MB.', code: 'body_too_large', limitBytes: 1024 * 1024 })
    expect(formData).not.toHaveBeenCalled()
  })

  test('a filesystem failure answers its errno, not the path', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await writeFile(path.join(h.root, 'blocked'), 'a file where the subdirectory should be')
    const res = await POST(upload(new File([TEMPLATE], 't.yaml'), { subdir: 'blocked' }))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.error).toBe('Failed to upload template')
    expect(body.code).toMatch(/^E[A-Z]+$/)
    expect(JSON.stringify(body)).not.toContain(h.root)
  })

  test('a valid template still uploads', async () => {
    const res = await POST(upload(new File([TEMPLATE], 't.yml')))
    expect(res.status).toBe(200)
    expect((await res.json()).uploaded).toEqual({ name: 't.yaml', path: 't.yaml', id: 'demo' })
  })
})

describe('DELETE', () => {
  test('a filesystem failure answers its errno', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    // A directory named like a template: unlink refuses it.
    await mkdir(path.join(h.root, 'dir.yaml'))
    const res = await DELETE(new NextRequest('http://localhost/api/nuclei-templates?path=dir.yaml', { method: 'DELETE' }))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.error).toBe('Failed to delete template')
    expect(body.code).toMatch(/^E[A-Z]+$/)
  })
})
