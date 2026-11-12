/**
 * /api/projects/[id]/wordlists: the project-ownership guard every other
 * projects/[id] route has (any signed-in user could list, upload or delete in
 * another user's project directory), the size refusal that runs before the body
 * is read, and failures that name their errno instead of a fixed string.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/api/projects/[id]/wordlists/route.test.ts"
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterAll } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import { existsSync } from 'fs'
import { mkdir, rm, writeFile } from 'fs/promises'
import path from 'path'

const h = vi.hoisted(() => {
  const root = `${process.env.TMPDIR || '/tmp'}/redamon-wordlists-test-${process.pid}-${Date.now()}`
  process.env.WORDLIST_UPLOAD_PATH = root
  return { root, guard: vi.fn() }
})

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))

import { GET, POST, DELETE } from './route'

const FOREIGN = 'foreignproject1'
const MINE = 'myproject1'
const params = (id: string) => ({ params: Promise.resolve({ id }) })
const notFound = () => NextResponse.json({ error: 'Not found' }, { status: 404 })

function upload(id: string, file: File, headers: Record<string, string> = {}) {
  const form = new FormData()
  form.append('file', file)
  return new NextRequest(`http://localhost/api/projects/${id}/wordlists`, { method: 'POST', body: form, headers })
}

beforeEach(async () => {
  vi.clearAllMocks()
  await rm(h.root, { recursive: true, force: true })
  await mkdir(path.join(h.root, FOREIGN), { recursive: true })
  await writeFile(path.join(h.root, FOREIGN, 'theirs.txt'), 'admin\n')
  h.guard.mockImplementation(async (id: string) => (id === FOREIGN ? notFound() : null))
})

afterAll(async () => {
  await rm(h.root, { recursive: true, force: true })
})

describe('a project the caller does not own', () => {
  test('GET is refused and lists nothing', async () => {
    const res = await GET(new NextRequest(`http://localhost/api/projects/${FOREIGN}/wordlists`), params(FOREIGN))
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'Not found' })
    expect(h.guard).toHaveBeenCalledWith(FOREIGN)
  })

  test('POST is refused and writes nothing', async () => {
    const res = await POST(upload(FOREIGN, new File(['x\n'], 'mine.txt', { type: 'text/plain' })), params(FOREIGN))
    expect(res.status).toBe(404)
    expect(existsSync(path.join(h.root, FOREIGN, 'mine.txt'))).toBe(false)
  })

  test('DELETE is refused and the file stays', async () => {
    const res = await DELETE(
      new NextRequest(`http://localhost/api/projects/${FOREIGN}/wordlists?name=theirs.txt`, { method: 'DELETE' }),
      params(FOREIGN),
    )
    expect(res.status).toBe(404)
    expect(existsSync(path.join(h.root, FOREIGN, 'theirs.txt'))).toBe(true)
  })
})

describe('the owner', () => {
  test('uploads and lists a wordlist', async () => {
    const res = await POST(upload(MINE, new File(['admin\n'], 'paths.txt', { type: 'text/plain' })), params(MINE))
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.uploaded).toEqual({ name: 'paths.txt', path: `/app/recon/wordlists/${MINE}/paths.txt` })
    expect(h.guard).toHaveBeenCalledWith(MINE)
  })

  test('a declared body over 50 MB is 413 body_too_large with the limit, before the body is read', async () => {
    const req = upload(MINE, new File(['x'], 'big.txt'), { 'content-length': String(51 * 1024 * 1024) })
    const formData = vi.spyOn(req, 'formData')
    const res = await POST(req, params(MINE))
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({
      error: 'The upload is larger than 50 MB.', code: 'body_too_large', limitBytes: 50 * 1024 * 1024,
    })
    expect(formData).not.toHaveBeenCalled()
  })

  test('a 50 MB file inside its multipart envelope passes the size check', async () => {
    const req = upload(MINE, new File(['admin\n'], 'ok.txt'), { 'content-length': String(50 * 1024 * 1024 + 2048) })
    const res = await POST(req, params(MINE))
    expect(res.status).not.toBe(413)
  })

  test('a filesystem failure answers its errno, not the path', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    // A file where the project's directory should be: mkdir cannot create it.
    await writeFile(path.join(h.root, MINE), 'not a directory')
    const res = await POST(upload(MINE, new File(['admin\n'], 'paths.txt')), params(MINE))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body.error).toBe('Failed to upload wordlist')
    expect(body.code).toMatch(/^E[A-Z]+$/)
    expect(JSON.stringify(body)).not.toContain(h.root)
  })
})
