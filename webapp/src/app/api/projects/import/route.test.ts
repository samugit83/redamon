/**
 * D10 — project import zip-bomb caps: oversize upload -> 413; too many entries
 * or over-declared-uncompressed -> 400; a normal small export passes the caps.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/projects/import/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import JSZip from 'jszip'

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

function formReq(file: File): NextRequest {
  const fd = new FormData()
  fd.set('file', file)
  // NextRequest accepts a FormData body; it sets the multipart boundary itself.
  return new NextRequest('http://localhost:3000/api/projects/import', {
    method: 'POST',
    body: fd,
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubEnv('PROJECT_IMPORT_MAX_UPLOAD_BYTES', '2000')
  vi.stubEnv('PROJECT_IMPORT_MAX_ENTRIES', '3')
  vi.stubEnv('PROJECT_IMPORT_MAX_UNCOMPRESSED_BYTES', '4096')
})

describe('POST /api/projects/import (D10 caps)', () => {
  test('oversize upload -> 413', async () => {
    const big = new File(['A'.repeat(5000)], 'big.zip', { type: 'application/zip' })
    const res = await POST(formReq(big))
    expect(res.status).toBe(413)
  })

  test('too many entries -> 400', async () => {
    const zip = new JSZip()
    for (let i = 0; i < 10; i++) zip.file(`f${i}.txt`, 'x')
    const buf = await zip.generateAsync({ type: 'uint8array' })
    const f = new File([buf as BlobPart], 'many.zip', { type: 'application/zip' })
    const res = await POST(formReq(f))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/too many entries/)
  })

  test('over-declared uncompressed size -> 400', async () => {
    const zip = new JSZip()
    zip.file('big.txt', 'A'.repeat(8192)) // > 4096 cap
    const buf = await zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE' })
    const f = new File([buf as BlobPart], 'bomb.zip', { type: 'application/zip' })
    const res = await POST(formReq(f))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/decompresses too large/)
  })

  test('a small archive passes the caps (fails later on missing manifest, not the caps)', async () => {
    const zip = new JSZip()
    zip.file('a.txt', 'hi') // no manifest.json -> route returns 400 "missing manifest"
    const buf = await zip.generateAsync({ type: 'uint8array' })
    const f = new File([buf as BlobPart], 'small.zip', { type: 'application/zip' })
    const res = await POST(formReq(f))
    // NOT a cap rejection: the caps passed, so the error is the manifest check.
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/manifest/i)
  })
})

describe('POST /api/projects/import (failures name their cause)', () => {
  test('a declared body over the cap is 413 body_too_large with the limit, before the body is read', async () => {
    vi.stubEnv('PROJECT_IMPORT_MAX_UPLOAD_BYTES', '')
    const req = new NextRequest('http://localhost:3000/api/projects/import', {
      method: 'POST',
      body: 'never read',
      headers: { 'content-type': 'multipart/form-data; boundary=x', 'content-length': String(80 * 1024 * 1024) },
    })
    const formData = vi.spyOn(req, 'formData')
    const res = await POST(req)
    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({
      error: 'The upload is larger than 55 MB.', code: 'body_too_large', limitBytes: 55 * 1024 * 1024,
    })
    expect(formData).not.toHaveBeenCalled()
  })

  test('the default cap fits under the 60 MB request-body cap with room for the envelope', async () => {
    const { DEFAULT_IMPORT_MAX_UPLOAD_BYTES } = await import('./limits')
    const { MULTIPART_ENVELOPE_BYTES } = await import('@/lib/roe/upload')
    expect(DEFAULT_IMPORT_MAX_UPLOAD_BYTES + MULTIPART_ENVELOPE_BYTES).toBeLessThan(60 * 1024 * 1024)
  })

  test('a file that is not a zip is a 400 invalid_zip', async () => {
    const res = await POST(formReq(new File(['not a zip'], 'x.zip', { type: 'application/zip' })))
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('invalid_zip')
  })

  test('an unexpected failure answers a code, never the exception text', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    const zip = new JSZip()
    zip.file('manifest.json', '{"version": 1, "projectName": "secret-target.example"')
    const buf = await zip.generateAsync({ type: 'uint8array' })
    const res = await POST(formReq(new File([buf as BlobPart], 'bad.zip', { type: 'application/zip' })))
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Import failed', code: 'SyntaxError' })
    expect(JSON.stringify(body)).not.toContain('secret-target')
  })
})
