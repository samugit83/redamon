/**
 * Strategy row 9 (L5): import is a SECOND creation path.
 *
 * `create_project` refuses a third-party engagement with no rate ceiling and no
 * authorization record. Import builds a project from a zip, so if it does not
 * apply the same rule it IS the way around it: export a compliant project, edit
 * one JSON field, import it back with the ceiling gone.
 *
 * The other half matters as much. Refusing is right; silently DOWNGRADING the
 * bundle to `internal` would strip the ceiling the exporting side declared and
 * say nothing, which is the same outcome reached quietly.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/api/projects/import/route.engagement.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn() }))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    engagementAuthorization: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))

import { POST } from './route'

const THIRD_PARTY_AUTH = [{
  documentSha256: 'd'.repeat(64),
  documentKind: 'hackerone_program',
  sourceUrl: 'https://example.invalid/program',
  programHandle: 'row9',
  issuedAt: '2026-01-01T00:00:00.000Z',
  recordedAt: '2026-01-02T00:00:00.000Z',
  summary: 'row 9',
}]

async function bundle(
  project: Record<string, unknown>,
  authorizations: unknown[] | null
): Promise<NextRequest> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1', projectName: 'imported' }))
  zip.file('project.json', JSON.stringify({
    id: 'old', userId: 'old', name: 'imported', targetDomain: 'example.invalid',
    createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    ...project,
  }))
  if (authorizations !== null) {
    zip.file('engagement/authorizations.json', JSON.stringify(authorizations))
  }
  // 'arraybuffer', not 'uint8array': a Uint8Array<ArrayBufferLike> is not a
  // valid BlobPart under this tsconfig.
  const buf = await zip.generateAsync({ type: 'arraybuffer' })
  const fd = new FormData()
  fd.set('file', new File([buf], 'p.zip', { type: 'application/zip' }))
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.createProject.mockResolvedValue({ id: 'new', name: 'imported' })
})

describe('row 9: an unauthorized third-party bundle is refused', () => {
  test('no ceiling and no authorization -> 400 naming both', async () => {
    const res = await POST(await bundle({ engagementKind: 'third_party' }, []))
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/request-rate ceiling/)
    expect(body.error).toMatch(/authorization record/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('a ceiling but no authorization -> 400 naming the authorization', async () => {
    const res = await POST(await bundle(
      { engagementKind: 'third_party', roeGlobalMaxRps: 3 },
      []
    ))
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/authorization record/)
    expect(body.error).not.toMatch(/request-rate ceiling/)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('an authorization but a zero ceiling -> 400, because 0 means unlimited', async () => {
    const res = await POST(await bundle(
      { engagementKind: 'third_party', roeGlobalMaxRps: 0 },
      THIRD_PARTY_AUTH
    ))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/request-rate ceiling/)
  })

  test('a legacy bundle carrying roeEnabled has it ignored, not replayed', async () => {
    // The column is DERIVED now, so a bundle exported before this shipped still
    // carries it. Replaying it would write a value nothing else believes; the
    // ceiling beside it is what decides, and it round-trips normally.
    const res = await POST(await bundle(
      { engagementKind: 'third_party', roeEnabled: false, roeGlobalMaxRps: 3 },
      THIRD_PARTY_AUTH
    ))
    expect(res.status).toBe(200)
    expect(h.createProject.mock.calls[0][0].data).not.toHaveProperty('roeEnabled')
  })

  test('a missing authorizations file counts as none, not as unchecked', async () => {
    const res = await POST(await bundle(
      { engagementKind: 'third_party', roeGlobalMaxRps: 3 },
      null
    ))
    expect(res.status).toBe(400)
    expect(h.createProject).not.toHaveBeenCalled()
  })

  test('the refusal never downgrades the bundle to internal', async () => {
    const res = await POST(await bundle({ engagementKind: 'third_party' }, []))
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/not imported/i)
  })

  test('a compliant third-party bundle is imported with its kind intact', async () => {
    const res = await POST(await bundle(
      { engagementKind: 'third_party', roeGlobalMaxRps: 3 },
      THIRD_PARTY_AUTH
    ))
    expect(res.status).toBeLessThan(400)
    expect(h.createProject.mock.calls[0][0].data.engagementKind).toBe('third_party')
  })

  test('an internal bundle needs neither', async () => {
    const res = await POST(await bundle({ engagementKind: 'internal' }, []))
    expect(res.status).toBeLessThan(400)
    expect(h.createProject.mock.calls[0][0].data.engagementKind).toBe('internal')
  })
})

test('importing a legacy project copy discards plaintext OpenAPI headers', async () => {
  const res = await POST(await bundle({
    engagementKind: 'internal',
    openapiSources: [{ id: 's1', url: 'https://example.test/spec', headers: ['Authorization: legacy-secret'] }],
    openapiDiscoveryHeaders: [{ origin: 'https://example.test', headers: ['Cookie: legacy-secret'] }],
  }, []))
  expect(res.status).toBeLessThan(400)
  const stored = h.createProject.mock.calls[0][0].data
  expect(stored.openapiSources).toEqual([{ id: 's1', url: 'https://example.test/spec' }])
  expect(stored).not.toHaveProperty('openapiDiscoveryHeaders')
  expect(JSON.stringify(stored)).not.toContain('legacy-secret')
})
