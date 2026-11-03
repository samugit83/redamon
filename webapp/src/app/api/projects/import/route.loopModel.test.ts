/**
 * An imported project never arrives on Agent in the Loop (T24, Q25): a person
 * picks the brain. A loop agent model is replaced by the importing user's
 * default (never itself a loop model) or the schema default, and the answer
 * says so; a loop pipeline model is dropped so the schema default applies.
 *
 * Same harness as route.engagement.test.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({ createProject: vi.fn(), findUser: vi.fn() }))

vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1', role: 'user' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.createProject(...a) },
    user: { findUnique: (...a: unknown[]) => h.findUser(...a) },
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
  h.findUser.mockResolvedValue({ defaultAgentModel: null })
})

const created = () => h.createProject.mock.calls[0][0].data as Record<string, unknown>

describe('a loop model in the bundle', () => {
  test('is replaced by the importing user\'s default, and the answer says so', async () => {
    h.findUser.mockResolvedValue({ defaultAgentModel: 'deepseek/deepseek-chat' })
    const res = await POST(await bundle({ agentOpenaiModel: 'loop/mcp', aiPipelineModel: 'gpt-5' }, null))
    expect(res.status).toBe(200)
    expect(created().agentOpenaiModel).toBe('deepseek/deepseek-chat')
    expect(created().aiPipelineModel).toBe('gpt-5')
    const body = await res.json()
    expect(body.warnings.join('\n')).toMatch(/used Agent in the Loop; it was imported with deepseek\/deepseek-chat/)
  })

  test('falls back to the schema default when the user has none (or a loop one)', async () => {
    for (const fallback of [null, 'loop/mcp']) {
      h.createProject.mockClear()
      h.findUser.mockResolvedValue({ defaultAgentModel: fallback })
      await POST(await bundle({ agentOpenaiModel: 'loop/mcp' }, null))
      expect(created().agentOpenaiModel).toBe('claude-opus-4-6')
    }
  })

  test('a loop pipeline model is dropped', async () => {
    await POST(await bundle({ aiPipelineModel: 'loop/mcp' }, null))
    expect('aiPipelineModel' in created()).toBe(false)
  })

  test('a provider model is imported as it is', async () => {
    const res = await POST(await bundle({ agentOpenaiModel: 'gpt-5' }, null))
    expect(created().agentOpenaiModel).toBe('gpt-5')
    expect((await res.json()).warnings.join('\n')).not.toMatch(/Agent in the Loop/)
    expect(h.findUser).not.toHaveBeenCalled()
  })
})
