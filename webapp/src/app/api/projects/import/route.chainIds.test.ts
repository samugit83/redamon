/**
 * R-15: the import renames each conversation's session id, and a chain id IS its
 * conversation's session id, so the restore is told the new one: the imported chain
 * then belongs to the imported conversation (its delete, its graph toggle), and no
 * restored node carries the source project's chain id. How the restore applies it
 * is graphRestore.globalIds.test.ts's.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({
  restoreGraph: vi.fn(),
  clearProjectGraph: vi.fn(),
  conversationCreate: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: vi.fn().mockResolvedValue({ id: 'newProject', name: 'src' }) },
    conversation: { create: (...a: unknown[]) => h.conversationCreate(...a) },
    chatMessage: { createMany: vi.fn() },
    remediation: { createMany: vi.fn() },
    report: { create: vi.fn() },
    userProjectPreset: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/graphRestore', () => ({
  clearProjectGraph: (...a: unknown[]) => h.clearProjectGraph(...a),
  restoreGraph: (...a: unknown[]) => h.restoreGraph(...a),
}))

import { POST } from './route'

const conversation = (id: string, sessionId: string) => ({
  id, projectId: 'oldProject', userId: 'oldOwner', sessionId, title: id, status: 'completed',
  agentRunning: false, currentPhase: 'informational', iterationCount: 3,
  createdAt: '2026-11-01T00:00:00Z', updatedAt: '2026-11-01T00:00:00Z',
})

async function bundle(withConversations: boolean): Promise<File> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1.1.0', projectName: 'src', stats: {} }))
  zip.file('project.json', JSON.stringify({ id: 'oldProject', userId: 'oldOwner', name: 'src', targetDomain: 'example.com' }))
  if (withConversations) {
    zip.file('conversations/conversations.json', JSON.stringify([
      conversation('c1', 'sess-A'), conversation('c2', 'sess-B')]))
  }
  zip.file('neo4j/nodes.json', JSON.stringify([
    { labels: ['AttackChain'], properties: { chain_id: 'sess-A' }, _exportId: 'n1' }]))
  zip.file('neo4j/relationships.json', JSON.stringify([]))
  const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
  return new File([buf], 'export.zip', { type: 'application/zip' })
}

const req = (file: File) => {
  const fd = new FormData()
  fd.set('file', file)
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.restoreGraph.mockResolvedValue({ nodes: 1, relationships: 0 })
  let n = 0
  h.conversationCreate.mockImplementation(async () => ({ id: `new-${++n}` }))
})

describe('import — chain ids follow the renamed conversations (R-15)', () => {
  test("each exported session id maps to its imported conversation's new one", async () => {
    const res = await POST(req(await bundle(true)))
    expect(res.status).toBe(200)

    const created = h.conversationCreate.mock.calls.map(([arg]) => (arg as { data: { sessionId: string } }).data.sessionId)
    expect(created).toHaveLength(2)
    expect(created[0]).toMatch(/^sess-A_imported_[0-9a-f]{8}$/)

    const [, , , opts] = h.restoreGraph.mock.calls[0]
    expect(opts).toMatchObject({ projectId: 'newProject', userId: 'importer' })
    const renamed = opts.renamedChainIds as ReadonlyMap<string, string>
    expect(renamed.get('sess-A')).toBe(created[0])
    expect(renamed.get('sess-B')).toBe(created[1])
    expect(renamed.size).toBe(2)
  })

  test('a bundle with no conversations still restores, with nothing renamed', async () => {
    const res = await POST(req(await bundle(false)))
    expect(res.status).toBe(200)
    const [, , , opts] = h.restoreGraph.mock.calls[0]
    expect((opts.renamedChainIds as ReadonlyMap<string, string>).size).toBe(0)
  })
})
