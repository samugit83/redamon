/**
 * A co-owner's export (step 5.2; SH-31, PE-25): `project:export` is Manage, so a Read + Write share
 * with Manage reaches it, and gets the project as they may read it: the row without the owner's secret
 * columns (projectReadView: credentials, header lists, the RoE document and what was parsed from it),
 * RoE revisions without their bodies, only their own conversations (step 5.8 widens it), none of the
 * owner's presets, and an audit row the project's activity feed shows. The owner's export is the one
 * built before: every column, the document, the revision bodies, every conversation, the presets, and
 * no feed line.
 *
 * Runs the real export route; the guard answers a context with the access under test, Prisma answers
 * from fixed rows and records each query, the graph export and the audit writer are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({
  access: null as unknown,
  effective: 'alice',
  queries: [] as Array<{ model: string; args: unknown }>,
  audits: [] as Array<Record<string, unknown>>,
}))

const PROJECT = {
  id: 'p1', userId: 'alice', name: 'Example project', targetDomain: 'rbac.test', engagementKind: 'internal',
  createdAt: new Date('2026-01-01T00:00:00Z'), updatedAt: new Date('2026-01-01T00:00:00Z'),
  katanaDepth: 3,
  // share: secret columns (registry): never in a non-owner's bundle.
  cypherfixGithubToken: 'rbac-fake-token', httpxCustomHeaders: ['X-Api-Key: rbac-fake'], roeClientContactEmail: 'client@rbac.test',
  roeRawText: 'rbac-fake-roe-text', roeDocumentName: 'roe.pdf', roeDocumentData: Buffer.from('rbac-fake-pdf'),
}
const REVISION = {
  documentName: 'old-roe.pdf', mimeType: 'application/pdf', data: Buffer.from('rbac-fake-old-pdf'), rawText: 'rbac-fake-old-text',
  parsedJson: { roeClientName: 'rbac-fake' }, appliedAt: null, supersededAt: new Date('2026-02-01T00:00:00Z'), reason: 'replaced',
}

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string) => ({
    permission, effective: { userId: h.effective }, principal: { id: h.effective, email: `${h.effective}@rbac.test` }, access: h.access,
  }),
}))
vi.mock('@/lib/prisma', () => {
  const model = (name: string) => new Proxy({}, {
    get: (_t, method: string) => async (args: unknown) => {
      h.queries.push({ model: `${name}.${method}`, args })
      if (name === 'project' && method === 'findUnique') return { ...PROJECT }
      if (name === 'roeDocumentRevision' && method === 'findMany') return [{ ...REVISION }]
      if (name === 'userProjectPreset' && method === 'findMany') return [{ name: 'owner-preset', description: '', settings: {}, createdAt: new Date(0) }]
      if (name === 'userMuteRulesPreset' && method === 'findMany') return [{ name: 'owner-rules', description: '', mode: 'off', rules: [] }]
      if (method === 'findMany') return []
      return null
    },
  })
  return { default: new Proxy({}, { get: (_t, name: string) => model(name) }) }
})
vi.mock('@/lib/audit', async (orig) => ({
  ...(await orig<typeof import('@/lib/audit')>()),
  writeAudit: async (entry: Record<string, unknown>) => { h.audits.push(entry) },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: async () => ({ records: [] }), close: async () => {} }) }))
vi.mock('@/lib/projectExport/graph', () => ({ exportProjectGraph: async () => ({ nodes: [], relationships: [], referenceLinks: [] }) }))
vi.mock('@/lib/reconPresets/server', () => ({ projectPresetForRead: () => ({ settings: {} }) }))
vi.mock('fs', async (orig) => ({ ...(await orig<typeof import('fs')>()), existsSync: () => false, readdirSync: () => [] }))

import { GET } from './route'
import { SHARE_SECRET_FIELDS } from '@/lib/authz/projectReadView'
import { REVISIONS_BUNDLE_PATH } from '@/lib/roe/revisionBundle'

const COOWNER = {
  project: { id: 'p1', userId: 'alice' }, level: 'write', via: 'share',
  toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: true },
}
const OWNER = { project: { id: 'p1', userId: 'alice' }, level: 'owner', toggles: { rawData: true }, via: 'owner' }

async function bundle(): Promise<JSZip> {
  const res = await GET(new Request('http://localhost:3000/api/projects/p1/export') as never, { params: Promise.resolve({ id: 'p1' }) })
  expect(res.status).toBe(200)
  return JSZip.loadAsync(await res.arrayBuffer())
}
const json = async (zip: JSZip, name: string) => JSON.parse(await zip.file(name)!.async('string'))

beforeEach(() => {
  h.queries.length = 0
  h.audits.length = 0
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe("non-owner export withholds secrets, others' conversations and presets (step 5.2)", () => {
  beforeEach(() => {
    h.access = COOWNER
    h.effective = 'bob'
  })

  test('the row without any share: secret column and without the RoE document', async () => {
    const project = await json(await bundle(), 'project.json')
    expect(project.katanaDepth).toBe(3)
    for (const key of SHARE_SECRET_FIELDS) expect([key, key in project]).toEqual([key, false])
    expect(project).not.toHaveProperty('roeDocumentDataBase64')
    expect(JSON.stringify(project)).not.toContain('rbac-fake')
  })

  test('RoE revisions without their bodies; only the exporter\'s conversations; no presets', async () => {
    const zip = await bundle()
    const [revision] = await json(zip, REVISIONS_BUNDLE_PATH)
    expect(revision).toMatchObject({ documentName: 'old-roe.pdf', dataBase64: null, rawText: '', parsedJson: null })
    const conversations = h.queries.find(q => q.model === 'conversation.findMany')
    expect(conversations?.args).toMatchObject({ where: { projectId: 'p1', userId: 'bob' } })
    expect(zip.file('presets/user_project_presets.json')).toBeNull()
    expect(zip.file('presets/user_mute_rules_presets.json')).toBeNull()
    expect(h.queries.some(q => q.model.startsWith('userProjectPreset') || q.model.startsWith('userMuteRulesPreset'))).toBe(false)
    expect((await json(zip, 'manifest.json')).stats).toMatchObject({ userPresets: 0, muteRulesPresets: 0 })
  })

  test('writes a feed line naming the exporter, with the project', async () => {
    await bundle()
    expect(h.audits).toEqual([expect.objectContaining({
      action: 'project.exported', actorId: 'bob', targetType: 'project', targetId: 'p1', projectId: 'p1',
    })])
  })
})

describe('owner unchanged', () => {
  test('every column, the document, revision bodies, every conversation, the presets; no feed line', async () => {
    h.access = OWNER
    h.effective = 'alice'
    const zip = await bundle()
    const project = await json(zip, 'project.json')
    expect(project.cypherfixGithubToken).toBe('rbac-fake-token')
    expect(project.roeDocumentDataBase64).toBe(Buffer.from('rbac-fake-pdf').toString('base64'))
    const revisions = await json(zip, REVISIONS_BUNDLE_PATH)
    expect(revisions[0].dataBase64).toBe(Buffer.from('rbac-fake-old-pdf').toString('base64'))
    expect(h.queries.find(q => q.model === 'conversation.findMany')?.args).toMatchObject({ where: { projectId: 'p1' } })
    expect((h.queries.find(q => q.model === 'conversation.findMany')?.args as { where: object }).where).not.toHaveProperty('userId')
    expect(zip.file('presets/user_project_presets.json')).not.toBeNull()
    expect(zip.file('presets/user_mute_rules_presets.json')).not.toBeNull()
    expect(h.audits).toEqual([])
  })
})
