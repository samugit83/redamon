/** @vitest-environment node */
import { expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({
  // As stored: a source with a token in its query (D10), and a preset, which
  // the save path stored without the project's sources.
  project: { openapiSources: [{ id: 's1', url: 'https://example.test/spec?token=fixture-token' }], openapiEnabled: true },
  preset: { openapiEnabled: true, openapiAutoDiscover: true },
}))
vi.mock('@/lib/prisma', () => ({ default: {
  project: {
    findUnique: vi.fn(async () => ({ id: 'p1', userId: 'u1', name: 'test', targetDomain: 'example.test', ...h.project })),
    findMany: vi.fn(async () => [{ id: 'p1', name: 'test', ...h.project }]),
  },
  ...Object.fromEntries(['conversation', 'chatMessage', 'remediation', 'report', 'scanVersion',
    'scanJob', 'scanSchedule', 'engagementAuthorization', 'roeDocumentRevision', 'nodeFilterExemption', 'userMuteRulesPreset'].map(name => [name, { findMany: vi.fn(async () => []) }])),
  projectNodeFilter: { findUnique: vi.fn(async () => null) },
  userProjectPreset: { findMany: vi.fn(async () => [{ id: 'preset', settings: h.preset }]) },
} }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  requireProjectAccess: vi.fn(async () => ({ project: { id: 'p1', userId: 'u1' } })),
  ownerScope: vi.fn(() => ({ userId: 'u1' })),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({
  run: vi.fn(async () => ({ records: [] })), close: vi.fn(),
}) }))
vi.mock('fs', async original => ({
  ...await original<typeof import('fs')>(), existsSync: vi.fn(() => false), readdirSync: vi.fn(() => []),
}))

import { GET } from './route'
import { GET as listProjects } from '../../route'

test('the export carries the project its document sources, token included, and no preset does', async () => {
  const response = await GET(new NextRequest('http://x/api/projects/p1/export'), { params: Promise.resolve({ id: 'p1' }) })
  expect(response.status).toBe(200)
  const zip = await JSZip.loadAsync(await response.arrayBuffer())
  // D10: a source URL, query token included, is a per-project secret that
  // travels with the project, like the project's other credentials.
  expect(await zip.file('project.json')!.async('text')).toContain('https://example.test/spec?token=fixture-token')
  expect(await zip.file('presets/user_project_presets.json')!.async('text')).not.toContain('openapiSources')
})

test('project list serialization also strips legacy OpenAPI credentials', async () => {
  const response = await listProjects()
  expect(response.status).toBe(200)
  expect(await response.text()).not.toContain('legacy-secret')
})
