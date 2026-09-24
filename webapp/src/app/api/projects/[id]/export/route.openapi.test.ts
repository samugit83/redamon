/** @vitest-environment node */
import { expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'

const h = vi.hoisted(() => ({
  legacy: {
    openapiSources: [{ id: 's1', url: 'https://example.test/spec', headers: ['Authorization: legacy-secret'] }],
    openapiDiscoveryHeaders: [{ origin: 'https://example.test', headers: ['Cookie: legacy-secret'] }],
  },
}))
vi.mock('@/lib/prisma', () => ({ default: {
  project: {
    findUnique: vi.fn(async () => ({ id: 'p1', userId: 'u1', name: 'test', targetDomain: 'example.test', ...h.legacy })),
    findMany: vi.fn(async () => [{ id: 'p1', name: 'test', ...h.legacy }]),
  },
  ...Object.fromEntries(['conversation', 'chatMessage', 'remediation', 'report', 'scanVersion',
    'scanJob', 'scanSchedule', 'engagementAuthorization'].map(name => [name, { findMany: vi.fn(async () => []) }])),
  userProjectPreset: { findMany: vi.fn(async () => [{ id: 'preset', settings: h.legacy }]) },
} }))
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

test('exported project and embedded presets contain no legacy header credentials', async () => {
  const response = await GET(new NextRequest('http://x/api/projects/p1/export'), { params: Promise.resolve({ id: 'p1' }) })
  expect(response.status).toBe(200)
  const zip = await JSZip.loadAsync(await response.arrayBuffer())
  for (const path of ['project.json', 'presets/user_project_presets.json']) {
    const text = await zip.file(path)!.async('text')
    expect(text).not.toContain('legacy-secret')
    expect(text).not.toContain('openapiDiscoveryHeaders')
    expect(text).toContain('https://example.test/spec')
  }
})

test('project list serialization also strips legacy OpenAPI credentials', async () => {
  const response = await listProjects()
  expect(response.status).toBe(200)
  expect(await response.text()).not.toContain('legacy-secret')
})
