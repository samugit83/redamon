/**
 * HD-27 on GET /api/projects/[id]: a browser caller who is not the owner never receives the
 * owner's secrets (the registry's `share: secret` columns); the owner and the service callers
 * read the row as before.
 *
 * The guard is doubled to answer the access level under test: until step 4.3 projectAccess() only
 * ever answers the owner, so a read collaborator exists here only as the level the guard hands
 * the route.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'internal-key-for-tests-0000000000000'
vi.stubEnv('INTERNAL_API_KEY', MASTER)

const FAKE = 'rbac-fake-share-secret-0001'
const h = vi.hoisted(() => ({ level: 'owner' as string }))

vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async ({ where }: { where: { id: string } }) => ({
        id: where.id, userId: 'owner-1', name: 'p', targetDomain: 'example.test', ipMode: false,
        domainBatchMode: false, nucleiSelectedCustomTemplates: [], nucleiTemplates: [], nucleiCustomTemplates: [],
        cypherfixGithubToken: FAKE,
        graphqlAuthValue: FAKE,
        phishingSmtpConfig: FAKE,
        roeClientContactEmail: 'client@e2e.local',
        roeRawText: FAKE,
        roeDocumentData: Buffer.from(FAKE),
        httpxCustomHeaders: [`X-Api-Key: ${FAKE}`],
        kiterunnerHeaders: [`Authorization-Token: ${FAKE}`],
        graphqlAuthHeader: 'X-Graphql-Auth',
        user: { id: 'owner-1', name: 'Owner', email: 'owner@e2e.local' },
        authProfile: null,
        nodeFilter: null, nodeFilterExemptions: [],
      }),
    },
    nucleiTemplate: { findMany: async () => [] },
    userSettings: { findUnique: async () => null },
  },
}))
vi.mock('@/lib/userSkillAgentPayload', () => ({ userSkillsForAgent: async () => [] }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/authz/guards', async () => {
  const real = await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')
  return {
    ...real,
    requirePermission: async (_r: Request, permission: string, opts: { projectId?: string } = {}) => ({
      session: { userId: 'caller-1', role: 'standard' },
      principal: { id: 'caller-1', role: 'standard' },
      actingAs: null,
      effective: { userId: 'caller-1' },
      permission,
      access: { project: { id: opts.projectId, userId: 'owner-1' }, level: h.level },
    }),
  }
})

import { GET } from './route'

function get(headers: Record<string, string> = {}) {
  return GET(new NextRequest('http://localhost/api/projects/proj-1', { headers }), { params: Promise.resolve({ id: 'proj-1' }) })
}

beforeEach(() => {
  h.level = 'owner'
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('GET /api/projects/[id] read view', () => {
  test('the owner reads every column, as before', async () => {
    const res = await get()
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.cypherfixGithubToken).toBe(FAKE)
    expect(body.httpxCustomHeaders).toEqual([`X-Api-Key: ${FAKE}`])
    expect(body.roeClientContactEmail).toBe('client@e2e.local')
    // The document bytes never travel on this read, for anyone.
    expect(body).not.toHaveProperty('roeDocumentData')
  })

  test('a read collaborator receives none of the secrets', async () => {
    h.level = 'read'
    const res = await get()
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain(FAKE)
    expect(text).not.toContain('client@e2e.local')
    const body = JSON.parse(text)
    for (const key of ['cypherfixGithubToken', 'graphqlAuthValue', 'phishingSmtpConfig', 'roeClientContactEmail',
      'roeRawText', 'roeDocumentData', 'httpxCustomHeaders', 'kiterunnerHeaders']) {
      expect(body, key).not.toHaveProperty(key)
    }
    // The rest of the row, the owner's id and the header NAME stay.
    expect(body).toMatchObject({ id: 'proj-1', userId: 'owner-1', targetDomain: 'example.test', graphqlAuthHeader: 'X-Graphql-Auth' })
    expect(body.user).toEqual({ id: 'owner-1', name: 'Owner', email: 'owner@e2e.local' })
  })

  test('the agent (master key) reads the whole row, whoever it reads for', async () => {
    h.level = 'read'
    const res = await get({ 'x-internal-key': MASTER })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.cypherfixGithubToken).toBe(FAKE)
    expect(body.kiterunnerHeaders).toEqual([`Authorization-Token: ${FAKE}`])
  })
})
