/**
 * GET /api/projects/[id] returns `myAccess` to a browser caller (step 4.3, PE-21 per project): the
 * caller's level, toggles, how the access was reached and the owner's name and email (the `user`
 * the row already carries, which stays). The owner reads `owner`, every toggle, through `owner`,
 * beside the row as before; a service caller (master or scanner key) reads no `myAccess`.
 *
 * The guard is doubled to hand the access under test, in the shape projectAccess() builds.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'internal-key-for-tests-0000000000000'
vi.stubEnv('INTERNAL_API_KEY', MASTER)

const FAKE = 'rbac-fake-share-secret-0001'
const h = vi.hoisted(() => ({ access: null as null | Record<string, unknown> }))

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
      access: { project: { id: opts.projectId, userId: 'owner-1' }, ...h.access },
    }),
  }
})

import { GET } from './route'

function get(headers: Record<string, string> = {}) {
  return GET(new NextRequest('http://localhost/api/projects/proj-1', { headers }), { params: Promise.resolve({ id: 'proj-1' }) })
}

const OWNER = { name: 'Owner', email: 'owner@e2e.local' }

beforeEach(() => {
  h.access = { level: 'owner', toggles: { rawData: true }, via: 'owner' }
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('GET /api/projects/[id] myAccess', () => {
  test('the owner: myAccess says owner, beside the whole row and its user as before', async () => {
    const body = await (await get()).json()
    expect(body.myAccess).toEqual({ level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER })
    expect(body.user).toEqual({ id: 'owner-1', name: 'Owner', email: 'owner@e2e.local' })
    expect(body.cypherfixGithubToken).toBe(FAKE)
  })

  test.each([
    ['a read share', 'share', false],
    ['a share with Raw data', 'share', true],
    ['oversight', 'oversight', false],
    ['break-glass', 'break_glass', true],
  ])('%s: myAccess names it and the owner who shared it, and the secrets stay out', async (_what, via, rawData) => {
    h.access = { level: 'read', toggles: { rawData }, via }
    const text = await (await get()).text()
    expect(text).not.toContain(FAKE)
    expect(JSON.parse(text).myAccess).toEqual({ level: 'read', toggles: { rawData }, via, owner: OWNER })
  })

  test('a service caller (master key) reads no myAccess', async () => {
    const body = await (await get({ 'x-internal-key': MASTER })).json()
    expect(body).not.toHaveProperty('myAccess')
    expect(body.cypherfixGithubToken).toBe(FAKE)
  })
})
