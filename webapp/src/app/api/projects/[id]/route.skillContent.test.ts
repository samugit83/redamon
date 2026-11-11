/**
 * GET /api/projects/[id]?includeSkillContent=true adds the owner's raw MCP servers and
 * skill texts for the master key only (NF-15, step 1.9).
 *
 * It answered any caller who passed the project check, the owner's browser and an admin
 * acting as the owner included, with `userMcpServers` holding the literal bearer tokens,
 * header and env values. Only the agent's settings fetch (the master key) needs them;
 * every other caller gets the project without. A non-admin owner's stdio servers never
 * reach the agent (NF-14): they are left out of the payload and logged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'm'.repeat(40)
const SCANNER = 's'.repeat(40)
const BEARER = 'owner-raw-bearer-SECRET-0001'

const mockProjectFindUnique = vi.fn()
const mockGetEffectiveUser = vi.fn()
const ownerRole = vi.hoisted(() => ({ role: 'standard' }))
const SERVERS = [
  { id: 'web', name: 'Web', transport: 'streamable_http', url: 'https://mcp.example.com/mcp', auth: { type: 'bearer', token: BEARER } },
  { id: 'cmd', name: 'Cmd', transport: 'stdio', command: 'npx', env: { K: 'v' } },
]
const SKILLS = [{ id: 'us-1', name: 'Mine', description: '', content: 'skill text', lineageRootId: null, version: null }]

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) },
    userAttackSkill: { findMany: async () => SKILLS },
    userSettings: { findUnique: async () => ({ mcpServers: SERVERS }) },
  },
}))
vi.mock('@/lib/authz/principal', () => ({
  loadPrincipal: vi.fn(async (id: string) => ({ id, role: ownerRole.role })),
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { GET } from './route'

function get(key?: string): NextRequest {
  return new NextRequest('http://x/api/projects/proj-1?includeSkillContent=true',
    key === undefined ? {} : { headers: { 'x-internal-key': key } })
}
const params = { params: Promise.resolve({ id: 'proj-1' }) }

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubEnv('INTERNAL_API_KEY', MASTER)
  vi.stubEnv('SCANNER_API_KEY', SCANNER)
  vi.stubEnv('ACCESS_ENFORCE', undefined)
  ownerRole.role = 'standard'
  mockProjectFindUnique.mockImplementation((args: { select?: unknown }) =>
    args?.select
      ? Promise.resolve({ id: 'proj-1', userId: 'owner-1' })
      : Promise.resolve({
          id: 'proj-1', userId: 'owner-1', name: 'P', targetDomain: 'example.com',
          attackSkillConfig: { builtIn: {}, user: { 'us-1': true } }, user: { id: 'owner-1' },
          authProfile: null, nodeFilter: null, nodeFilterExemptions: [],
        }),
  )
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner-1' })
})
afterEach(() => { vi.unstubAllEnvs() })

describe('includeSkillContent only for the master key', () => {
  test("the owner's browser gets the project without servers or skill texts", async () => {
    const res = await GET(get(), params)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain(BEARER)
    const body = JSON.parse(text)
    expect(body.id).toBe('proj-1')
    expect(body).not.toHaveProperty('userMcpServers')
    expect(body).not.toHaveProperty('userAttackSkills')
  })

  test('the scanner key gets them neither', async () => {
    // Step 1.16: as a scan calls it, with its job credential, so the read succeeds.
    const { mintJobCredential } = await import('@/lib/authz/machineCredential')
    const req = new NextRequest('http://x/api/projects/proj-1?includeSkillContent=true', {
      headers: { 'x-internal-key': SCANNER, 'x-redamon-job': mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' }) },
    })
    const res = await GET(req, params)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).not.toHaveProperty('userMcpServers')
    expect(body).not.toHaveProperty('userAttackSkills')
  })

  test("the agent's settings fetch (master key) gets both, the raw bearer included", async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const body = await (await GET(get(MASTER), params)).json()
    expect(body.userAttackSkills.map((s: { id: string }) => s.id)).toEqual(['us-1'])
    expect(body.userMcpServers[0].auth.token).toBe(BEARER)
  })
})

describe("a non-admin owner's stdio servers never reach the agent", () => {
  test('left out of the payload and logged', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const body = await (await GET(get(MASTER), params)).json()
    expect(body.userMcpServers.map((s: { id: string }) => s.id)).toEqual(['web'])
    expect(warn).toHaveBeenCalledWith('[rbac] stdio mcp server skipped user=owner-1 server=cmd')
  })

  test("an administrator's are sent", async () => {
    ownerRole.role = 'admin'
    const body = await (await GET(get(MASTER), params)).json()
    expect(body.userMcpServers.map((s: { id: string }) => s.id)).toEqual(['web', 'cmd'])
  })
})
