/**
 * GET /api/projects/[id] delivers approved skill-text overrides to the agent (TD-16).
 *
 * Only the agent's own settings fetch gets them: the master key AND the separate
 * includeSkillOverrides flag. The scanner key, a browser session, and master-key callers
 * that ask only for includeSkillContent (the text-to-cypher path) get the response they
 * got before, and a failure to compute the overrides never changes the rest of the payload.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'm'.repeat(40)
const SCANNER = 's'.repeat(40)

const mockProjectFindUnique = vi.fn()
const mockResolveForProject = vi.fn()
const mockGetEffectiveUser = vi.fn()
const SKILLS = [{ id: 'us-1', name: 'Mine', description: '', content: 'c', lineageRootId: null, version: null }]
let userToggles: Record<string, boolean> = { 'us-1': true }

vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => mockProjectFindUnique(...a) },
    userAttackSkill: {
      findMany: async (a: { where?: { id?: { in?: string[] } } }) =>
        SKILLS.filter((s) => !a?.where?.id?.in || a.where.id.in.includes(s.id)),
    },
    userSettings: { findUnique: async () => ({ mcpServers: [] }) },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: vi.fn(), close: vi.fn() }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/plugins/overrides', () => ({
  resolveForProject: (...a: unknown[]) => mockResolveForProject(...a),
}))
vi.mock('@/lib/access', async () => {
  const actual = await vi.importActual<typeof import('@/lib/access')>('@/lib/access')
  return { ...actual, requireEffectiveUser: () => mockGetEffectiveUser() }
})

import { GET } from './route'
import { computeSkillTextOverrides } from '@/lib/plugins/overrideDelivery'
import { mintJobCredential } from '@/lib/authz/machineCredential'

const OVERRIDES = {
  'path_traversal/payload_reference': {
    value: 'text', baseSha256: 'a'.repeat(64), overrideId: 'ov-1', changeSetId: 'cs-1',
    revision: 2, pluginId: 'fixture-plugin',
  },
}

const BOTH = '?includeSkillContent=true&includeSkillOverrides=true'

function wireProject() {
  mockProjectFindUnique.mockImplementation((args: { select?: unknown }) =>
    args?.select
      ? Promise.resolve({ id: 'proj-1', userId: 'owner-1' })
      : Promise.resolve({
          id: 'proj-1', userId: 'owner-1', name: 'P', targetDomain: 'example.com',
          attackSkillConfig: { builtIn: {}, user: userToggles }, user: { id: 'owner-1' },
          authProfile: null, nodeFilter: null, nodeFilterExemptions: [],
        }),
  )
}

function get(query: string, key?: string): NextRequest {
  // Step 1.16: the scanner key reads only beside its scan's job credential.
  const job: Record<string, string> = key === SCANNER
    ? { 'x-redamon-job': mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' }) }
    : {}
  return new NextRequest(`http://x/api/projects/proj-1${query}`,
    key === undefined ? {} : { headers: { 'x-internal-key': key, ...job } })
}
const params = { params: Promise.resolve({ id: 'proj-1' }) }

async function body(query: string, key?: string) {
  const res = await GET(get(query, key), params)
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubEnv('INTERNAL_API_KEY', MASTER)
  vi.stubEnv('SCANNER_API_KEY', SCANNER)
  // Enforcement on (its default); unstubAllEnvs puts the caller's value back.
  vi.stubEnv('ACCESS_ENFORCE', undefined)
  userToggles = { 'us-1': true }
  wireProject()
  mockResolveForProject.mockResolvedValue(OVERRIDES)
  mockGetEffectiveUser.mockResolvedValue({ userId: 'owner-1' })
})

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('GET /api/projects/[id] skillTextOverrides', () => {
  test('master key, both flags, an active override: delivered', async () => {
    const json = await body(BOTH, MASTER)
    expect(json.skillTextOverrides).toEqual(OVERRIDES)
    expect(json.userAttackSkills).toHaveLength(1)
  })

  test('a user skill is sent only when the project sets it to true: a missing toggle is off', async () => {
    expect((await body(BOTH, MASTER)).userAttackSkills).toEqual([{ id: 'us-1', name: 'Mine', description: '', content: 'c', supersedes: [] }])
    userToggles = {}
    expect((await body(BOTH, MASTER)).userAttackSkills).toEqual([])
    userToggles = { 'us-1': false }
    expect((await body(BOTH, MASTER)).userAttackSkills).toEqual([])
  })

  test('the override flag alone is enough on the master key (the plain return path)', async () => {
    const json = await body('?includeSkillOverrides=true', MASTER)
    expect(json.skillTextOverrides).toEqual(OVERRIDES)
    expect(json.userAttackSkills).toBeUndefined()
  })

  test('master key with includeSkillContent only (text-to-cypher): absent, nothing computed', async () => {
    const json = await body('?includeSkillContent=true', MASTER)
    expect(json).not.toHaveProperty('skillTextOverrides')
    expect(mockResolveForProject).not.toHaveBeenCalled()
  })

  test('scanner key with both flags: absent, nothing computed', async () => {
    const json = await body(BOTH, SCANNER)
    expect(json).not.toHaveProperty('skillTextOverrides')
    expect(mockResolveForProject).not.toHaveBeenCalled()
  })

  test("the owner's browser session with both flags: absent, nothing computed", async () => {
    const json = await body(BOTH)
    expect(json).not.toHaveProperty('skillTextOverrides')
    expect(mockResolveForProject).not.toHaveBeenCalled()
    expect(mockGetEffectiveUser).toHaveBeenCalled()
  })

  test('no override applies: the field is left out', async () => {
    mockResolveForProject.mockResolvedValue({})
    const json = await body(BOTH, MASTER)
    expect(json).not.toHaveProperty('skillTextOverrides')
  })

  test('resolution throws: the response is exactly the one without the field', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      mockResolveForProject.mockRejectedValue(new Error('db down'))
      const failed = await body(BOTH, MASTER)
      mockResolveForProject.mockResolvedValue({})
      const without = await body(BOTH, MASTER)
      expect(failed).toEqual(without)
      expect(failed).not.toHaveProperty('skillTextOverrides')
      expect(warn).toHaveBeenCalledWith('[plugins] skill overrides omitted:', expect.any(Error))
    } finally {
      warn.mockRestore()
    }
  })

  test('only the project id reaches the resolver (the owner is read from the project row there)', async () => {
    await body(`${BOTH}&userId=someone-else&scopeId=someone-else`, MASTER)
    expect(mockResolveForProject).toHaveBeenCalledTimes(1)
    expect(mockResolveForProject.mock.calls[0]).toEqual(['proj-1'])
  })
})

describe('computeSkillTextOverrides', () => {
  test('what the store resolves for the project', async () => {
    await expect(computeSkillTextOverrides('proj-1')).resolves.toEqual(OVERRIDES)
    expect(mockResolveForProject).toHaveBeenCalledWith('proj-1')
  })
})
