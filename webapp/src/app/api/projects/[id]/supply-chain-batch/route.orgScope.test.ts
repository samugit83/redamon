/**
 * POST /api/projects/[id]/supply-chain-batch on a shared project: the org a batch enumerates is the
 * project's scope (`supplyChainOrgName`, `share: scope`), so a body naming another org is a scope
 * change the caller's level must reach (classifyChange: only the owner widens scope, OQ-23), judged
 * before GitHub is asked anything. The stored org, however it is spelled, is the caller's to run.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({
  access: null as unknown,
  projectFindUnique: vi.fn(),
  userSettingsFindUnique: vi.fn(),
  batchCreate: vi.fn(),
  jobCreate: vi.fn(),
  itemCreate: vi.fn(),
  listOwnerRepos: vi.fn(),
}))

vi.mock('@/lib/authz/guards', async () => {
  const real = await vi.importActual<typeof import('@/lib/authz/guards')>('@/lib/authz/guards')
  return {
    ...real,
    requirePermission: async (_req: Request, permission: string) => ({
      session: { userId: 'collab', role: 'standard' },
      principal: { id: 'collab', role: 'standard' },
      actingAs: null,
      effective: { userId: 'collab' },
      permission,
      capabilities: { has: () => true },
      access: h.access,
    }),
  }
})
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'collab' }) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) },
    userSettings: { findUnique: (...a: unknown[]) => h.userSettingsFindUnique(...a) },
    $transaction: async (cb: (tx: unknown) => unknown) => cb({
      supplyChainBatch: { create: (...a: unknown[]) => h.batchCreate(...a) },
      jobQueue: { create: (...a: unknown[]) => h.jobCreate(...a) },
      supplyChainBatchItem: { create: (...a: unknown[]) => h.itemCreate(...a) },
    }),
  },
}))
vi.mock('@/lib/github/orgRepos', async orig => ({
  ...(await orig<typeof import('@/lib/github/orgRepos')>()),
  listOwnerRepos: (...a: unknown[]) => h.listOwnerRepos(...a),
}))

import { POST } from './route'

const P = { id: 'p1', userId: 'owner' }
const run = { runScans: true, useAgent: false, exploit: false }
const ACCESS = {
  owner: { project: P, level: 'owner', toggles: { rawData: true }, via: 'owner' },
  'co-owner': { project: P, level: 'write', toggles: { rawData: true, ...run, manage: true }, via: 'share' },
  editor: { project: P, level: 'write', toggles: { rawData: true, ...run, manage: false }, via: 'share' },
}
const PROJECT = {
  id: 'p1', userId: 'owner', supplyChainOrgName: 'acme', supplyChainOrgIncludeForks: false,
  supplyChainOrgIncludeArchived: false, supplyChainOrgMaxRepos: 50, supplyChainOrgRef: '',
  supplyChainOrgDeepAnalysisEnabled: false, supplyChainRepoScope: '',
  supplyChainInputMode: 'github', supplyChainSbomFile: '', supplyChainRepoUrl: '', supplyChainRepoRef: '',
  supplyChainDeepAnalysisEnabled: false,
}
const REPOS = [
  { fullName: 'acme/a', owner: 'acme', repo: 'a', url: 'https://github.com/acme/a.git', defaultBranch: 'main', fork: false, archived: false },
]

const post = (body: unknown = {}) => POST(
  new NextRequest('http://x', { method: 'POST', body: JSON.stringify(body) }),
  { params: Promise.resolve({ id: 'p1' }) },
)

beforeEach(() => {
  vi.clearAllMocks()
  h.access = ACCESS['co-owner']
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.userSettingsFindUnique.mockResolvedValue({ supplyChainGithubToken: 'rbac-fake-gh-token-0001' })
  h.listOwnerRepos.mockResolvedValue(REPOS)
  h.batchCreate.mockResolvedValue({ id: 'batch1' })
  h.jobCreate.mockResolvedValue({ id: 'job1' })
  h.itemCreate.mockResolvedValue({})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('the org a batch enumerates is the project\'s scope', () => {
  test('a co-owner naming another org is refused as a scope widening, before GitHub is asked', async () => {
    const res = await post({ org: 'other-org' })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({
      code: 'forbidden', permission: 'scan:supply_chain', level: 'O',
      refused: [expect.objectContaining({ key: 'supplyChainOrgName', needs: 'owner' })],
    })
    expect(h.listOwnerRepos).not.toHaveBeenCalled()
    expect(h.batchCreate).not.toHaveBeenCalled()
    expect(console.warn).toHaveBeenCalledWith(expect.stringMatching(/^\[rbac\] settings_refused .*keys=supplyChainOrgName/))
  })

  test('an editor is refused the same', async () => {
    h.access = ACCESS.editor
    expect((await post({ org: 'https://github.com/orgs/other-org' })).status).toBe(403)
    expect(h.listOwnerRepos).not.toHaveBeenCalled()
  })

  test('a project with no org stored: naming one is the owner\'s', async () => {
    h.projectFindUnique.mockResolvedValue({ ...PROJECT, supplyChainOrgName: '' })
    expect((await post({ org: 'acme' })).status).toBe(403)
    expect(h.listOwnerRepos).not.toHaveBeenCalled()
  })

  test('the stored org runs, however the body spells it', async () => {
    for (const body of [{}, { org: 'acme' }, { org: 'ACME' }, { org: 'https://github.com/orgs/acme' }]) {
      vi.clearAllMocks()
      const res = await post(body)
      expect(res.status, JSON.stringify(body)).toBe(201)
      expect(String(h.listOwnerRepos.mock.calls[0][0]).toLowerCase()).toBe('acme')
    }
  })

  test('the owner may still name any org', async () => {
    h.access = ACCESS.owner
    const res = await post({ org: 'other-org' })
    expect(res.status).toBe(201)
    expect(h.listOwnerRepos.mock.calls[0][0]).toBe('other-org')
  })

  test('no access decided: refused', async () => {
    h.access = null
    expect((await post({ org: 'other-org' })).status).toBe(403)
    expect(h.listOwnerRepos).not.toHaveBeenCalled()
  })
})
