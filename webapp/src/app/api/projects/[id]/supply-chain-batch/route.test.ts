/**
 * Scan Queue Phase 6 - supply-chain org batch creation. guardProject first;
 * token from settings never body; enumerate; then batch + items + one
 * supply_chain_repo JobQueue row (priority -10) per repo in one transaction.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  guardProject: vi.fn(),
  effectiveUser: vi.fn(),
  projectFindUnique: vi.fn(),
  userSettingsFindUnique: vi.fn(),
  batchCreate: vi.fn(),
  jobCreate: vi.fn(),
  itemCreate: vi.fn(),
  listOwnerRepos: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guardProject(...a) }))
vi.mock('@/lib/session', () => ({ getEffectiveUser: () => h.effectiveUser() }))
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

const PROJECT = {
  id: 'p1', userId: 'u1', supplyChainOrgName: 'acme', supplyChainOrgIncludeForks: false,
  supplyChainOrgIncludeArchived: false, supplyChainOrgMaxRepos: 50, supplyChainOrgRef: '',
  supplyChainOrgDeepAnalysisEnabled: true, supplyChainRepoScope: '',
  supplyChainInputMode: 'github', supplyChainSbomFile: '', supplyChainRepoUrl: '', supplyChainRepoRef: '',
  supplyChainDeepAnalysisEnabled: false,
}
const REPOS = [
  { fullName: 'acme/a', owner: 'acme', repo: 'a', url: 'https://github.com/acme/a.git', defaultBranch: 'main', fork: false, archived: false },
  { fullName: 'acme/b', owner: 'acme', repo: 'b', url: 'https://github.com/acme/b.git', defaultBranch: 'dev', fork: false, archived: false },
]

const post = (body: unknown = {}) => new NextRequest('http://x', { method: 'POST', body: JSON.stringify(body) })
const sp = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  h.guardProject.mockResolvedValue(null)
  h.effectiveUser.mockResolvedValue({ userId: 'u1' })
  h.projectFindUnique.mockResolvedValue(PROJECT)
  h.userSettingsFindUnique.mockResolvedValue({ supplyChainGithubToken: 'ghp_x' })
  h.listOwnerRepos.mockResolvedValue(REPOS)
  let n = 0
  h.batchCreate.mockResolvedValue({ id: 'batch1' })
  h.jobCreate.mockImplementation(async () => ({ id: `job${++n}` }))
  h.itemCreate.mockResolvedValue({})
})

test('non-ownership yields the guard response, no work', async () => {
  h.guardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(404)
  expect(h.listOwnerRepos).not.toHaveBeenCalled()
})

test('creates a batch + one supply_chain_repo job per repo (priority -10)', async () => {
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(201)
  const body = await res.json()
  expect(body).toMatchObject({ ok: true, batchId: 'batch1', totalItems: 2 })
  expect(h.jobCreate).toHaveBeenCalledTimes(2)
  expect(h.itemCreate).toHaveBeenCalledTimes(2)
  const jobData = h.jobCreate.mock.calls[0][0].data
  expect(jobData).toMatchObject({ kind: 'supply_chain_repo', priority: -10, batchId: 'batch1', status: 'queued' })
  expect(jobData.payload).toMatchObject({ repo_full_name: 'acme/a', repo_url: 'https://github.com/acme/a.git', ref: 'main', deep_analysis: true })
})

test('the token comes from settings, never the request body', async () => {
  await POST(post({ token: 'ghp_EVIL' }), sp('p1'))
  const opts = h.listOwnerRepos.mock.calls[0][1]
  expect(opts.token).toBe('ghp_x')
})

test('an invalid org is a 400 before enumeration', async () => {
  h.projectFindUnique.mockResolvedValue({ ...PROJECT, supplyChainOrgName: '' })
  const res = await POST(post({ org: 'bad org' }), sp('p1'))
  expect(res.status).toBe(400)
  expect(h.listOwnerRepos).not.toHaveBeenCalled()
})

test('a 403 from GitHub surfaces as an error, no batch created', async () => {
  const { GithubEnumError } = await import('@/lib/github/orgRepos')
  h.listOwnerRepos.mockRejectedValue(new GithubEnumError('rate limit', 403))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(403)
  expect(h.batchCreate).not.toHaveBeenCalled()
})

test('zero repos is a 400, no batch', async () => {
  h.listOwnerRepos.mockResolvedValue([])
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(400)
  expect(h.batchCreate).not.toHaveBeenCalled()
})

// --- GitHub Enterprise ------------------------------------------------------
// The host is operator input that becomes a server-side fetch and `git clone`
// argv, so it is accepted ONLY when it matches the configured GHE host, and the
// credential is chosen by host so the two tokens can never cross.

test('a GHE target enumerates that host with the GHE token, and stamps it on the rows', async () => {
  h.userSettingsFindUnique.mockResolvedValue({
    supplyChainGithubToken: 'ghp_dotcom',
    githubEnterpriseHost: 'ghe.example.com',
    githubEnterpriseToken: 'ghp_ghe',
  })
  h.listOwnerRepos.mockResolvedValue([
    { fullName: 'acme/a', owner: 'acme', repo: 'a', url: 'https://ghe.example.com/acme/a.git', defaultBranch: 'main', fork: false, archived: false },
  ])
  const res = await POST(post({ org: 'https://ghe.example.com/orgs/acme' }), sp('p1'))
  expect(res.status).toBe(201)
  expect(await res.json()).toMatchObject({ org: 'acme', host: 'ghe.example.com' })

  const [owner, opts] = h.listOwnerRepos.mock.calls[0]
  expect(owner).toBe('acme')
  expect(opts.host).toBe('ghe.example.com')
  expect(opts.token).toBe('ghp_ghe')          // the GHE credential...
  expect(opts.token).not.toBe('ghp_dotcom')   // ...never the github.com one

  expect(h.batchCreate.mock.calls[0][0].data).toMatchObject({ org: 'acme', host: 'ghe.example.com' })
  expect(h.jobCreate.mock.calls[0][0].data.payload).toMatchObject({ host: 'ghe.example.com' })
})

test('an unconfigured host is refused before any fetch, and says why', async () => {
  h.userSettingsFindUnique.mockResolvedValue({
    supplyChainGithubToken: 'ghp_dotcom', githubEnterpriseHost: '', githubEnterpriseToken: '',
  })
  const res = await POST(post({ org: 'https://ghe.evil.example/orgs/acme' }), sp('p1'))
  expect(res.status).toBe(400)
  expect((await res.json()).error).toMatch(/not a configured GitHub host/)
  expect(h.listOwnerRepos).not.toHaveBeenCalled()
  expect(h.batchCreate).not.toHaveBeenCalled()
})

test('a github.com target still uses the github.com token even when a GHE host is configured', async () => {
  h.userSettingsFindUnique.mockResolvedValue({
    supplyChainGithubToken: 'ghp_dotcom',
    githubEnterpriseHost: 'ghe.example.com',
    githubEnterpriseToken: 'ghp_ghe',
    // Secret Hunt's token is a different credential and must not be reached for.
    githubAccessToken: 'ghp_secret_hunt',
  })
  await POST(post({ org: 'acme' }), sp('p1'))
  const opts = h.listOwnerRepos.mock.calls[0][1]
  expect(opts.host).toBe('github.com')
  expect(opts.token).toBe('ghp_dotcom')
  expect(opts.token).not.toBe('ghp_secret_hunt')
})

test('a bare name keeps defaulting to github.com and stamps host on the batch', async () => {
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(201)
  expect(h.listOwnerRepos.mock.calls[0][1].host).toBe('github.com')
  expect(h.batchCreate.mock.calls[0][0].data).toMatchObject({ host: 'github.com' })
  expect(h.jobCreate.mock.calls[0][0].data.payload).toMatchObject({ host: 'github.com' })
})

test('a GitHub refusal keeps its own text and gains a code', async () => {
  const { GithubEnumError } = await import('@/lib/github/orgRepos')
  h.listOwnerRepos.mockRejectedValue(new GithubEnumError('GitHub returned 404: Not Found', 404))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(404)
  expect(await res.json()).toEqual({ error: 'GitHub returned 404: Not Found', code: 'github_enum_failed' })
})

test('an unexpected enumeration throw is a 502 with its class, not its text', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.listOwnerRepos.mockRejectedValue(new TypeError('Cannot read properties of undefined (reading acme-internal)'))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(502)
  const body = await res.json()
  expect(body).toEqual({ error: 'GitHub enumeration failed', code: 'TypeError' })
  expect(JSON.stringify(body)).not.toContain('acme-internal')
})

test('a failed transaction answers the Prisma code, never the message', async () => {
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.batchCreate.mockRejectedValue(Object.assign(
    new Error('Transaction failed writing repo acme/secret-repo'),
    { name: 'PrismaClientKnownRequestError', code: 'P2028' },
  ))
  const res = await POST(post(), sp('p1'))
  expect(res.status).toBe(500)
  const body = await res.json()
  expect(body).toEqual({ error: 'Failed to create the org batch', code: 'P2028' })
  expect(JSON.stringify(body)).not.toContain('secret-repo')
})
