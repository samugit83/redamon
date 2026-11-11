/**
 * HD-20 (step 1.16): the scanner key alone no longer unmasks an account's secrets. A
 * scan reads its owner's settings with the scanner key AND the job credential minted
 * for its start, which must name this account; the master key is unchanged.
 *
 * The real session and credential helpers run; Prisma is a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const MASTER = 'internal-key-for-tests-0000000000000'
const SCANNER = 'scanner-key-for-tests-00000000000000'
vi.stubEnv('AUTH_SECRET', 'm'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', MASTER)
vi.stubEnv('SCANNER_API_KEY', SCANNER)

const SHODAN = 'shodan-SECRET-0000000000000001'
const h = vi.hoisted(() => ({
  settingsReads: 0,
  // The live projects and their owners; a deleted one is simply absent.
  projects: new Map<string, string>(),
}))

vi.mock('next/headers', () => ({ cookies: vi.fn(async () => ({ get: () => undefined })) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findUnique: async () => {
        h.settingsReads += 1
        return { userId: 'owner-1', shodanApiKey: SHODAN, mcpServers: [] }
      },
    },
    apiKeyRotationConfig: { findMany: async () => [] },
    project: {
      findUnique: async ({ where }: { where: { id: string } }) =>
        h.projects.has(where.id) ? { userId: h.projects.get(where.id) } : null,
    },
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => {}) }))

import {
  JOB_CREDENTIAL_LABEL, RUN_CREDENTIAL_LABEL, deriveKey, mintJobCredential, mintMachineCredential,
} from '@/lib/authz/machineCredential'
import { GET } from './route'

const params = { params: Promise.resolve({ id: 'owner-1' }) }

function get(headers: Record<string, string>) {
  return GET(new NextRequest('http://x/api/users/owner-1/settings?internal=true', { headers }), params)
}

beforeEach(() => {
  h.settingsReads = 0
  h.projects = new Map([['proj-1', 'owner-1']])
  vi.restoreAllMocks()
})

describe('the scanner key reads an account\'s settings only with a job credential for it', () => {
  test('scanner key without credential masked or 403: 403, logged, nothing read', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const res = await get({ 'x-internal-key': SCANNER })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'job_credential_required', reason: 'missing' })
    expect(h.settingsReads).toBe(0)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] job credential refused reason=missing'))
  })

  test('credential for another user 403', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const token = mintJobCredential({ tenant: 'someone-else', projectId: 'proj-1' })
    const res = await get({ 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ code: 'job_credential_required', reason: 'tenant_mismatch' })
    expect(h.settingsReads).toBe(0)
  })

  test('a forged, expired or run-shaped credential is refused', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    const good = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const expired = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1', ttlSeconds: -1 })
    const exp = Math.floor(Date.now() / 1000) + 3600
    const sandboxRun = { ten: 'owner-1', pid: 'proj-1', run: 'run-1', exp }
    for (const [token, reason] of [
      [`${good.split('.')[0]}.${'A'.repeat(43)}`, 'bad_signature'],
      [expired, 'expired'],
      ['not-a-token', 'malformed'],
      // A run credential the agent hands the sandbox, presented as a job credential.
      [mintMachineCredential({ aud: 'graph', ...sandboxRun }, deriveKey(MASTER, RUN_CREDENTIAL_LABEL)), 'bad_signature'],
      // Run-shaped claims under the job key: the right audience, a run instead of a job.
      [mintMachineCredential({ aud: 'scan', ...sandboxRun }, deriveKey(MASTER, JOB_CREDENTIAL_LABEL)), 'missing_claims'],
      [mintMachineCredential({ aud: 'traffic', ...sandboxRun }, deriveKey(MASTER, JOB_CREDENTIAL_LABEL)), 'wrong_audience'],
    ]) {
      const res = await get({ 'x-internal-key': SCANNER, 'x-redamon-job': token })
      expect(res.status).toBe(403)
      expect((await res.json()).reason).toBe(reason)
    }
    expect(h.settingsReads).toBe(0)
  })

  test('matching credential unmasked', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await get({ 'x-internal-key': SCANNER, 'x-redamon-job': token })
    expect(res.status).toBe(200)
    expect((await res.json()).shodanApiKey).toBe(SHODAN)
  })

  test('a credential whose project was deleted, or now belongs to someone else, reads nothing', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    for (const live of [new Map<string, string>(), new Map([['proj-1', 'new-owner']])]) {
      h.projects = live
      const res = await get({ 'x-internal-key': SCANNER, 'x-redamon-job': token })
      expect(res.status).toBe(403)
      expect(await res.json()).toMatchObject({ code: 'job_credential_required', reason: 'project_gone' })
    }
    expect(h.settingsReads).toBe(0)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('[rbac] job credential refused reason=project_gone'))
  })

  test('a job credential without the scanner key opens nothing', async () => {
    const token = mintJobCredential({ tenant: 'owner-1', projectId: 'proj-1' })
    const res = await get({ 'x-redamon-job': token })
    expect(res.status).toBe(401)
    expect(h.settingsReads).toBe(0)
  })

  test('the master key reads unmasked without a credential, as before', async () => {
    const res = await get({ 'x-internal-key': MASTER })
    expect(res.status).toBe(200)
    expect((await res.json()).shodanApiKey).toBe(SHODAN)
  })
})
