/**
 * The account plans of onAccessReduced stop the account's Tradecraft ingestion jobs (D-10): a
 * disabled or deleted account can no longer act, so its own library's jobs end. A share's loss,
 * a capability removed or a sign-out leaves them: the library is the account's own.
 *
 * Prisma is the in-memory deletionDb; the agent a double.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({ db: null as unknown, agent: [] as string[], failFlag: false }))

vi.mock('@/lib/prisma', async () => {
  const { createDeletionDb } = await import('@/lib/authz/__testing__/deletionDb')
  h.db = createDeletionDb()
  return { default: h.db }
})
vi.mock('@/lib/agentFetch', async (orig) => {
  const actual = await orig<typeof import('@/lib/agentFetch')>()
  return {
    ...actual,
    agentFetch: async (path: string) => {
      h.agent.push(path)
      const body = path.endsWith('/cancel') ? { cancelled: 1 } : path === '/ws/close' ? { closed: 0 } : { stopped: 0 }
      return new Response(JSON.stringify(body), { status: 200 })
    },
  }
})

import type { DeletionDb } from './__testing__/deletionDb'
import { setFlagsForTests } from './flags'
import { PLANS, onAccessReduced, type AccessReducedReason } from './revocation'

const db = () => h.db as DeletionDb
const flagged = () => db().rows('tradecraftIngestionJob').filter(j => j.cancelRequested === true).map(j => j.id).sort()

beforeEach(() => {
  h.agent = []
  db().seed({
    user: [{ id: 'bob', name: 'Bob', email: 'bob@e2e.local', role: 'standard', status: 'active' }],
    project: [], projectCollaborator: [], jobQueue: [], scanSchedule: [], triageRun: [], auditLog: [],
    tradecraftIngestionJob: [
      { id: 'j1', userId: 'bob', kind: 'refresh', status: 'running', cancelRequested: false },
      { id: 'j2', userId: 'bob', kind: 'add', status: 'queued', cancelRequested: false },
      { id: 'j3', userId: 'bob', kind: 'add', status: 'succeeded', cancelRequested: false },
      { id: 'j4', userId: 'carla', kind: 'add', status: 'running', cancelRequested: false },
    ],
  })
  setFlagsForTests({ identity: true, permissions: true, sharing: true })
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('onAccessReduced and the Tradecraft jobs', () => {
  test("disable_cancels_jobs: the account's unfinished jobs are flagged and the agent told", async () => {
    const out = await onAccessReduced(null, 'bob', 'account_disabled')
    expect(out.tradecraft).toEqual({ cancelled: 2 })
    expect(flagged()).toEqual(['j1', 'j2'])
    expect(h.agent).toContain('/tradecraft/v2/users/bob/cancel')
    expect(out.failed).toEqual([])
  })

  test('a deleted account: the same step', async () => {
    const out = await onAccessReduced(null, 'bob', 'account_deleted')
    expect(out.tradecraft).toEqual({ cancelled: 2 })
    expect(flagged()).toEqual(['j1', 'j2'])
  })

  test.each([
    ['share_revoked', 'p1'], ['share_reduced', 'p1'], ['consent_withdrawn', 'p1'],
  ] as const)('a project reduction (%s) leaves the account\'s own jobs', async (reason, projectId) => {
    const out = await onAccessReduced(projectId, 'bob', reason)
    expect(out.tradecraft).toBeUndefined()
    expect(flagged()).toEqual([])
    expect(h.agent.filter(p => p.startsWith('/tradecraft/'))).toEqual([])
  })

  test.each(['capability_removed', 'sessions_revoked', 'credentials_reset', 'device_session_revoked'] as const)(
    'an account reduction that keeps the account able to act (%s) leaves its jobs', async (reason) => {
      const out = await onAccessReduced(null, 'bob', reason)
      expect(out.tradecraft).toBeUndefined()
      expect(flagged()).toEqual([])
    },
  )

  test('the plans that stop the jobs are exactly the disabled and the deleted account', () => {
    const stopping = (Object.keys(PLANS) as AccessReducedReason[]).filter(r => PLANS[r].tradecraftJobs).sort()
    expect(stopping).toEqual(['account_deleted', 'account_disabled'])
  })

  test('a flag that cannot be written is reported as a failed step, never raised', async () => {
    const jobs = db().tradecraftIngestionJob as { updateMany: (...a: unknown[]) => Promise<unknown> }
    const real = jobs.updateMany
    jobs.updateMany = async () => { throw Object.assign(new Error('db down'), { code: 'P1001' }) }
    try {
      const out = await onAccessReduced(null, 'bob', 'account_disabled')
      expect(out.tradecraft).toEqual({ error: 'P1001' })
      expect(out.failed).toContain('cancel_tradecraft_jobs')
      expect(h.agent).not.toContain('/tradecraft/v2/users/bob/cancel')
    } finally {
      jobs.updateMany = real
    }
  })
})
