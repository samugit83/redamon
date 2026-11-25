/**
 * The drawer's job list and cancel name the viewer to the agent (gap audit G-10): a job another
 * person started runs in that person's own Kali sandbox, and the agent leaves it out of the list
 * and answers its cancel as an unknown job only when it knows who asks. Under act-as the viewer is
 * the member, as the agent records a job's owner.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest } from 'next/server'

const calls: string[] = []

vi.mock('@/lib/authz/guards', () => ({
  requirePermission: vi.fn(async () => ({ effective: { userId: 'member-1' } })),
}))
vi.mock('../../agentProxy', () => ({
  callAgent: vi.fn(async (path: string) => {
    calls.push(path)
    return { ok: true, res: new Response(JSON.stringify({ jobs: [] }), { status: 200 }) }
  }),
  agentErrorResponse: vi.fn(),
}))

import { GET as listJobs } from './route'
import { POST as cancelJob } from './[jobId]/cancel/route'

describe('drawer job routes name the viewer', () => {
  beforeEach(() => { calls.length = 0 })

  test('the list asks the agent for the viewer\'s view of the project\'s jobs', async () => {
    const res = await listJobs(new NextRequest('http://localhost/api/agent/workspace/jobs?projectId=p1&active=true'))
    expect(res.status).toBe(200)
    expect(calls).toEqual(['/workspace/jobs?projectId=p1&userId=member-1&active=true'])
  })

  test('a cancel names the viewer, so another person\'s job is unknown to it', async () => {
    const res = await cancelJob(
      new NextRequest('http://localhost/api/agent/workspace/jobs/j1/cancel?projectId=p1', { method: 'POST' }),
      { params: Promise.resolve({ jobId: 'j1' }) },
    )
    expect(res.status).toBe(200)
    expect(calls).toEqual(['/workspace/jobs/j1/cancel?projectId=p1&userId=member-1'])
  })
})
