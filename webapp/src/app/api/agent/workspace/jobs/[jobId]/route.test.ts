/**
 * GET /api/agent/workspace/jobs/[jobId]: one workspace job's status and progress.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuardProject = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuardProject(...a) }))

import { GET } from './route'

const JOB = 'a'.repeat(32)
const params = (jobId: string) => ({ params: Promise.resolve({ jobId }) })
let fetchCalls: string[]
let agentAnswer: Response

beforeEach(() => {
  fetchCalls = []
  mockGuardProject.mockReset()
  mockGuardProject.mockResolvedValue(null)
  agentAnswer = new Response(JSON.stringify({ job_id: JOB, status: 'running', progress: { phase: 'extracting' } }),
    { status: 200, headers: { 'Content-Type': 'application/json' } })
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    fetchCalls.push(String(url))
    return agentAnswer
  }))
})

describe('GET /api/agent/workspace/jobs/[jobId]', () => {
  test('passes the status and progress through', async () => {
    const res = await GET(new NextRequest(`http://x/api/agent/workspace/jobs/${JOB}?projectId=p1`), params(JOB))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ job_id: JOB, status: 'running', progress: { phase: 'extracting' } })
    expect(fetchCalls).toEqual([expect.stringContaining(`/workspace/jobs/${JOB}?projectId=p1`)])
  })

  test('denied project never reaches the agent', async () => {
    mockGuardProject.mockResolvedValue(NextResponse.json({ error: 'Not found' }, { status: 404 }))
    const res = await GET(new NextRequest(`http://x/x?projectId=victim`), params(JOB))
    expect(res.status).toBe(404)
    expect(fetchCalls).toHaveLength(0)
  })

  test('bad job id is 404 without calling the agent', async () => {
    for (const bad of ['x', '../etc', 'A'.repeat(32), `${JOB}/../cancel`]) {
      const res = await GET(new NextRequest(`http://x/x?projectId=p1`), params(bad))
      expect(res.status).toBe(404)
    }
    expect(fetchCalls).toHaveLength(0)
  })

  test('agent 404 passes through', async () => {
    agentAnswer = new Response(JSON.stringify({ error: 'Not found.', code: 'not_found' }),
      { status: 404, headers: { 'Content-Type': 'application/json' } })
    const res = await GET(new NextRequest(`http://x/x?projectId=p1`), params(JOB))
    expect(res.status).toBe(404)
    expect((await res.json()).code).toBe('not_found')
  })
})
