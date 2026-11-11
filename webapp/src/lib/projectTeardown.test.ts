/**
 * The project teardown (HD-11): the steps of DELETE /api/projects/[id], in their
 * order, shared with DELETE /api/users/[id]. Every external boundary is a double
 * (Prisma, the orchestrator, the agent, Neo4j, the workspace purge, the body GC);
 * the authorization archive and the triage client are real.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  events: [] as string[],
  capturedFindMany: vi.fn(),
  jobsUpdateMany: vi.fn(),
  conversations: vi.fn(),
  authorizationCount: vi.fn(),
  archiveSql: [] as { sql: string; params: unknown[] }[],
  archiveFails: false,
  projectDelete: vi.fn(),
  orchestrator: vi.fn(),
  agent: vi.fn(),
  purge: vi.fn(),
  gc: vi.fn(),
  graphRun: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: {
    capturedHttpTransaction: { findMany: (...a: unknown[]) => h.capturedFindMany(...a) },
    jobQueue: { updateMany: (...a: unknown[]) => h.jobsUpdateMany(...a) },
    conversation: { findMany: (...a: unknown[]) => h.conversations(...a) },
    engagementAuthorization: { count: (...a: unknown[]) => h.authorizationCount(...a) },
    project: { delete: (...a: unknown[]) => h.projectDelete(...a) },
    $transaction: async (fn: (tx: unknown) => unknown) => fn({
      $executeRawUnsafe: async (sql: string, ...params: unknown[]) => {
        if (h.archiveFails && sql.includes('INSERT')) throw new Error('archive table missing')
        h.archiveSql.push({ sql, params })
        if (sql.includes('INSERT')) h.events.push(`archive ${params[0]}`)
        return 1
      },
    }),
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestrator(...a) }))
vi.mock('@/lib/agentFetch', async () => ({
  ...(await vi.importActual<typeof import('@/lib/agentFetch')>('@/lib/agentFetch')),
  agentFetch: (...a: unknown[]) => h.agent(...a),
}))
vi.mock('@/lib/workspacePurge', () => ({ purgeProjectWorkspace: (...a: unknown[]) => h.purge(...a) }))
vi.mock('@/lib/captureBodies', () => ({ gcOrphanBodies: (...a: unknown[]) => h.gc(...a) }))
vi.mock('@/app/api/graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => h.graphRun(...a), close: async () => undefined }),
}))

import { teardownProject, TEARDOWN_STEPS } from './projectTeardown'

const PROJECT = { id: 'p1', userId: 'owner-1' }
const ACTOR = { actorUserId: 'admin-9' }

const agentBodies = (path: string) => h.agent.mock.calls
  .filter(c => c[0] === path)
  .map(c => JSON.parse((c[1] as { body: string }).body))

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
  vi.spyOn(console, 'log').mockImplementation(() => undefined)
  h.events.length = 0
  h.archiveSql.length = 0
  h.archiveFails = false
  h.capturedFindMany.mockImplementation(async () => { h.events.push('collect bodies'); return [] })
  h.jobsUpdateMany.mockImplementation(async () => { h.events.push('cancel jobs'); return { count: 0 } })
  h.conversations.mockImplementation(async () => { h.events.push('read chats'); return [] })
  h.authorizationCount.mockResolvedValue(0)
  h.projectDelete.mockImplementation(async ({ where }: { where: { id: string } }) => {
    h.events.push(`delete ${where.id}`)
    return { id: where.id }
  })
  h.orchestrator.mockImplementation(async (url: string, init?: { method?: string }) => {
    const path = new URL(url).pathname
    if (path.endsWith('/files')) h.events.push('delete files')
    else if (path.endsWith('/partial/all')) h.events.push('list partials')
    else h.events.push(`stop ${path.split('/')[1]}`)
    return { ok: true, json: async () => ({ deleted: [], runs: [] }), method: init?.method }
  })
  h.agent.mockImplementation(async (path: string) => {
    h.events.push(`agent ${path}`)
    return { ok: true, status: 200, json: async () => ({ stopped: false }) }
  })
  h.purge.mockImplementation(async (pid: string) => { h.events.push(`purge ${pid}`) })
  h.gc.mockImplementation(async () => { h.events.push('gc bodies'); return { deleted: 0 } })
  h.graphRun.mockImplementation(async () => { h.events.push('clear graph'); return { records: [] } })
})

describe('the steps of the project delete, in its order', () => {
  test('every step runs once, in order, and reports ok', async () => {
    const result = await teardownProject(PROJECT, ACTOR)
    expect(result.ok).toBe(true)
    expect(result.steps.map(s => s.step)).toEqual([...TEARDOWN_STEPS])
    expect(result.steps.filter(s => s.outcome !== 'ok')).toEqual([{ step: 'gc_bodies', outcome: 'skipped' }])
    // Work stops first, the archive comes before the row, the workspace only once
    // the row is gone, then the files and the graph.
    const first = (e: string) => h.events.findIndex(x => x.startsWith(e))
    expect(first('collect bodies')).toBeLessThan(first('cancel jobs'))
    expect(first('cancel jobs')).toBeLessThan(first('agent /graph/triage'))
    expect(first('agent /graph/triage')).toBeLessThan(first('read chats'))
    expect(first('read chats')).toBeLessThan(first('stop recon'))
    expect(first('stop recon')).toBeLessThan(first('delete p1'))
    expect(first('delete p1')).toBeLessThan(first('purge p1'))
    expect(first('purge p1')).toBeLessThan(first('delete files'))
    expect(first('delete files')).toBeLessThan(first('clear graph'))
  })

  test('the scan stops are the project-level ones the route always made', async () => {
    await teardownProject(PROJECT, ACTOR)
    const urls = h.orchestrator.mock.calls.map(c => String(c[0]))
    for (const stop of ['/recon/p1/stop?graceful=false', '/gvm/p1/stop?ingest=false',
      '/github-hunt/p1/stop?ingest=false', '/supply-chain/p1/stop', '/trufflehog/p1/stop-all', '/recon/p1/partial/all']) {
      expect(urls.some(u => u.endsWith(stop))).toBe(true)
    }
    expect(urls.some(u => u.endsWith('/project/p1/files'))).toBe(true)
  })

  test('captured bodies are listed before the delete and collected after it', async () => {
    h.capturedFindMany.mockImplementation(async () => {
      h.events.push('collect bodies')
      return [{ reqBodyRef: 'a'.repeat(64), respBodyRef: null }]
    })
    const result = await teardownProject(PROJECT, ACTOR)
    expect(h.capturedFindMany).toHaveBeenCalledWith({
      where: { projectId: 'p1' }, select: { reqBodyRef: true, respBodyRef: true },
    })
    expect(h.gc).toHaveBeenCalledWith(['a'.repeat(64), null])
    expect(h.events.indexOf('gc bodies')).toBeGreaterThan(h.events.indexOf('delete p1'))
    expect(result.steps.find(s => s.step === 'gc_bodies')?.outcome).toBe('ok')
  })
})

describe('the tenant is the project owner', () => {
  test('the triage stop names the project owner, never the actor', async () => {
    await teardownProject(PROJECT, ACTOR)
    expect(agentBodies('/graph/triage')).toEqual([{ op: 'stop_run', user_id: 'owner-1', project_id: 'p1' }])
  })

  test('each chat stop names the conversation owner', async () => {
    h.conversations.mockResolvedValue([{ userId: 'owner-1', sessionId: 's1' }])
    await teardownProject(PROJECT, ACTOR)
    expect(agentBodies('/agent-session/stop')).toEqual([{ user_id: 'owner-1', project_id: 'p1', session_id: 's1' }])
  })
})

describe('best-effort steps report a failure and the teardown goes on', () => {
  test('every best-effort step failing still deletes the project', async () => {
    h.capturedFindMany.mockRejectedValue(new Error('db'))
    h.jobsUpdateMany.mockRejectedValue(new Error('db'))
    h.conversations.mockRejectedValue(new Error('db'))
    h.agent.mockRejectedValue(new Error('agent down'))
    h.orchestrator.mockRejectedValue(new Error('orchestrator down'))
    h.purge.mockRejectedValue(new Error('agent down'))
    h.graphRun.mockRejectedValue(new Error('neo4j down'))
    const result = await teardownProject(PROJECT, ACTOR)
    expect(result.ok).toBe(true)
    expect(h.projectDelete).toHaveBeenCalledOnce()
    const outcome = Object.fromEntries(result.steps.map(s => [s.step, s.outcome]))
    expect(outcome).toMatchObject({
      collect_body_refs: 'failed', cancel_jobs: 'failed', stop_triage: 'failed', stop_chats: 'failed',
      stop_scans: 'failed', archive_authorizations: 'ok', delete_project: 'ok', purge_workspace: 'failed',
      delete_files: 'failed', clear_graph: 'failed',
    })
  })

  test('an agent that answers an error marks the triage stop failed', async () => {
    h.agent.mockResolvedValue({ ok: false, status: 503, json: async () => ({ error: 'down', code: 'busy' }) })
    const result = await teardownProject(PROJECT, ACTOR)
    expect(result.steps.find(s => s.step === 'stop_triage')?.outcome).toBe('failed')
    expect(result.ok).toBe(true)
  })
})

describe('the two steps that stop the teardown', () => {
  test('an archive failure stops before anything is deleted', async () => {
    h.authorizationCount.mockResolvedValue(1)
    h.archiveFails = true
    const result = await teardownProject(PROJECT, ACTOR)
    expect(result).toMatchObject({ ok: false, failedStep: 'archive_authorizations', code: 'authorization_archive_failed' })
    expect(result.steps.at(-1)).toEqual({ step: 'archive_authorizations', outcome: 'failed' })
    expect(h.projectDelete).not.toHaveBeenCalled()
    expect(h.purge).not.toHaveBeenCalled()
    expect(h.events).not.toContain('delete files')
    expect(h.events).not.toContain('clear graph')
  })

  test('the archive records why: project_deleted by default, the caller\'s reason otherwise', async () => {
    h.authorizationCount.mockResolvedValue(1)
    await teardownProject(PROJECT, ACTOR)
    await teardownProject(PROJECT, { ...ACTOR, archiveReason: 'user_deleted' })
    const inserts = h.archiveSql.filter(s => s.sql.includes('INSERT'))
    expect(inserts.map(s => s.params)).toEqual([['p1', 'project_deleted'], ['p1', 'user_deleted']])
  })

  test('a row already gone reports project_not_found and stops', async () => {
    const gone = Object.assign(new Error('Record to delete does not exist.'), { code: 'P2025' })
    h.projectDelete.mockRejectedValue(gone)
    const result = await teardownProject(PROJECT, ACTOR)
    expect(result).toMatchObject({ ok: false, failedStep: 'delete_project', code: 'project_not_found', error: gone })
    expect(h.purge).not.toHaveBeenCalled()
    expect(h.graphRun).not.toHaveBeenCalled()
  })

  test('any other delete failure carries the error for the caller to answer', async () => {
    const boom = Object.assign(new Error('timeout'), { code: 'P2024' })
    h.projectDelete.mockRejectedValue(boom)
    const result = await teardownProject(PROJECT, ACTOR)
    expect(result).toMatchObject({ ok: false, failedStep: 'delete_project', code: 'delete_failed', error: boom })
  })
})
