/**
 * The live-check fixture cleanup (scripts/e2e-rbac-cleanup.mjs) must leave nothing a run
 * created: the fixture projects' Neo4j nodes and the checkpoints of their agent runs went
 * unremoved (each live run removed them by hand), and the audit rows of the matrix's
 * throwaway account, which the runner deletes by SQL mid-run, could no longer be matched.
 * And it must touch nothing else: no other account, project, graph node or thread.
 *
 * Prisma and the Neo4j session are in-memory doubles here (the checkpoint double follows
 * the script's SQL); scripts/e2e-rbac-cleanup.pg.integration.test.ts runs the real SQL and
 * Prisma filters on Postgres.
 *
 * Run: npx vitest run scripts/e2e-rbac-cleanup.test.ts
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { GLOBAL_REFERENCE_LABELS as GRAPH_RESTORE_LABELS } from '@/lib/graphRestore'
import {
  CHECKPOINT_TABLES, DELETED_FIXTURE_ID, FIXTURE_EMAIL, GLOBAL_REFERENCE_LABELS,
  cleanupRbacFixtures, clearFixtureGraph, deleteFixtureCheckpoints,
} from './e2e-rbac-cleanup.mjs'

type Row = Record<string, unknown>
type Where = Record<string, unknown>

// ---- an in-memory Prisma for the tables the cleanup touches ----

function fieldMatches(value: unknown, cond: unknown): boolean {
  if (cond === null) return value === null || value === undefined
  if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
    const c = cond as Row
    if (Array.isArray(c.path)) {
      const at = (value as Row | null)?.[String(c.path[0])]
      if ('string_starts_with' in c) return typeof at === 'string' && at.startsWith(String(c.string_starts_with))
      throw new Error(`double: unsupported JSON filter ${JSON.stringify(c)}`)
    }
    for (const [op, arg] of Object.entries(c)) {
      if (op === 'in' && !(arg as unknown[]).includes(value)) return false
      if (op === 'startsWith' && !(typeof value === 'string' && value.startsWith(String(arg)))) return false
      if (op === 'endsWith' && !(typeof value === 'string' && value.endsWith(String(arg)))) return false
      if (!['in', 'startsWith', 'endsWith'].includes(op)) throw new Error(`double: unsupported operator ${op}`)
    }
    return true
  }
  return value === cond
}

function rowMatches(row: Row, where: Where = {}): boolean {
  return Object.entries(where).every(([k, v]) => {
    if (k === 'OR') return (v as Where[]).some(w => rowMatches(row, w))
    return fieldMatches(row[k], v)
  })
}

function makeDb() {
  const t: Record<string, Row[]> = {
    user: [], project: [], jobQueue: [], engagementAuthorization: [], auditLog: [], actAsAudit: [],
    checkpoints: [], checkpoint_blobs: [], checkpoint_writes: [],
  }
  const calls: string[] = []
  const pick = (r: Row, select?: Row) => (select ? Object.fromEntries(Object.keys(select).map(k => [k, r[k]])) : { ...r })
  const delegate = (name: string) => ({
    findMany: async (a: { where?: Where; select?: Row } = {}) => { calls.push(`${name}.findMany`); return t[name].filter(r => rowMatches(r, a.where)).map(r => pick(r, a.select)) },
    count: async (a: { where?: Where } = {}) => t[name].filter(r => rowMatches(r, a.where)).length,
    updateMany: async (a: { where?: Where; data: Row }) => {
      const rows = t[name].filter(r => rowMatches(r, a.where))
      rows.forEach(r => Object.assign(r, a.data))
      return { count: rows.length }
    },
    delete: async (a: { where: Where }) => {
      calls.push(`${name}.delete`)
      const i = t[name].findIndex(r => rowMatches(r, a.where))
      if (i < 0) throw Object.assign(new Error('not found'), { code: 'P2025' })
      if (name === 'project') t.jobQueue = t.jobQueue.filter(j => j.projectId !== a.where.id)
      return t[name].splice(i, 1)[0]
    },
    deleteMany: async (a: { where?: Where } = {}) => {
      calls.push(`${name}.deleteMany`)
      const before = t[name].length
      t[name] = t[name].filter(r => !rowMatches(r, a.where))
      return { count: before - t[name].length }
    },
  })
  const part = (thread: string, i: number) => thread.split(':')[i] ?? ''
  const db = {
    t, calls, missingCheckpointTables: false, failCheckpoints: false,
    user: delegate('user'), project: delegate('project'), jobQueue: delegate('jobQueue'),
    engagementAuthorization: delegate('engagementAuthorization'), auditLog: delegate('auditLog'), actAsAudit: delegate('actAsAudit'),
    $queryRawUnsafe: async (sql: string) => {
      const table = /to_regclass\('public\.(\w+)'\)/.exec(sql)?.[1]
      if (!table) throw new Error(`double: unexpected query ${sql}`)
      return [{ present: !db.missingCheckpointTables }]
    },
    // The script's DELETE, read as it is written: user part in $1, project part in $2, or an
    // rbac- session whose user and project are both gone.
    $executeRawUnsafe: async (sql: string, userIds: string[], projectIds: string[]) => {
      const table = /DELETE FROM "(\w+)"/.exec(sql)?.[1]
      if (!table || !CHECKPOINT_TABLES.includes(table)) throw new Error(`double: unexpected statement ${sql}`)
      calls.push(`${table}.delete`)
      if (db.failCheckpoints) throw Object.assign(new Error('permission denied'), { code: '42501' })
      const gone = (thread: string) => !t.user.some(u => u.id === part(thread, 0)) && !t.project.some(p => p.id === part(thread, 1))
      const before = t[table].length
      t[table] = t[table].filter(r => {
        const th = String(r.thread_id)
        return !(userIds.includes(part(th, 0)) || projectIds.includes(part(th, 1)) || (part(th, 2).startsWith('rbac-') && gone(th)))
      })
      return before - t[table].length
    },
  }
  return db
}

// ---- a Neo4j session over an in-memory node list ----

function makeGraph(nodes: Array<{ labels: string[]; project_id?: string }>) {
  const g = {
    nodes, runs: [] as Array<{ cypher: string; params: Row }>, fail: false,
    session: {
      run: async (cypher: string, params: { pids: string[]; excluded: string[] }) => {
        g.runs.push({ cypher, params })
        if (g.fail) throw Object.assign(new Error('Neo4j unavailable'), { code: 'ServiceUnavailable' })
        const doomed = g.nodes.filter(n => n.project_id !== undefined && params.pids.includes(n.project_id)
          && !n.labels.some(l => params.excluded.includes(l)))
        g.nodes = g.nodes.filter(n => !doomed.includes(n))
        return { summary: { counters: { updates: () => ({ nodesDeleted: doomed.length }) } } }
      },
    },
  }
  return g
}

// ---- fixtures: two seeded members, one project each, one real account and project ----

let db: ReturnType<typeof makeDb>
let graph: ReturnType<typeof makeGraph>
const purged: string[] = []
const warn = vi.fn()

function seed() {
  db = makeDb()
  db.t.user.push(
    { id: 'u-fa', email: 'rbac-member-a@e2e.local' },
    { id: 'u-fb', email: 'rbac-member-b@e2e.local' },
    { id: 'u-upg', email: 'upg-member-a@e2e.local' },
    { id: 'u-real', email: 'alice@example.com' },
    { id: 'u-near', email: 'rbac-member-a@example.com' },
    { id: 'u-audit', email: 'e2e-audit-owner@e2e.local' },
    { id: 'u-iphn', email: 'iphn-owner@e2e.local' },
  )
  db.t.project.push(
    { id: 'p-fa', userId: 'u-fa' }, { id: 'p-fb', userId: 'u-fb' },
    { id: 'p-real', userId: 'u-real' }, { id: 'p-audit', userId: 'u-audit' }, { id: 'p-nwlab', userId: 'u-iphn' },
  )
  db.t.jobQueue.push({ id: 'j1', projectId: 'p-fa', status: 'queued' }, { id: 'j2', projectId: 'p-real', status: 'queued' })
  db.t.auditLog.push(
    { id: 'a-login-fa', actorId: 'u-fa', targetId: 'u-fa', action: 'auth.login.success', after: {} },
    { id: 'a-project-fb', actorId: 'u-real', targetId: 'p-fb', action: 'project.update', after: {} },
    // The throwaway account, deleted by SQL mid-run: only its fixed id names it.
    { id: 'a-login-deleted', actorId: DELETED_FIXTURE_ID, targetId: DELETED_FIXTURE_ID, action: 'auth.login.success', after: {} },
    { id: 'a-fail-deleted', actorId: null, targetId: null, action: 'auth.login.failure', after: { email: 'rbac-deleted@e2e.local' } },
    { id: 'a-lockout-upg', actorId: null, targetId: null, action: 'auth.login.lockout', after: { email: 'upg-member-b@e2e.local' } },
    { id: 'a-fail-real', actorId: null, targetId: null, action: 'auth.login.failure', after: { email: 'alice@example.com' } },
    { id: 'a-fail-near', actorId: null, targetId: null, action: 'auth.login.failure', after: { email: 'rbac-member-a@example.com' } },
    { id: 'a-fail-audit', actorId: null, targetId: null, action: 'auth.login.failure', after: { email: 'e2e-audit-owner@e2e.local' } },
    { id: 'a-real', actorId: 'u-real', targetId: 'p-real', action: 'project.update', after: {} },
  )
  db.t.actAsAudit.push(
    { id: 'x1', adminId: 'u-fa', targetUserId: 'u-fb' },
    { id: 'x2', adminId: 'u-real', targetUserId: 'u-audit' },
  )
  for (const table of CHECKPOINT_TABLES) {
    db.t[table].push(
      { thread_id: 'u-fa:p-fa:rbac-stub-long-run-1' },
      { thread_id: 'u-fa:p-fa:0123456789abcdef0123456789abcdef' },
      // An admin's act-as run on a fixture project is keyed under the member, but the project names it too.
      { thread_id: 'u-other:p-fb:sess' },
      // Leftovers of an earlier run whose fixtures are gone.
      { thread_id: 'u-gone:p-gone:rbac-stub-approval-1' },
      { thread_id: `${DELETED_FIXTURE_ID}:p-gone:sess` },
      // Never touched: a live account's thread, even one named rbac-, and a gone user's other session.
      { thread_id: 'u-real:p-real:0123' },
      { thread_id: 'u-real:p-real:rbac-sess-looks-like-a-fixture' },
      { thread_id: 'u-gone:p-gone:0123456789' },
      { thread_id: 'u-audit:p-audit:sess' },
    )
  }
  graph = makeGraph([
    { labels: ['Domain'], project_id: 'p-fa' }, { labels: ['AttackChain'], project_id: 'p-fa' },
    { labels: ['ChainStep'], project_id: 'p-fb' }, { labels: ['CVE'], project_id: 'p-fa' },
    { labels: ['Domain'], project_id: 'p-real' }, { labels: ['Domain'], project_id: 'p-nwlab' },
    { labels: ['MitreData'] },
  ])
  purged.length = 0
  warn.mockReset()
}

const run = () => cleanupRbacFixtures({ prisma: db, graph: graph.session, purgeWorkspace: async (id: string) => { purged.push(id) }, warn })
const threads = (table = 'checkpoints') => db.t[table].map(r => r.thread_id).sort()

beforeEach(seed)

describe('the fixtures go, with their graph and agent checkpoints', () => {
  test('fixture users, projects, graph nodes and checkpoints are removed', async () => {
    const s = await run()

    expect(s.failed).toBe(false)
    expect(db.t.user.map(u => u.id).sort()).toEqual(['u-audit', 'u-iphn', 'u-near', 'u-real'])
    expect(db.t.project.map(p => p.id).sort()).toEqual(['p-audit', 'p-nwlab', 'p-real'])
    expect(s).toMatchObject({ cleaned: 3, projectsDeleted: 2, graphNodesDeleted: 3 })
    expect(purged.sort()).toEqual(['p-fa', 'p-fb'])
    expect(graph.nodes).toEqual([
      { labels: ['CVE'], project_id: 'p-fa' }, { labels: ['Domain'], project_id: 'p-real' },
      { labels: ['Domain'], project_id: 'p-nwlab' }, { labels: ['MitreData'] },
    ])
    for (const table of CHECKPOINT_TABLES) {
      expect(threads(table)).toEqual([
        'u-audit:p-audit:sess', 'u-gone:p-gone:0123456789', 'u-real:p-real:0123', 'u-real:p-real:rbac-sess-looks-like-a-fixture',
      ])
    }
    expect(s.checkpointRowsDeleted).toBe(5 * CHECKPOINT_TABLES.length)
  })

  test('the graph and the checkpoints are cleared before any fixture row is deleted', async () => {
    const order: string[] = []
    const run0 = graph.session.run
    graph.session.run = async (...a: Parameters<typeof run0>) => { order.push('graph'); return run0(...a) }
    await run()
    const firstRowDelete = db.calls.findIndex(c => c === 'project.delete' || c === 'user.deleteMany')
    const lastCheckpoint = db.calls.map(c => c.endsWith('.delete') && c.startsWith('checkpoint')).lastIndexOf(true)
    expect(order).toEqual(['graph'])
    expect(lastCheckpoint).toBeGreaterThan(-1)
    expect(lastCheckpoint).toBeLessThan(firstRowDelete)
  })

  test('the graph query names only the fixture projects and spares the shared reference nodes', async () => {
    await run()
    expect(graph.runs).toHaveLength(1)
    expect([...graph.runs[0].params.pids as string[]].sort()).toEqual(['p-fa', 'p-fb'])
    expect(graph.runs[0].params.excluded).toEqual(['CVE', 'MitreData', 'Capec'])
    expect(graph.runs[0].cypher).toMatch(/n\.project_id IN \$pids/)
    expect(graph.runs[0].cypher).toMatch(/NONE\(l IN labels\(n\) WHERE l IN \$excluded\)/)
  })

  test('the shared reference labels are graphRestore\'s', () => {
    expect(GLOBAL_REFERENCE_LABELS).toEqual([...GRAPH_RESTORE_LABELS])
  })

  test('live jobs of a fixture project are canceled, nobody else\'s', async () => {
    db.t.engagementAuthorization.push({ id: 'auth1', projectId: 'p-fb' })
    await run()
    expect(db.t.jobQueue.find(j => j.id === 'j2')?.status).toBe('queued')
  })
})

describe('audit rows', () => {
  test('the fixtures\' rows go, including the throwaway account deleted mid-run', async () => {
    const s = await run()
    expect(db.t.auditLog.map(a => a.id).sort()).toEqual(['a-fail-audit', 'a-fail-near', 'a-fail-real', 'a-real'])
    expect(db.t.actAsAudit.map(a => a.id)).toEqual(['x2'])
    expect(s.auditRowsDeleted).toBe(5 + 1)
  })

  test('the rows of a fixture account deleted through the Users page go, found by its user.delete row', async () => {
    // DELETE /api/users/[id] records the account's address in `before`: once the user row is
    // gone, that row is the only record that the id was a fixture's (the P0-18 throwaway).
    db.t.auditLog.push(
      { id: 'a-del-thrown', actorId: 'u-fa', targetType: 'user', targetId: 'u-thrown', action: 'user.delete', before: { email: 'rbac-throwaway@e2e.local' }, after: {} },
      { id: 'a-login-thrown', actorId: 'u-thrown', targetType: 'user', targetId: 'u-thrown', action: 'auth.login.success', after: {} },
      { id: 'a-real-on-thrown', actorId: 'u-real', targetType: 'user', targetId: 'u-thrown', action: 'user.update', after: {} },
      // A real account and a near-miss address deleted the same way: their rows stay.
      { id: 'a-del-bob', actorId: 'u-real', targetType: 'user', targetId: 'u-bob', action: 'user.delete', before: { email: 'bob@example.com' }, after: {} },
      { id: 'a-login-bob', actorId: 'u-bob', targetType: 'user', targetId: 'u-bob', action: 'auth.login.success', after: {} },
      { id: 'a-del-near', actorId: 'u-real', targetType: 'user', targetId: 'u-near2', action: 'user.delete', before: { email: 'rbac-x@example.com' }, after: {} },
      { id: 'a-login-near2', actorId: 'u-near2', targetType: 'user', targetId: 'u-near2', action: 'auth.login.success', after: {} },
    )
    db.t.actAsAudit.push({ id: 'x3', adminId: 'u-real', targetUserId: 'u-thrown' }, { id: 'x4', adminId: 'u-real', targetUserId: 'u-bob' })
    for (const table of CHECKPOINT_TABLES) db.t[table].push({ thread_id: 'u-thrown:p-gone:sess' }, { thread_id: 'u-bob:p-gone:sess' })
    const s = await run()
    for (const table of CHECKPOINT_TABLES) {
      expect(threads(table)).toContain('u-bob:p-gone:sess')
      expect(threads(table)).not.toContain('u-thrown:p-gone:sess')
    }
    expect(db.t.auditLog.map(a => a.id).sort()).toEqual([
      'a-del-bob', 'a-del-near', 'a-fail-audit', 'a-fail-near', 'a-fail-real', 'a-login-bob', 'a-login-near2', 'a-real',
    ])
    expect(db.t.actAsAudit.map(a => a.id)).toEqual(['x2', 'x4'])
    expect(s.auditRowsDeleted).toBe(5 + 3 + 1 + 1)
  })

  test('the fixed id is the seed\'s', () => {
    const seedSource = readFileSync(path.join(__dirname, 'e2e-rbac-seed.mjs'), 'utf8')
    expect(seedSource).toMatch(new RegExp(`key: 'DELETED',[^}]*id: '${DELETED_FIXTURE_ID}'`))
  })

  test('only exact fixture addresses are fixtures', () => {
    for (const e of ['rbac-member-a@e2e.local', 'rbac-deleted@e2e.local', 'upg-admin-a@e2e.local']) expect(FIXTURE_EMAIL.test(e)).toBe(true)
    for (const e of ['rbac-member-a@example.com', 'e2e-audit-x@e2e.local', 'iphn-a@e2e.local', 'nwlab-a@e2e.local',
      'xrbac-a@e2e.local', 'rbac-a@e2e.local.evil', 'RBAC-A@e2e.local']) expect(FIXTURE_EMAIL.test(e)).toBe(false)
  })
})

describe('failures and repeats', () => {
  test('a project holding an authorization record is kept with its owner, graph, threads and rows', async () => {
    db.t.engagementAuthorization.push({ id: 'auth1', projectId: 'p-fb' })
    const s = await run()

    expect(s.failed).toBe(true)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('CLEANUP_ERROR: project p-fb holds 1 authorization record'))
    expect(db.t.project.some(p => p.id === 'p-fb')).toBe(true)
    expect(db.t.user.some(u => u.id === 'u-fb')).toBe(true)
    expect(graph.nodes.some(n => n.project_id === 'p-fb')).toBe(true)
    expect(threads()).toContain('u-other:p-fb:sess')
    expect(db.t.auditLog.some(a => a.id === 'a-project-fb')).toBe(true)
    expect(db.t.project.some(p => p.id === 'p-fa')).toBe(false)
  })

  test('Neo4j down: nothing is deleted, the run fails, a rerun finishes it', async () => {
    graph.fail = true
    const s = await run()

    expect(s.failed).toBe(true)
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/^CLEANUP_ERROR: the fixtures' graph or agent checkpoints could not be cleared \(ServiceUnavailable\)/))
    expect(db.t.user).toHaveLength(7)
    expect(db.t.project).toHaveLength(5)
    expect(db.t.auditLog).toHaveLength(9)

    graph.fail = false
    expect((await run()).failed).toBe(false)
    expect(graph.nodes.some(n => n.project_id === 'p-fa' && n.labels[0] !== 'CVE')).toBe(false)
  })

  test('no Neo4j session at all counts as down when there are fixture projects', async () => {
    const s = await cleanupRbacFixtures({ prisma: db, graph: null, purgeWorkspace: async () => {}, warn })
    expect(s.failed).toBe(true)
    expect(db.t.project).toHaveLength(5)
  })

  test('a failed checkpoint delete deletes no row either', async () => {
    db.failCheckpoints = true
    const s = await run()
    expect(s.failed).toBe(true)
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('(42501)'))
    expect(db.t.user).toHaveLength(7)
  })

  test('no checkpointer tables (MemorySaver) is not a failure', async () => {
    db.missingCheckpointTables = true
    const s = await run()
    expect(s.failed).toBe(false)
    expect(s.checkpointRowsDeleted).toBe(0)
    expect(db.t.user).toHaveLength(4)
  })

  test('a second run finds nothing', async () => {
    await run()
    const again = await run()
    expect(again).toEqual({ cleaned: 0, projectsDeleted: 0, auditRowsDeleted: 0, graphNodesDeleted: 0, checkpointRowsDeleted: 0, failed: false })
    expect(graph.runs).toHaveLength(1)
  })
})

describe('the two clearing helpers on their own', () => {
  test('no project, no graph query', async () => {
    expect(await clearFixtureGraph(graph.session, [])).toBe(0)
    expect(graph.runs).toEqual([])
  })

  test('each checkpointer table is checked and cleared, parameters bound, never interpolated', async () => {
    const seen: Array<{ sql: string; params: unknown[] }> = []
    const fake = {
      $queryRawUnsafe: async () => [{ present: true }],
      $executeRawUnsafe: async (sql: string, ...params: unknown[]) => { seen.push({ sql, params }); return 1 },
    }
    expect(await deleteFixtureCheckpoints(fake, { userIds: ["u'1"], projectIds: ['p1'] })).toBe(3)
    expect(seen.map(s => /DELETE FROM "(\w+)"/.exec(s.sql)?.[1])).toEqual(CHECKPOINT_TABLES)
    for (const s of seen) {
      expect(s.params).toEqual([["u'1"], ['p1']])
      expect(s.sql).not.toContain("u'1")
    }
  })
})
