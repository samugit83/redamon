/**
 * The live-check fixture cleanup (scripts/e2e-rbac-cleanup.mjs) on a real Postgres: its
 * checkpoint DELETE (thread ids "<user>:<project>:<session>" split by `split_part`, the
 * orphan rule checked against `users` and `projects`), the JSON filter on failed sign-ins
 * and the cascades the project delete relies on. Neo4j is a recording double.
 *
 * Needs a DISPOSABLE database holding the webapp schema (`prisma db push`); it empties
 * `audit_log`, `act_as_audit`, `projects` and `users` (CASCADE) and creates the three
 * checkpointer tables (langgraph's columns that matter here) between tests. Run:
 *   PLUGINS_PG_TEST_URL=postgresql://... npx vitest run --no-file-parallelism scripts/e2e-rbac-cleanup.pg.integration.test.ts
 * Without the variable it is skipped. It refuses a database that already holds users
 * unless that database carries the pg-integration marker table.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, beforeEach, afterAll } from 'vitest'
import { PrismaClient } from '@prisma/client'
import { CHECKPOINT_TABLES, DELETED_FIXTURE_ID, cleanupRbacFixtures } from './e2e-rbac-cleanup.mjs'

const URL = process.env.PLUGINS_PG_TEST_URL
const MARKER = 'plugins_pg_integration_test_marker'
const db = URL ? new PrismaClient({ datasources: { db: { url: URL } } }) : (null as unknown as PrismaClient)

const graphCalls: Array<{ pids: string[]; excluded: string[] }> = []
const graph = {
  run: async (_cypher: string, params: { pids: string[]; excluded: string[] }) => {
    graphCalls.push(params)
    return { summary: { counters: { updates: () => ({ nodesDeleted: params.pids.length }) } } }
  },
}
const purged: string[] = []
const run = () => cleanupRbacFixtures({ prisma: db, graph, purgeWorkspace: async (id: string) => { purged.push(id) }, warn: () => {} })

async function threads(table: string): Promise<string[]> {
  const rows = await db.$queryRawUnsafe<{ thread_id: string }[]>(`SELECT thread_id FROM "${table}"`)
  return rows.map(r => r.thread_id).sort()
}

describe.skipIf(!URL)('cleanupRbacFixtures on a real Postgres (PLUGINS_PG_TEST_URL)', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(async () => {
    graphCalls.length = 0
    purged.length = 0
    await db.$executeRawUnsafe('TRUNCATE audit_log, act_as_audit, projects, users CASCADE')
    for (const table of CHECKPOINT_TABLES) {
      await db.$executeRawUnsafe(`DROP TABLE IF EXISTS "${table}"`)
      await db.$executeRawUnsafe(`CREATE TABLE "${table}" (thread_id text NOT NULL, checkpoint_ns text NOT NULL DEFAULT '', n int)`)
    }
    const users = [
      ['u-fa', 'rbac-member-a@e2e.local'], ['u-fb', 'rbac-member-b@e2e.local'],
      ['u-real', 'alice@example.invalid'], ['u-audit', 'e2e-audit-owner@e2e.local'],
    ]
    for (const [id, email] of users) await db.user.create({ data: { id, email, name: id, password: '', role: 'standard' } })
    for (const [id, userId] of [['p-fa', 'u-fa'], ['p-fb', 'u-fb'], ['p-real', 'u-real'], ['p-audit', 'u-audit']]) {
      await db.project.create({ data: { id, userId, name: `name-${id}`, targetDomain: 'example.invalid' } })
    }
    await db.conversation.create({ data: { userId: 'u-fa', projectId: 'p-fa', sessionId: 'rbac-sess-PA', title: 'x' } })
    await db.auditLog.createMany({
      data: [
        { id: 'a-login-fa', actorId: 'u-fa', targetId: 'u-fa', action: 'auth.login.success', targetType: 'user', after: {} },
        { id: 'a-login-deleted', actorId: DELETED_FIXTURE_ID, targetId: DELETED_FIXTURE_ID, action: 'auth.login.success', targetType: 'user', after: {} },
        { id: 'a-fail-deleted', action: 'auth.login.failure', targetType: 'user', after: { email: 'rbac-deleted@e2e.local', ip: '127.0.0.1' } },
        { id: 'a-fail-near', action: 'auth.login.failure', targetType: 'user', after: { email: 'rbac-member-a@example.invalid' } },
        { id: 'a-fail-audit', action: 'auth.login.failure', targetType: 'user', after: { email: 'e2e-audit-owner@e2e.local' } },
        { id: 'a-no-email', action: 'system.something', targetType: 'system', after: { count: 3 } },
        { id: 'a-null-after', action: 'system.other', targetType: 'system' },
        { id: 'a-real', actorId: 'u-real', targetId: 'p-real', action: 'project.update', targetType: 'project', after: {} },
      ],
    })
    for (const table of CHECKPOINT_TABLES) {
      const rows = [
        'u-fa:p-fa:rbac-stub-long-run-1', 'u-fa:p-fa:0123abcd', 'u-other:p-fb:sess',
        'u-gone:p-gone:rbac-stub-approval-1', `${DELETED_FIXTURE_ID}:p-gone:sess`,
        'u-real:p-real:0123', 'u-real:p-real:rbac-sess-looks-like-a-fixture', 'u-gone:p-gone:0123456789',
        'u-real:p-gone:rbac-x', 'u-gone:p-real:rbac-y', 'u-audit:p-audit:sess', 'no-colons-at-all',
      ]
      for (const t of rows) await db.$executeRawUnsafe(`INSERT INTO "${table}" (thread_id, n) VALUES ($1, 1)`, t)
    }
  })

  afterAll(async () => {
    if (!URL) return
    for (const table of CHECKPOINT_TABLES) await db.$executeRawUnsafe(`DROP TABLE IF EXISTS "${table}"`)
    await db.$disconnect()
  })

  test('fixtures, their checkpoints and audit rows go; nothing else does', async () => {
    const s = await run()

    expect(s.failed).toBe(false)
    expect((await db.user.findMany({ select: { id: true } })).map(u => u.id).sort()).toEqual(['u-audit', 'u-real'])
    expect((await db.project.findMany({ select: { id: true } })).map(p => p.id).sort()).toEqual(['p-audit', 'p-real'])
    expect(await db.conversation.count()).toBe(0)
    expect(graphCalls.map(c => [...c.pids].sort())).toEqual([['p-fa', 'p-fb']])
    expect(purged.sort()).toEqual(['p-fa', 'p-fb'])
    for (const table of CHECKPOINT_TABLES) {
      expect(await threads(table)).toEqual([
        'no-colons-at-all', 'u-audit:p-audit:sess', 'u-gone:p-gone:0123456789', 'u-gone:p-real:rbac-y',
        'u-real:p-gone:rbac-x', 'u-real:p-real:0123', 'u-real:p-real:rbac-sess-looks-like-a-fixture',
      ])
    }
    expect(s.checkpointRowsDeleted).toBe(5 * CHECKPOINT_TABLES.length)
    expect((await db.auditLog.findMany({ select: { id: true } })).map(a => a.id).sort())
      .toEqual(['a-fail-audit', 'a-fail-near', 'a-no-email', 'a-null-after', 'a-real'])
    expect(s).toMatchObject({ cleaned: 2, projectsDeleted: 2, auditRowsDeleted: 3 })
  })

  test('a second run changes nothing', async () => {
    await run()
    const again = await run()
    expect(again).toEqual({ cleaned: 0, projectsDeleted: 0, auditRowsDeleted: 0, graphNodesDeleted: 0, checkpointRowsDeleted: 0, failed: false })
  })

  test('without the checkpointer tables the rest still goes', async () => {
    for (const table of CHECKPOINT_TABLES) await db.$executeRawUnsafe(`DROP TABLE "${table}"`)
    const s = await run()
    expect(s).toMatchObject({ failed: false, checkpointRowsDeleted: 0, cleaned: 2 })
  })
})
