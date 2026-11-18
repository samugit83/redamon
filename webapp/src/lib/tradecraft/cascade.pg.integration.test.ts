/**
 * Deletes on a real Postgres (T1.11): the user delete's order (the jobs flagged, then the row
 * with its cascade) leaves no tradecraft row with the account's id (R-201, AC-43); a project
 * delete takes its choices and leaves the resources (R-059); conversations that quoted a page
 * keep their text when the resource or its owner goes (R-210).
 *
 * Run through the disposable harness, on the session's own database:
 *   TC_PG_DB=tc_<session> tooling/scripts/tradecraft_pg_testdb.sh web src/lib/tradecraft/cascade.pg.integration.test.ts
 * Without TRADECRAFT_PG_TEST_URL (or PLUGINS_PG_TEST_URL) it is skipped. It refuses a database
 * that holds users without the harness's marker table.
 *
 * @vitest-environment node
 */
import { afterAll, beforeAll, beforeEach, describe, expect, test, vi } from 'vitest'
import { stubAgent } from './__testing__/agentDouble'

const URL_ = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL
vi.mock('@/lib/prisma', async () => {
  const { PrismaClient } = await import('@prisma/client')
  const url = process.env.TRADECRAFT_PG_TEST_URL || process.env.PLUGINS_PG_TEST_URL || 'postgresql://unused@127.0.0.1:1/unused'
  return { default: new PrismaClient({ datasources: { db: { url } } }) }
})

import db from '@/lib/prisma'
import { cancelUserTradecraftJobs } from './deleteCleanup'

const MARKER = 'plugins_pg_integration_test_marker'
const RUN = `tcc${process.pid}${Date.now().toString(36)}`

const BY_USER = ['tradecraft_ingestion_jobs', 'tradecraft_entries', 'tradecraft_sections', 'tradecraft_tree_nodes',
  'tradecraft_user_settings', 'user_tradecraft_resources']
const BY_RESOURCE = ['tradecraft_ingestion_jobs', 'tradecraft_page_ids', 'tradecraft_entries', 'tradecraft_sections',
  'tradecraft_tree_nodes', 'tradecraft_curations', 'tradecraft_project_choices']

async function count(table: string, column: string, value: string): Promise<number> {
  const rows = await db.$queryRawUnsafe<{ n: number }[]>(`SELECT count(*)::int AS n FROM ${table} WHERE ${column} = $1`, value)
  return rows[0].n
}

/** An account with a project, one resource holding a row in every tradecraft table, and two unfinished jobs. */
async function seedAccount(tag: string) {
  const userId = `${RUN}-${tag}-u`
  const projectId = `${RUN}-${tag}-p`
  await db.user.create({ data: { id: userId, name: tag, email: `${userId}@example.invalid` } })
  await db.project.create({ data: { id: projectId, userId, name: tag } })
  await db.tradecraftUserSettings.create({ data: { userId, v2Enabled: true } })
  const resource = await db.userTradecraftResource.create({
    data: { userId, name: tag, slug: `lib-${tag}`, url: `https://${tag}.example.invalid/`, storageMode: 'stored', generation: 1 },
  })
  const page = await db.tradecraftPageId.create({ data: { resourceId: resource.id, url: `https://${tag}.example.invalid/sqli` } })
  const entry = await db.tradecraftEntry.create({
    data: { userId, resourceId: resource.id, generation: 1, pageId: page.id, url: page.url, title: 'Blind injection', storedText: 'fake page text' },
  })
  await db.tradecraftSection.create({
    data: { entryId: entry.id, resourceId: resource.id, userId, generation: 1, ord: 0, level: 2, heading: 'Timing', text: 'fake section text' },
  })
  await db.tradecraftTreeNode.create({ data: { resourceId: resource.id, userId, generation: 1, path: 'Web/', parentPath: '', label: 'Web', pageCount: 1 } })
  await db.tradecraftCuration.create({ data: { resourceId: resource.id, url: page.url, blocked: true } })
  const running = await db.tradecraftIngestionJob.create({
    data: { userId, resourceId: resource.id, kind: 'refresh', status: 'running', leaseUntil: new Date(Date.now() + 60_000), actorUserId: userId },
  })
  const queued = await db.tradecraftIngestionJob.create({ data: { userId, kind: 'convert', status: 'queued' } })
  await db.userTradecraftResource.update({ where: { id: resource.id }, data: { activeJobId: running.id } })
  await db.tradecraftProjectChoice.create({ data: { projectId, resourceId: resource.id, createdById: userId } })
  return { userId, projectId, resourceId: resource.id, jobIds: [running.id, queued.id] }
}

async function conversationQuoting(owner: string, projectId: string, tag: string) {
  const conversation = await db.conversation.create({ data: { projectId, userId: owner, sessionId: `${RUN}-${tag}-s` } })
  await db.chatMessage.create({
    data: { conversationId: conversation.id, sequenceNum: 1, type: 'tool_result', data: { tool: 'tradecraft_lookup', text: 'quoted: fake page text' } },
  })
  return conversation.id
}

describe.skipIf(!URL_)('tradecraft deletes on a real Postgres', () => {
  beforeAll(async () => {
    const [{ users }] = await db.$queryRaw<{ users: number }[]>`SELECT count(*)::int AS users FROM users`
    const [{ marked }] = await db.$queryRaw<{ marked: boolean }[]>`SELECT to_regclass(${MARKER}) IS NOT NULL AS marked`
    if (users > 0 && !marked) throw new Error('Refusing to run: this database holds users and is not a disposable test database')
    if (!marked) await db.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS ${MARKER} (created_at timestamptz DEFAULT now())`)
  })

  beforeEach(() => { stubAgent() })

  afterAll(async () => {
    await db.$executeRawUnsafe(`DELETE FROM users WHERE id LIKE '${RUN}-%'`)
    await db.$disconnect()
  })

  test('user_delete: the jobs are flagged first, then no tradecraft row with the id remains (R-201, AC-43)', async () => {
    const { userId, resourceId, jobIds } = await seedAccount('del')
    const other = await seedAccount('keep')
    const cancelled = await cancelUserTradecraftJobs(userId)
    expect(cancelled.flagged).toBe(2)
    const flags = await db.tradecraftIngestionJob.findMany({ where: { id: { in: jobIds } }, select: { cancelRequested: true } })
    expect(flags.map(f => f.cancelRequested)).toEqual([true, true])
    await db.user.delete({ where: { id: userId } })
    for (const t of BY_USER) expect(await count(t, 'user_id', userId), t).toBe(0)
    for (const t of BY_RESOURCE) expect(await count(t, 'resource_id', resourceId), t).toBe(0)
    for (const t of BY_RESOURCE) expect(await count(t, 'resource_id', other.resourceId), `${t} of another account`).toBeGreaterThan(0)
    expect((await db.tradecraftIngestionJob.findFirst({ where: { userId: other.userId, status: 'running' } }))?.cancelRequested).toBe(false)
  })

  test('project_delete: its choices go, the resources and their pages stay (R-059)', async () => {
    const { userId, projectId, resourceId } = await seedAccount('proj')
    await db.project.delete({ where: { id: projectId } })
    expect(await count('tradecraft_project_choices', 'project_id', projectId)).toBe(0)
    expect(await count('user_tradecraft_resources', 'id', resourceId)).toBe(1)
    expect(await count('tradecraft_entries', 'resource_id', resourceId)).toBe(1)
    expect(await count('tradecraft_user_settings', 'user_id', userId)).toBe(1)
  })

  test('conversations_untouched: text quoted from a page outlives the resource and its owner (R-210)', async () => {
    const a = await seedAccount('quoted')
    const b = await seedAccount('reader')
    const own = await conversationQuoting(a.userId, a.projectId, 'own')
    const theirs = await conversationQuoting(b.userId, b.projectId, 'theirs')
    await db.userTradecraftResource.delete({ where: { id: a.resourceId } })
    for (const id of [own, theirs]) {
      const messages = await db.chatMessage.findMany({ where: { conversationId: id }, select: { data: true } })
      expect(messages.map(m => (m.data as { text: string }).text)).toEqual(['quoted: fake page text'])
    }
    await db.user.delete({ where: { id: a.userId } })
    const kept = await db.chatMessage.findMany({ where: { conversationId: theirs }, select: { data: true } })
    expect(kept.map(m => (m.data as { text: string }).text)).toEqual(['quoted: fake page text'])
  })
})
