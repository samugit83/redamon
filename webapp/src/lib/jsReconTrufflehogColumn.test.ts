/**
 * The pre-push step that keeps JS Recon's TruffleHog engine off in the projects
 * that existed before it (scripts/add-js-recon-trufflehog-column.mjs).
 *
 * `db push` would add the column with its default, true, and Postgres fills
 * every existing row with it. The step adds it first with DEFAULT false, so the
 * push only moves the default. Three things must hold, and each can drift on its
 * own: the step adds only a missing column and never rewrites a present one, it
 * names the column the schema maps, and the entrypoint runs it fatally BEFORE
 * the push (after it, the rows are already true).
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

import { addJsReconTrufflehogColumn, COLUMN } from '../../scripts/add-js-recon-trufflehog-column.mjs'

/** A Prisma stand-in: answers the two existence probes and the count, records the SQL. */
function fakePrisma({ table, column, projects = 0 }: { table: boolean; column: boolean; projects?: number }) {
  const executed: string[] = []
  return {
    executed,
    async $queryRawUnsafe(sql: string) {
      if (sql.includes('information_schema.tables')) return table ? [{ '?column?': 1 }] : []
      if (sql.includes('information_schema.columns')) return column ? [{ '?column?': 1 }] : []
      if (sql.includes('count(*)')) return [{ n: projects }]
      throw new Error(`unexpected query: ${sql}`)
    },
    async $executeRawUnsafe(sql: string) {
      executed.push(sql)
      return 0
    },
  }
}

describe('addJsReconTrufflehogColumn', () => {
  test('a fresh database is left to the push, which creates the column with DEFAULT true', async () => {
    const prisma = fakePrisma({ table: false, column: false })
    expect(await addJsReconTrufflehogColumn(prisma)).toEqual({ status: 'fresh', keptOff: 0 })
    expect(prisma.executed).toEqual([])
  })

  test('an existing database without the column gets it with DEFAULT false', async () => {
    const prisma = fakePrisma({ table: true, column: false, projects: 3 })
    expect(await addJsReconTrufflehogColumn(prisma)).toEqual({ status: 'added', keptOff: 3 })
    expect(prisma.executed).toHaveLength(1)
    const sql = prisma.executed[0].replace(/\s+/g, ' ')
    expect(sql).toContain(`ADD COLUMN IF NOT EXISTS ${COLUMN} boolean NOT NULL DEFAULT false`)
  })

  test('a column already present is never rewritten, so a project switched on stays on', async () => {
    const prisma = fakePrisma({ table: true, column: true, projects: 3 })
    expect(await addJsReconTrufflehogColumn(prisma)).toEqual({ status: 'present', keptOff: 0 })
    expect(prisma.executed).toEqual([])
  })

  test('it names the column the schema maps, and the schema default is the one it holds back', () => {
    const schema = readFileSync(path.resolve(__dirname, '../../prisma/schema.prisma'), 'utf8')
    const line = schema.split('\n').find((l) => /^\s*jsReconTrufflehogEnabled\s/.test(l)) ?? ''
    expect(line).toContain(`@map("${COLUMN}")`)
    expect(line).toContain('@default(true)')
  })

  test('the entrypoint runs it fatally, before the push', () => {
    const dockerfile = readFileSync(path.resolve(__dirname, '../../Dockerfile'), 'utf8')
    const entry = dockerfile.split('\n').find((l) => l.includes('> /app/entrypoint.sh')) ?? ''
    const step = entry.indexOf('node scripts/add-js-recon-trufflehog-column.mjs 2>&1 || exit 1\\n')
    expect(step).toBeGreaterThan(-1)
    expect(entry.indexOf('db push')).toBeGreaterThan(step)
  })
})
