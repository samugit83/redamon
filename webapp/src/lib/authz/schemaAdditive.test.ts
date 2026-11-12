/**
 * UP-02, master plan §9.7: every schema change of the RBAC plan is additive. The boot
 * runs `prisma db push --accept-data-loss`, which drops a column that left the schema
 * together with its data, and during a rolling deploy an old copy still reads every
 * column it knew. So every field of the 7.7.2 release (the upgrade harness's pinned
 * base) must still exist with the same type and column, and a column added to a 7.7.2
 * table must be nullable or carry a default, or the push cannot fill existing rows.
 *
 * The snapshot `__fixtures__/schema-7.7.2-fields.json` was generated once from
 * `git show 442debbf:webapp/prisma/schema.prisma` with `__testing__/prismaSchema.ts`.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/schemaAdditive.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import { parsePrismaModels, baseType } from './__testing__/prismaSchema'
import release from './__fixtures__/schema-7.7.2-fields.json'

const WEBAPP = path.resolve(__dirname, '../../..')
const now = parsePrismaModels(readFileSync(path.join(WEBAPP, 'prisma/schema.prisma'), 'utf8'))

type Snapshot = Record<string, { table: string; fields: Record<string, { type: string; column: string }> }>
const old = (release as { models: Snapshot }).models

describe('the 7.7.2 schema survives every RBAC change', () => {
  test('the snapshot is the whole 7.7.2 schema, not a truncated copy', () => {
    expect(Object.keys(old)).toHaveLength(47)
    expect(Object.keys(old.User.fields)).toEqual(expect.arrayContaining(['id', 'email', 'password', 'role']))
    expect(old.UserSettings.fields.captureProxyEnabled).toEqual({ type: 'Boolean', column: 'capture_proxy_enabled' })
  })

  test('every 7.7.2 model still exists with the same table', () => {
    const lost = Object.entries(old)
      .filter(([name, m]) => now[name]?.table !== m.table)
      .map(([name, m]) => `${name} (${m.table})`)
    expect(lost).toEqual([])
  })

  test('every 7.7.2 model field still exists with the same type', () => {
    const changed: string[] = []
    for (const [name, m] of Object.entries(old)) {
      for (const [field, was] of Object.entries(m.fields)) {
        const is = now[name]?.fields[field]
        if (!is) changed.push(`${name}.${field} removed`)
        else if (is.type !== was.type || is.column !== was.column) {
          changed.push(`${name}.${field} ${was.type} ${was.column} -> ${is.type} ${is.column}`)
        }
      }
    }
    expect(changed).toEqual([])
  })

  test('a column added to a 7.7.2 table is nullable or has a default', () => {
    const unfillable: string[] = []
    for (const name of Object.keys(old)) {
      for (const [field, f] of Object.entries(now[name]?.fields ?? {})) {
        if (old[name].fields[field]) continue
        if (now[baseType(f.type)]) continue // a relation field: no column of its own
        const fillable = f.type.endsWith('?') || /@default\(|@updatedAt/.test(f.line)
        if (!fillable) unfillable.push(`${name}.${field}`)
      }
    }
    expect(unfillable).toEqual([])
  })
})
