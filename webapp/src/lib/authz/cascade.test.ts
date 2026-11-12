/**
 * What deleting an account does to the identity tables of step 2.1 and the permission
 * tables of step 3.3, read from the schema text (the real-database cascade runs in the
 * upgrade harness):
 *   - an account's invite and reset links die with it, so no link outlives the account
 *     it would sign in as; so do its permission set assignments and overrides (DV-10);
 *   - the instance row and the audit rows name accounts by plain id, never by foreign
 *     key: deleting an account must not be blocked by, nor cascade into, the instance
 *     settings or the append-only audit trail. A permission set and an override name the
 *     admin who wrote them the same way, so they outlive that admin;
 *   - an assignment names its set by plain id: `builtin:<slug>` has no row, and deleting a
 *     custom set leaves its assignments dangling, which resolution reads as No access
 *     (fail closed) rather than silently widening to the default.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/cascade.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import { parsePrismaModels } from './__testing__/prismaSchema'

const WEBAPP = path.resolve(__dirname, '../../..')
const now = parsePrismaModels(readFileSync(path.join(WEBAPP, 'prisma/schema.prisma'), 'utf8'))

describe('deleting an account', () => {
  test('UserInvite rows cascade with the user', () => {
    const invite = now.UserInvite
    expect(invite, 'model UserInvite').toBeDefined()
    expect(invite.fields.userId).toMatchObject({ type: 'String', column: 'user_id' })
    const relation = invite.fields.user
    expect(relation?.type).toBe('User')
    expect(relation.line).toMatch(/@relation\(\s*fields:\s*\[userId\],\s*references:\s*\[id\],\s*onDelete:\s*Cascade\s*\)/)
    expect(now.User.fields.invites?.type).toBe('UserInvite[]')
  })

  test.each(['InstanceSettings', 'AuditLog', 'ActAsAudit', 'PermissionSet'])('%s keeps no foreign key to an account', (model) => {
    const relations = Object.values(now[model]?.fields ?? {}).filter((f) => f.line.includes('@relation'))
    expect(now[model], `model ${model}`).toBeDefined()
    expect(relations).toEqual([])
  })

  test.each([
    ['UserPermissionSet', 'permissionSets'],
    ['UserPermissionOverride', 'permissionOverrides'],
  ])('%s rows cascade with the user', (model, backRelation) => {
    const m = now[model]
    expect(m, `model ${model}`).toBeDefined()
    expect(m.fields.userId).toMatchObject({ type: 'String', column: 'user_id' })
    expect(m.fields.user?.type).toBe('User')
    expect(m.fields.user.line).toMatch(/@relation\(\s*fields:\s*\[userId\],\s*references:\s*\[id\],\s*onDelete:\s*Cascade\s*\)/)
    expect(now.User.fields[backRelation]?.type).toBe(`${model}[]`)
  })

  test.each(['UserPermissionSet', 'UserPermissionOverride'])('%s has no foreign key but its account', (model) => {
    const relations = Object.entries(now[model]?.fields ?? {})
      .filter(([, f]) => f.line.includes('@relation'))
      .map(([name]) => name)
    expect(relations).toEqual(['user'])
  })

  test('an assignment names its set by plain id: no model points at PermissionSet', () => {
    const pointing = Object.entries(now)
      .flatMap(([name, m]) => Object.entries(m.fields).map(([f, def]) => [name, f, def.type] as const))
      .filter(([, , type]) => type.replace(/\[\]$|\?$/, '') === 'PermissionSet')
      .map(([name, f]) => `${name}.${f}`)
    expect(now.PermissionSet, 'model PermissionSet').toBeDefined()
    expect(pointing).toEqual([])
  })
})
