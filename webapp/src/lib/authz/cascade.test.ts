/**
 * What deleting an account does to the identity tables of step 2.1, read from the
 * schema text (the real-database cascade runs in the upgrade harness):
 *   - an account's invite and reset links die with it, so no link outlives the account
 *     it would sign in as;
 *   - the instance row and the audit rows name accounts by plain id, never by foreign
 *     key: deleting an account must not be blocked by, nor cascade into, the instance
 *     settings or the append-only audit trail.
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

  test.each(['InstanceSettings', 'AuditLog', 'ActAsAudit'])('%s keeps no foreign key to an account', (model) => {
    const relations = Object.values(now[model]?.fields ?? {}).filter((f) => f.line.includes('@relation'))
    expect(now[model], `model ${model}`).toBeDefined()
    expect(relations).toEqual([])
  })
})
