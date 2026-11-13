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
 * And what deleting an account or a project does to the sharing tables of step 4.2 (DV-10): a
 * share (`ProjectCollaborator`) and a break-glass row go with the project and with the account
 * they let in, so no access outlives either; the person who granted a share is a plain id, so a
 * share outlives the admin or owner who wrote it until the owner revokes it.
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

const cascadeOn = (key: string) =>
  new RegExp(`@relation\\(\\s*fields:\\s*\\[${key}\\],\\s*references:\\s*\\[id\\],\\s*onDelete:\\s*Cascade\\s*\\)`)

describe('deleting a project or an account (step 4.2)', () => {
  test.each([
    ['ProjectCollaborator', 'collaborators', 'collaborations'],
    ['ProjectBreakGlass', 'breakGlass', 'breakGlass'],
  ])('%s rows cascade with the project and with the user', (model, projectBack, userBack) => {
    const m = now[model]
    expect(m, `model ${model}`).toBeDefined()
    expect(m.fields.projectId).toMatchObject({ type: 'String', column: 'project_id' })
    expect(m.fields.project?.type).toBe('Project')
    expect(m.fields.project.line).toMatch(cascadeOn('projectId'))
    expect(m.fields.userId).toMatchObject({ type: 'String', column: 'user_id' })
    expect(m.fields.user?.type).toBe('User')
    expect(m.fields.user.line).toMatch(cascadeOn('userId'))
    expect(now.Project.fields[projectBack]?.type).toBe(`${model}[]`)
    expect(now.User.fields[userBack]?.type).toBe(`${model}[]`)
  })

  test.each(['ProjectCollaborator', 'ProjectBreakGlass'])('%s has no foreign key but its project and its account', (model) => {
    const relations = Object.entries(now[model]?.fields ?? {})
      .filter(([, f]) => f.line.includes('@relation'))
      .map(([name]) => name)
    expect(relations).toEqual(['project', 'user'])
  })

  test('a share names the person who granted it by plain id: it outlives that account', () => {
    expect(now.ProjectCollaborator.fields.grantedById).toMatchObject({ type: 'String', column: 'granted_by_id' })
    expect(now.ProjectCollaborator.fields.grantedById.line).not.toContain('@relation')
  })

  test('a token\'s project allowlist names projects by plain id: deleting a project leaves the token as it is', () => {
    const allowlist = now.McpAccessToken?.fields.projectAllowlist
    expect(allowlist).toMatchObject({ type: 'String[]', column: 'project_allowlist' })
    expect(Object.values(now.McpAccessToken.fields).filter((f) => f.type.replace(/\[\]$|\?$/, '') === 'Project')).toEqual([])
  })
})

// Step 6.10: a device session holds an address and a browser, personal data that must not outlive the
// account; the admin who revoked it is a plain id, so the record of the revocation outlives that admin.
describe('deleting an account: device sessions (step 6.10)', () => {
  test('UserSession rows cascade with the user; the revoker is no foreign key', () => {
    const session = now.UserSession
    expect(session, 'model UserSession').toBeDefined()
    expect(session.fields.user.line).toMatch(/@relation\(\s*fields:\s*\[userId\],\s*references:\s*\[id\],\s*onDelete:\s*Cascade\s*\)/)
    expect(now.User.fields.deviceSessions?.type).toBe('UserSession[]')
    expect(session.fields.revokedById).toMatchObject({ type: 'String?', column: 'revoked_by_id' })
    expect(session.fields.revokedById.line).not.toContain('@relation')
  })
})

// Step 6.11: an assignment goes with its instance provider and names its set by plain id (a built-in
// set has no row, and deleteSet refuses a set an assignment names); a usage row goes with its account.
describe('deleting a provider or an account: instance LLM providers (step 6.11)', () => {
  test('PermissionSetProvider rows cascade with the provider; the set and the author are no foreign key', () => {
    const assignment = now.PermissionSetProvider
    expect(assignment, 'model PermissionSetProvider').toBeDefined()
    expect(assignment.fields.provider.line).toMatch(/@relation\(\s*fields:\s*\[providerId\],\s*references:\s*\[id\],\s*onDelete:\s*Cascade\s*\)/)
    expect(now.InstanceLlmProvider.fields.sets?.type).toBe('PermissionSetProvider[]')
    for (const plain of ['setId', 'createdById']) expect(assignment.fields[plain].line).not.toContain('@relation')
  })

  test('QuotaUsage rows cascade with the user; an instance provider names its author by plain id', () => {
    expect(now.QuotaUsage.fields.user.line).toMatch(/@relation\(\s*fields:\s*\[userId\],\s*references:\s*\[id\],\s*onDelete:\s*Cascade\s*\)/)
    expect(now.User.fields.quotaUsage?.type).toBe('QuotaUsage[]')
    const provider = now.InstanceLlmProvider
    expect(Object.values(provider.fields).filter((f) => f.line.includes('@relation'))).toEqual([])
  })
})

// Step 5.6: a project's access policy goes with the project; the owner who consented is a plain id, so
// deleting that account neither blocks on nor cascades into the row (a transfer keeps the project).
describe('deleting a project or an account: the project access policy (step 5.6)', () => {
  test('ProjectAccessPolicy rows cascade with the project; the consenting person is no foreign key', () => {
    const policy = now.ProjectAccessPolicy
    expect(policy, 'model ProjectAccessPolicy').toBeDefined()
    expect(policy.fields.project.line).toMatch(/@relation\(\s*fields:\s*\[projectId\],\s*references:\s*\[id\],\s*onDelete:\s*Cascade\s*\)/)
    expect(now.Project.fields.accessPolicy?.type).toBe('ProjectAccessPolicy?')
    expect(policy.fields.ownerCredentialConsentById.line).not.toContain('@relation')
    expect(Object.entries(policy.fields).filter(([, f]) => f.line.includes('@relation')).map(([name]) => name)).toEqual(['project'])
  })
})
