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

// Step 4.2: what the sharing step adds is new tables, back-relations (no column) and two token
// columns whose defaults read as the token's behaviour before (its owner's projects only).
describe('the sharing schema is additive (step 4.2)', () => {
  test('the sharing tables are new: no 7.7.2 table is reused', () => {
    expect(old.ProjectCollaborator).toBeUndefined()
    expect(old.ProjectBreakGlass).toBeUndefined()
    const tables = Object.values(old).map((m) => m.table)
    expect(tables).not.toContain('project_collaborators')
    expect(tables).not.toContain('project_break_glass')
  })

  test('the token columns are new and filled by their defaults on every existing row', () => {
    expect(old.McpAccessToken.fields.includeSharedProjects).toBeUndefined()
    expect(old.McpAccessToken.fields.projectAllowlist).toBeUndefined()
    expect(now.McpAccessToken.fields.includeSharedProjects.line).toMatch(/@default\(false\)/)
    expect(now.McpAccessToken.fields.projectAllowlist.line).toMatch(/@default\(\[\]\)/)
  })

  test('Project and User gain relation fields only, never a column', () => {
    for (const [model, fields] of [['Project', ['collaborators', 'breakGlass']], ['User', ['collaborations', 'breakGlass']]] as const) {
      for (const f of fields) {
        expect(old[model].fields[f], `${model}.${f}`).toBeUndefined()
        expect(now[baseType(now[model].fields[f].type)], `${model}.${f} is a relation`).toBeDefined()
      }
    }
  })
})

// Step 6.9: the allowlist is one new table and nothing else: no 7.7.2 table or column changes.
describe('the plugin allowlist schema is additive (step 6.9)', () => {
  test('plugin_access_rules is new: no 7.7.2 table is reused', () => {
    expect(old.PluginAccessRule).toBeUndefined()
    expect(Object.values(old).map((m) => m.table)).not.toContain('plugin_access_rules')
  })
})

// Step 6.10: device sessions are one new table and a back-relation on User (no column).
describe('the device sessions schema is additive (step 6.10)', () => {
  test('user_sessions is new: no 7.7.2 table is reused', () => {
    expect(old.UserSession).toBeUndefined()
    expect(Object.values(old).map((m) => m.table)).not.toContain('user_sessions')
  })

  test('User gains a relation field only, never a column', () => {
    expect(old.User.fields.deviceSessions).toBeUndefined()
    expect(now[baseType(now.User.fields.deviceSessions.type)]).toBeDefined()
  })
})

// Step 6.11: three new tables, a back-relation on User and one InstanceSettings column with a default.
describe('the instance LLM providers schema is additive (step 6.11)', () => {
  test.each([
    ['InstanceLlmProvider', 'instance_llm_providers'],
    ['PermissionSetProvider', 'permission_set_providers'],
    ['QuotaUsage', 'quota_usage'],
  ])('%s is new: no 7.7.2 table is reused (%s)', (model, table) => {
    expect(old[model]).toBeUndefined()
    expect(Object.values(old).map((m) => m.table)).not.toContain(table)
  })

  test('User gains a relation field only, never a column; byoLlmForbidden is new with a default', () => {
    expect(old.User.fields.quotaUsage).toBeUndefined()
    expect(now[baseType(now.User.fields.quotaUsage.type)]).toBeDefined()
    expect(old.InstanceSettings?.fields.byoLlmForbidden).toBeUndefined()
    expect(now.InstanceSettings.fields.byoLlmForbidden.line).toContain('@default(false)')
  })
})

// Step 5.5: one nullable column on a 7.7.2 table.
describe('the schedule pause reason is additive (step 5.5)', () => {
  test('ScanSchedule.pausedReason is new and nullable; the 7.7.2 schedule columns are untouched', () => {
    expect(old.ScanSchedule.fields.pausedReason).toBeUndefined()
    expect(now.ScanSchedule.fields.pausedReason.type).toBe('String?')
    for (const [name, was] of Object.entries(old.ScanSchedule.fields)) {
      expect({ name, type: now.ScanSchedule.fields[name]?.type, column: now.ScanSchedule.fields[name]?.column })
        .toEqual({ name, type: was.type, column: was.column })
    }
  })
})

// Step 5.6: a new table; Project gains a relation field only, never a column (DV-16).
describe('the project access policy is additive (step 5.6)', () => {
  test('ProjectAccessPolicy is new: no 7.7.2 table is reused (project_access_policies)', () => {
    expect(old.ProjectAccessPolicy).toBeUndefined()
    expect(Object.values(old).map((m) => m.table)).not.toContain('project_access_policies')
  })

  test('Project gains the accessPolicy relation field only; its 7.7.2 columns are untouched', () => {
    expect(old.Project.fields.accessPolicy).toBeUndefined()
    expect(now[baseType(now.Project.fields.accessPolicy.type)]).toBeDefined()
    for (const [name, was] of Object.entries(old.Project.fields)) {
      expect({ name, type: now.Project.fields[name]?.type, column: now.Project.fields[name]?.column })
        .toEqual({ name, type: was.type, column: was.column })
    }
  })
})

// Step 6.6: one nullable column on the instance settings row (a table the RBAC plan added in 2.1).
describe('the audit retention pending change is additive (step 6.6)', () => {
  test('InstanceSettings.auditRetentionPending is nullable with no default: the existing row reads null', () => {
    expect(old.InstanceSettings).toBeUndefined()
    expect(now.InstanceSettings.fields.auditRetentionPending.type).toBe('Json?')
    expect(now.InstanceSettings.fields.auditRetentionPending.line).not.toContain('@default')
  })
})
