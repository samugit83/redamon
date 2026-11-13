/**
 * The identity schema of RBAC step 2.1 (phase_02 "Design"), and the naming every table
 * and column added since 7.7.2 follows: snake_case, as the rest of the schema. The
 * shell harnesses (`tests/rbac_upgrade_live.sh`, `tests/rbac_scripts_db_test.sh`) and
 * the host scripts query these tables by their SQL names.
 *
 * Existing rows must read as today's behaviour once `db push` adds the columns: every
 * account active, session version 0, no forced password change, no notices.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/schemaMaps.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import { parsePrismaModels, baseType } from './__testing__/prismaSchema'
import release from './__fixtures__/schema-7.7.2-fields.json'

const WEBAPP = path.resolve(__dirname, '../../..')
const now = parsePrismaModels(readFileSync(path.join(WEBAPP, 'prisma/schema.prisma'), 'utf8'))
const old = (release as { models: Record<string, { fields: Record<string, unknown> }> }).models

const snake = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
const isRelation = (type: string) => Boolean(now[baseType(type)])

function field(model: string, name: string) {
  const f = now[model]?.fields[name]
  if (!f) throw new Error(`${model}.${name} is not in schema.prisma`)
  return f
}

describe('naming of what was added since 7.7.2', () => {
  test('every new model and field has a snake_case map', () => {
    const wrong: string[] = []
    for (const [name, m] of Object.entries(now)) {
      const known = old[name]
      if (!known && (m.table === name || !/^[a-z][a-z0-9_]*$/.test(m.table))) wrong.push(`model ${name} -> ${m.table}`)
      for (const [fieldName, f] of Object.entries(m.fields)) {
        if (known?.fields[fieldName] || isRelation(f.type)) continue
        if (f.column !== snake(fieldName)) wrong.push(`${name}.${fieldName} -> ${f.column}`)
      }
    }
    expect(wrong).toEqual([])
  })
})

describe('the identity schema (step 2.1)', () => {
  test.each([
    ['User', 'status', 'String', 'status'],
    ['User', 'sessionVersion', 'Int', 'session_version'],
    ['User', 'mustChangePassword', 'Boolean', 'must_change_password'],
    ['User', 'lastLoginAt', 'DateTime?', 'last_login_at'],
    ['User', 'adminProfileId', 'String?', 'admin_profile_id'],
    ['User', 'passwordOnHold', 'String', 'password_on_hold'],
    ['User', 'pendingNotices', 'Json', 'pending_notices'],
    ['AuditLog', 'onBehalfOfUserId', 'String?', 'on_behalf_of_user_id'],
    ['AuditLog', 'projectId', 'String?', 'project_id'],
    ['AuditLog', 'permission', 'String?', 'permission'],
    ['AuditLog', 'actorEmail', 'String?', 'actor_email'],
    ['ActAsAudit', 'reason', 'String?', 'reason'],
    ['ActAsAudit', 'durationMinutes', 'Int?', 'duration_minutes'],
    ['ActAsAudit', 'endedBy', 'String?', 'ended_by'],
  ])('%s.%s is %s in column %s', (model, name, type, column) => {
    expect(field(model, name)).toMatchObject({ type, column })
  })

  test('existing accounts read as active, version 0, no forced change, nothing on hold, no notices', () => {
    expect(field('User', 'status').line).toContain('@default("active")')
    expect(field('User', 'sessionVersion').line).toContain('@default(0)')
    expect(field('User', 'mustChangePassword').line).toContain('@default(false)')
    expect(field('User', 'passwordOnHold').line).toContain('@default("")')
    expect(field('User', 'pendingNotices').line).toContain('@default("[]")')
  })

  test('the new tables map to instance_settings and user_invites', () => {
    expect(now.InstanceSettings?.table).toBe('instance_settings')
    expect(now.UserInvite?.table).toBe('user_invites')
  })

  test('audit rows are indexed by project and time', () => {
    expect(now.AuditLog.blockAttributes).toContain('@@index([projectId, createdAt])')
    expect(now.AuditLog.blockAttributes).toContain('@@index([actorId, createdAt])')
  })

  test('InstanceSettings is one row, id "instance"', () => {
    expect(field('InstanceSettings', 'id').line).toMatch(/@id\s+@default\("instance"\)/)
  })

  test.each([
    ['passwordMinLength', 'Int', '12'],
    ['passwordAskChangeIfShort', 'Boolean', 'false'],
    ['memberSessionTtlHours', 'Int', '168'],
    ['adminSessionTtlHours', 'Int', '12'],
    ['adminIdleMinutes', 'Int', '60'],
    ['inviteTtlHours', 'Int', '168'],
    ['resetTtlHours', 'Int', '4'],
    ['impersonationMaxMinutes', 'Int', '720'],
    ['impersonationReasonRequired', 'Boolean', 'false'],
    ['impersonationNotifyTarget', 'Boolean', 'true'],
    ['sharingPolicy', 'Json', '"{}"'],
    ['directoryVisible', 'Boolean', 'false'],
    ['quotas', 'Json', '"{}"'],
  ])('InstanceSettings.%s is %s, default %s', (name, type, def) => {
    const f = field('InstanceSettings', name)
    expect(f.type).toBe(type)
    expect(f.line).toContain(`@default(${def})`)
  })

  test.each([
    'rootUserId', 'rootConfirmedAt', 'rootAssignedBy', 'pendingRootTransferTo', 'pendingRootTransferExpires',
    'publicBaseUrl', 'defaultMemberSetId', 'auditRetentionDays', 'tunnelSourceUserId', 'captureSourceUserId',
    'updatedById',
  ])('InstanceSettings.%s is nullable (unset until someone sets it)', (name) => {
    expect(field('InstanceSettings', name).type).toMatch(/\?$/)
  })

  // T12: the tunnel, capture, egress and SCA settings move out of the user rows. The
  // backfill copies each value as it is, so each field must be the same column with the
  // same type and the same default as its UserSettings original.
  test('the moved settings copy their UserSettings fields exactly', () => {
    const moved = Object.entries(now.UserSettings.fields).filter(([name]) =>
      /^(tunnelsEnabled|ngrokAuthtoken|chiselServerUrl|chiselAuth|captureProxy\w+|captureEgress\w+|scaIntelIgnoreSuffixes)$/.test(name),
    )
    expect(moved.length).toBe(4 + 12 + 11 + 1)
    const defaultOf = (line: string) => line.match(/@default\(([^)]*)\)/)?.[1] ?? null
    const drift = moved
      .filter(([name, f]) => {
        const copy = now.InstanceSettings?.fields[name]
        return !copy || copy.type !== f.type || copy.column !== f.column || defaultOf(copy.line) !== defaultOf(f.line)
      })
      .map(([name]) => name)
    expect(drift).toEqual([])
  })

  test('UserInvite holds a kind, a unique token hash, an expiry and its outcome', () => {
    expect(field('UserInvite', 'kind').type).toBe('String')
    expect(field('UserInvite', 'tokenHash')).toMatchObject({ type: 'String', column: 'token_hash' })
    expect(field('UserInvite', 'tokenHash').line).toContain('@unique')
    expect(field('UserInvite', 'expiresAt').type).toBe('DateTime')
    expect(field('UserInvite', 'usedAt').type).toBe('DateTime?')
    expect(field('UserInvite', 'cancelledAt').type).toBe('DateTime?')
    expect(field('UserInvite', 'createdById').type).toBe('String')
    expect(field('UserInvite', 'reason').type).toBe('String?')
    expect(now.UserInvite.blockAttributes).toContain('@@index([userId, kind])')
  })
})

// Step 3.3 (phase_03): where a member's permission sets and overrides are kept. No row
// exists after the upgrade, so every account resolves to its account type's default.
describe('the permission schema (step 3.3)', () => {
  const columnsOf = (model: string) =>
    Object.entries(now[model]?.fields ?? {}).filter(([, f]) => !isRelation(f.type)).map(([name]) => name)

  test('the new tables map to permission_sets, user_permission_sets and user_permission_overrides', () => {
    expect(now.PermissionSet?.table).toBe('permission_sets')
    expect(now.UserPermissionSet?.table).toBe('user_permission_sets')
    expect(now.UserPermissionOverride?.table).toBe('user_permission_overrides')
  })

  test.each([
    ['PermissionSet', 'id', 'String', 'id'],
    ['PermissionSet', 'kind', 'String', 'kind'],
    ['PermissionSet', 'name', 'String', 'name'],
    ['PermissionSet', 'description', 'String?', 'description'],
    ['PermissionSet', 'permissions', 'String[]', 'permissions'],
    ['PermissionSet', 'clonedFrom', 'String?', 'cloned_from'],
    ['PermissionSet', 'createdById', 'String', 'created_by_id'],
    ['PermissionSet', 'createdAt', 'DateTime', 'created_at'],
    ['PermissionSet', 'updatedAt', 'DateTime', 'updated_at'],
    ['UserPermissionSet', 'userId', 'String', 'user_id'],
    ['UserPermissionSet', 'setId', 'String', 'set_id'],
    ['UserPermissionSet', 'createdAt', 'DateTime', 'created_at'],
    ['UserPermissionOverride', 'userId', 'String', 'user_id'],
    ['UserPermissionOverride', 'permission', 'String', 'permission'],
    ['UserPermissionOverride', 'effect', 'String', 'effect'],
    ['UserPermissionOverride', 'expiresAt', 'DateTime?', 'expires_at'],
    ['UserPermissionOverride', 'reason', 'String?', 'reason'],
    ['UserPermissionOverride', 'grantedById', 'String', 'granted_by_id'],
    ['UserPermissionOverride', 'createdAt', 'DateTime', 'created_at'],
  ])('%s.%s is %s in column %s', (model, name, type, column) => {
    expect(field(model, name)).toMatchObject({ type, column })
  })

  test('each table holds exactly these columns', () => {
    expect(columnsOf('PermissionSet')).toEqual([
      'id', 'kind', 'name', 'description', 'permissions', 'clonedFrom', 'createdById', 'createdAt', 'updatedAt',
    ])
    expect(columnsOf('UserPermissionSet')).toEqual(['userId', 'setId', 'createdAt'])
    expect(columnsOf('UserPermissionOverride')).toEqual([
      'userId', 'permission', 'effect', 'expiresAt', 'reason', 'grantedById', 'createdAt',
    ])
  })

  test('a set has a generated id and a unique name; the database keeps the times', () => {
    expect(field('PermissionSet', 'id').line).toMatch(/@id\s+@default\(cuid\(\)\)/)
    expect(field('PermissionSet', 'name').line).toContain('@unique')
    expect(field('PermissionSet', 'createdAt').line).toContain('@default(now())')
    expect(field('PermissionSet', 'updatedAt').line).toContain('@updatedAt')
    expect(field('UserPermissionSet', 'createdAt').line).toContain('@default(now())')
    expect(field('UserPermissionOverride', 'createdAt').line).toContain('@default(now())')
  })

  test('one assignment per account and set, one override per account and permission', () => {
    expect(now.UserPermissionSet.blockAttributes).toContain('@@id([userId, setId])')
    expect(now.UserPermissionOverride.blockAttributes).toContain('@@id([userId, permission])')
  })

  test('an account reaches its assignments and overrides', () => {
    expect(field('User', 'permissionSets').type).toBe('UserPermissionSet[]')
    expect(field('User', 'permissionOverrides').type).toBe('UserPermissionOverride[]')
  })

  // PE-30 (D-20): one admin profile per admin is the single nullable column of step 2.1,
  // never a list or a join table; the instance default set is the settings row's.
  test('an admin keeps one profile in User.adminProfileId; the step adds no column to users or the settings row', () => {
    expect(field('User', 'adminProfileId')).toMatchObject({ type: 'String?', column: 'admin_profile_id' })
    expect(field('InstanceSettings', 'defaultMemberSetId')).toMatchObject({ type: 'String?', column: 'default_member_set_id' })
    const profileHolders = Object.entries(now)
      .filter(([name, m]) => name !== 'User' && Object.keys(m.fields).some((f) => /adminProfile/i.test(f)))
      .map(([name]) => name)
    expect(profileHolders).toEqual([])
    const userPermissionFields = Object.keys(now.User.fields).filter((f) => /permission/i.test(f))
    expect(userPermissionFields).toEqual(['permissionSets', 'permissionOverrides'])
  })
})

// Step 4.2 (phase_04): where a share and a break-glass access are kept, and a token's opt-in to
// shared projects. No row exists after the upgrade and every token reads as before (its owner's
// projects only), so nothing changes until an owner shares and a person opts a token in.
describe('the sharing schema (step 4.2)', () => {
  const columnsOf = (model: string) =>
    Object.entries(now[model]?.fields ?? {}).filter(([, f]) => !isRelation(f.type)).map(([name]) => name)

  test('the new tables map to project_collaborators and project_break_glass', () => {
    expect(now.ProjectCollaborator?.table).toBe('project_collaborators')
    expect(now.ProjectBreakGlass?.table).toBe('project_break_glass')
  })

  test.each([
    ['ProjectCollaborator', 'projectId', 'String', 'project_id'],
    ['ProjectCollaborator', 'userId', 'String', 'user_id'],
    ['ProjectCollaborator', 'access', 'String', 'access'],
    ['ProjectCollaborator', 'runScans', 'Boolean', 'run_scans'],
    ['ProjectCollaborator', 'useAgent', 'Boolean', 'use_agent'],
    ['ProjectCollaborator', 'exploit', 'Boolean', 'exploit'],
    ['ProjectCollaborator', 'rawData', 'Boolean', 'raw_data'],
    ['ProjectCollaborator', 'manage', 'Boolean', 'manage'],
    ['ProjectCollaborator', 'expiresAt', 'DateTime?', 'expires_at'],
    ['ProjectCollaborator', 'note', 'String?', 'note'],
    ['ProjectCollaborator', 'grantedById', 'String', 'granted_by_id'],
    ['ProjectCollaborator', 'createdAt', 'DateTime', 'created_at'],
    ['ProjectCollaborator', 'updatedAt', 'DateTime', 'updated_at'],
    ['ProjectBreakGlass', 'id', 'String', 'id'],
    ['ProjectBreakGlass', 'projectId', 'String', 'project_id'],
    ['ProjectBreakGlass', 'userId', 'String', 'user_id'],
    ['ProjectBreakGlass', 'reason', 'String', 'reason'],
    ['ProjectBreakGlass', 'expiresAt', 'DateTime', 'expires_at'],
    ['ProjectBreakGlass', 'createdAt', 'DateTime', 'created_at'],
    ['McpAccessToken', 'includeSharedProjects', 'Boolean', 'include_shared_projects'],
    ['McpAccessToken', 'projectAllowlist', 'String[]', 'project_allowlist'],
  ])('%s.%s is %s in column %s', (model, name, type, column) => {
    expect(field(model, name)).toMatchObject({ type, column })
  })

  test('each table holds exactly these columns', () => {
    expect(columnsOf('ProjectCollaborator')).toEqual([
      'projectId', 'userId', 'access', 'runScans', 'useAgent', 'exploit', 'rawData', 'manage', 'expiresAt', 'note',
      'grantedById', 'createdAt', 'updatedAt',
    ])
    expect(columnsOf('ProjectBreakGlass')).toEqual(['id', 'projectId', 'userId', 'reason', 'expiresAt', 'createdAt'])
  })

  test('a share grants nothing beyond its level until an owner says so: every toggle defaults to false', () => {
    for (const toggle of ['runScans', 'useAgent', 'exploit', 'rawData', 'manage']) {
      expect(field('ProjectCollaborator', toggle).line, toggle).toContain('@default(false)')
    }
    expect(field('ProjectCollaborator', 'access').line).not.toContain('@default')
    expect(field('ProjectCollaborator', 'createdAt').line).toContain('@default(now())')
    expect(field('ProjectCollaborator', 'updatedAt').line).toContain('@updatedAt')
    expect(field('ProjectBreakGlass', 'id').line).toMatch(/@id\s+@default\(cuid\(\)\)/)
    expect(field('ProjectBreakGlass', 'createdAt').line).toContain('@default(now())')
  })

  test('one share per project and account; shares found by account, break-glass rows by project and account', () => {
    expect(now.ProjectCollaborator.blockAttributes).toContain('@@id([projectId, userId])')
    expect(now.ProjectCollaborator.blockAttributes).toContain('@@index([userId])')
    expect(now.ProjectBreakGlass.blockAttributes).toContain('@@index([projectId, userId])')
  })

  test('existing tokens keep reaching only their owner\'s projects: not opted in, no allowlist', () => {
    expect(field('McpAccessToken', 'includeSharedProjects').line).toContain('@default(false)')
    expect(field('McpAccessToken', 'projectAllowlist').line).toContain('@default([])')
  })

  test('a project and an account reach their shares and break-glass rows', () => {
    expect(field('Project', 'collaborators').type).toBe('ProjectCollaborator[]')
    expect(field('Project', 'breakGlass').type).toBe('ProjectBreakGlass[]')
    expect(field('User', 'collaborations').type).toBe('ProjectCollaborator[]')
    expect(field('User', 'breakGlass').type).toBe('ProjectBreakGlass[]')
  })

  // The policy column exists since step 2.4; 4.2 defines its shape (src/lib/authz/sharingPolicy.ts)
  // and adds no instance column (DV-16: the back-relations are not Project columns either).
  test('the instance row gains no column: the sharing policy is the existing JSON column', () => {
    expect(field('InstanceSettings', 'sharingPolicy')).toMatchObject({ type: 'Json', column: 'sharing_policy' })
    expect(Object.keys(now.InstanceSettings.fields).filter((f) => /shar|collab|breakGlass/i.test(f))).toEqual(['sharingPolicy'])
  })
})

// Step 6.9 (phase_06): the per-plugin allowlist. The table arrives empty, and a plugin with no rule
// is available as before, so nothing changes until an admin limits a plugin.
describe('the plugin allowlist schema (step 6.9)', () => {
  const columnsOf = (model: string) =>
    Object.entries(now[model]?.fields ?? {}).filter(([, f]) => !isRelation(f.type)).map(([name]) => name)

  test('the new table maps to plugin_access_rules', () => {
    expect(now.PluginAccessRule?.table).toBe('plugin_access_rules')
  })

  test.each([
    ['PluginAccessRule', 'pluginId', 'String', 'plugin_id'],
    ['PluginAccessRule', 'setId', 'String', 'set_id'],
    ['PluginAccessRule', 'createdById', 'String', 'created_by_id'],
    ['PluginAccessRule', 'createdAt', 'DateTime', 'created_at'],
  ])('%s.%s is %s in column %s', (model, name, type, column) => {
    expect(field(model, name)).toMatchObject({ type, column })
  })

  test('the table holds exactly these columns, one rule per plugin and set, found by set', () => {
    expect(columnsOf('PluginAccessRule')).toEqual(['pluginId', 'setId', 'createdById', 'createdAt'])
    expect(now.PluginAccessRule.blockAttributes).toContain('@@id([pluginId, setId])')
    expect(now.PluginAccessRule.blockAttributes).toContain('@@index([setId])')
    expect(field('PluginAccessRule', 'createdAt').line).toContain('@default(now())')
  })

  // T7: a set id may be a built-in (code, no row); a plugin id is the catalog's, kept across an
  // uninstall. No relation means no cascade can drop a rule, and no model gains a back-relation.
  test('no foreign key: no relation field on the rule, none pointing at it', () => {
    expect(Object.values(now.PluginAccessRule.fields).filter((f) => isRelation(f.type))).toEqual([])
    const pointing = Object.entries(now)
      .filter(([, m]) => Object.values(m.fields).some((f) => baseType(f.type) === 'PluginAccessRule'))
      .map(([name]) => name)
    expect(pointing).toEqual([])
  })
})

// Step 6.10 (phase_06): device sessions. The table arrives empty, a row is written only at a sign-in
// with RBAC_GOVERNANCE_ENABLED on, and a login token without `sid` stays valid, so nothing changes for
// an existing session.
describe('the device sessions schema (step 6.10)', () => {
  const columnsOf = (model: string) =>
    Object.entries(now[model]?.fields ?? {}).filter(([, f]) => !isRelation(f.type)).map(([name]) => name)

  test('the new table maps to user_sessions', () => {
    expect(now.UserSession?.table).toBe('user_sessions')
  })

  test.each([
    ['UserSession', 'id', 'String', 'id'],
    ['UserSession', 'userId', 'String', 'user_id'],
    ['UserSession', 'sessionVersion', 'Int', 'session_version'],
    ['UserSession', 'createdAt', 'DateTime', 'created_at'],
    ['UserSession', 'lastSeenAt', 'DateTime', 'last_seen_at'],
    ['UserSession', 'expiresAt', 'DateTime', 'expires_at'],
    ['UserSession', 'ip', 'String?', 'ip'],
    ['UserSession', 'ipTrusted', 'Boolean', 'ip_trusted'],
    ['UserSession', 'userAgent', 'String?', 'user_agent'],
    ['UserSession', 'revokedAt', 'DateTime?', 'revoked_at'],
    ['UserSession', 'revokedById', 'String?', 'revoked_by_id'],
    ['UserSession', 'endedBy', 'String?', 'ended_by'],
  ])('%s.%s is %s in column %s', (model, name, type, column) => {
    expect(field(model, name)).toMatchObject({ type, column })
  })

  test('the table holds exactly these columns, found by account and by the two sweep dates', () => {
    expect(columnsOf('UserSession')).toEqual([
      'id', 'userId', 'sessionVersion', 'createdAt', 'lastSeenAt', 'expiresAt', 'ip', 'ipTrusted', 'userAgent',
      'revokedAt', 'revokedById', 'endedBy',
    ])
    expect(field('UserSession', 'id').line).toMatch(/@id\s+@default\(cuid\(\)\)/)
    expect(field('UserSession', 'createdAt').line).toContain('@default(now())')
    expect(field('UserSession', 'lastSeenAt').line).toContain('@default(now())')
    expect(field('UserSession', 'ipTrusted').line).toContain('@default(false)')
    for (const index of ['@@index([userId])', '@@index([expiresAt])', '@@index([revokedAt])']) {
      expect(now.UserSession.blockAttributes).toContain(index)
    }
  })

  // The address and browser are personal data: they go with the account (and with the row, which
  // the sweep deletes 30 days after it ended). The revoking admin is a plain id, so deleting that
  // admin keeps the record of the revocation.
  test('a session goes with its account; the revoker is no foreign key', () => {
    expect(field('UserSession', 'user')).toMatchObject({ type: 'User' })
    expect(field('UserSession', 'user').line).toContain('onDelete: Cascade')
    expect(field('User', 'deviceSessions').type).toBe('UserSession[]')
    expect(Object.values(now.UserSession.fields).filter((f) => isRelation(f.type)).map((f) => f.type)).toEqual(['User'])
  })
})

// Step 6.11 (phase_06): instance LLM providers, their assignments to permission sets, the daily usage
// a budget counts, and the bring-your-own policy. The tables arrive empty and the policy off, so no
// provider is offered and every account keeps its own providers until Root changes something.
describe('the instance LLM providers schema (step 6.11)', () => {
  const columnsOf = (model: string) =>
    Object.entries(now[model]?.fields ?? {}).filter(([, f]) => !isRelation(f.type)).map(([name]) => name)

  test('the new tables map to instance_llm_providers, permission_set_providers and quota_usage', () => {
    expect(now.InstanceLlmProvider?.table).toBe('instance_llm_providers')
    expect(now.PermissionSetProvider?.table).toBe('permission_set_providers')
    expect(now.QuotaUsage?.table).toBe('quota_usage')
  })

  // The provider row is the user provider row without its account: the same columns, types and
  // defaults, so the agent builds both the same way (llm_builder.instance_build_args).
  test('an instance provider has the user provider columns, without the account', () => {
    const userColumns = columnsOf('UserLlmProvider').filter((c) => c !== 'userId')
    expect(columnsOf('InstanceLlmProvider')).toEqual(userColumns)
    for (const name of userColumns) {
      const mine = field('InstanceLlmProvider', name)
      const theirs = field('UserLlmProvider', name)
      expect(mine.type, name).toBe(theirs.type)
      expect(mine.column, name).toBe(theirs.column)
      expect(mine.line.match(/@default\([^)]*\)+/)?.[0] ?? null, name).toBe(theirs.line.match(/@default\([^)]*\)+/)?.[0] ?? null)
    }
    expect(field('InstanceLlmProvider', 'id').line).toMatch(/@id\s+@default\(cuid\(\)\)/)
  })

  test.each([
    ['PermissionSetProvider', 'setId', 'String', 'set_id'],
    ['PermissionSetProvider', 'providerId', 'String', 'provider_id'],
    ['PermissionSetProvider', 'createdById', 'String?', 'created_by_id'],
    ['PermissionSetProvider', 'createdAt', 'DateTime', 'created_at'],
    ['QuotaUsage', 'userId', 'String', 'user_id'],
    ['QuotaUsage', 'day', 'DateTime', 'day'],
    ['QuotaUsage', 'kind', 'String', 'kind'],
    ['QuotaUsage', 'count', 'Int', 'count'],
    ['QuotaUsage', 'updatedAt', 'DateTime', 'updated_at'],
  ])('%s.%s is %s in column %s', (model, name, type, column) => {
    expect(field(model, name)).toMatchObject({ type, column })
  })

  test('one assignment per set and provider, found by provider; one usage row per account, day and kind', () => {
    expect(columnsOf('PermissionSetProvider')).toEqual(['setId', 'providerId', 'createdById', 'createdAt'])
    expect(now.PermissionSetProvider.blockAttributes).toContain('@@id([setId, providerId])')
    expect(now.PermissionSetProvider.blockAttributes).toContain('@@index([providerId])')
    expect(columnsOf('QuotaUsage')).toEqual(['userId', 'day', 'kind', 'count', 'updatedAt'])
    expect(now.QuotaUsage.blockAttributes).toContain('@@id([userId, day, kind])')
    expect(now.QuotaUsage.blockAttributes).toContain('@@index([day])')
    expect(field('QuotaUsage', 'day').line).toContain('@db.Date')
    expect(field('QuotaUsage', 'count').line).toContain('@default(0)')
  })

  test('InstanceSettings.byoLlmForbidden is Boolean, default false (every account keeps its own providers)', () => {
    expect(field('InstanceSettings', 'byoLlmForbidden')).toMatchObject({ type: 'Boolean', column: 'byo_llm_forbidden' })
    expect(field('InstanceSettings', 'byoLlmForbidden').line).toContain('@default(false)')
  })

  // T7: a set id may be a built-in (code, no row), so an assignment names it by plain id; it goes with
  // its provider. A usage row goes with its account. Nothing else points at the new tables.
  test('the relations: an assignment with its provider, usage with its account, no foreign key to a set', () => {
    expect(Object.values(now.PermissionSetProvider.fields).filter((f) => isRelation(f.type)).map((f) => f.type)).toEqual(['InstanceLlmProvider'])
    expect(field('InstanceLlmProvider', 'sets').type).toBe('PermissionSetProvider[]')
    expect(Object.values(now.QuotaUsage.fields).filter((f) => isRelation(f.type)).map((f) => f.type)).toEqual(['User'])
    expect(field('User', 'quotaUsage').type).toBe('QuotaUsage[]')
    const pointing = (target: string) => Object.entries(now)
      .filter(([, m]) => Object.values(m.fields).some((f) => baseType(f.type) === target))
      .map(([name]) => name)
    expect(pointing('InstanceLlmProvider')).toEqual(['PermissionSetProvider'])
    expect(pointing('PermissionSetProvider')).toEqual(['InstanceLlmProvider'])
    expect(pointing('QuotaUsage')).toEqual(['User'])
  })
})
