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
