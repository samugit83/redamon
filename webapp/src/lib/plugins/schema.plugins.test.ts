/**
 * The plugin tables as declared in schema.prisma, and the boot order that applies
 * their constraints. The real-database behaviour (cascades, the one-active index,
 * the CHECK constraints) is proved by tests/plugins_db_test.sh; this pins the text
 * that produces it, so a careless edit fails here first.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

const WEBAPP = path.resolve(__dirname, '../../..')
const schema = readFileSync(path.join(WEBAPP, 'prisma/schema.prisma'), 'utf8')
const dockerfile = readFileSync(path.join(WEBAPP, 'Dockerfile'), 'utf8')
const script = readFileSync(path.join(WEBAPP, 'scripts/apply-plugin-constraints.mjs'), 'utf8')

function model(name: string): string {
  const m = schema.match(new RegExp(`^model ${name} \\{([\\s\\S]*?)^\\}`, 'm'))
  if (!m) throw new Error(`model ${name} not found in schema.prisma`)
  return m[1]
}

const PLUGIN_MODELS = {
  PluginInstall: 'plugin_installs',
  PluginData: 'plugin_data',
  PluginOverride: 'plugin_overrides',
  PluginPlatformState: 'plugin_platform_state',
}

describe('the four plugin platform models', () => {
  test.each(Object.entries(PLUGIN_MODELS))('%s maps to %s', (name, table) => {
    expect(model(name)).toContain(`@@map("${table}")`)
  })

  test('every relation of a plugin model cascades', () => {
    const relations = Object.keys(PLUGIN_MODELS).flatMap((name) =>
      model(name).split('\n').filter((l) => l.includes('@relation(')),
    )
    // PluginData and PluginOverride: plugin, user, project each.
    expect(relations).toHaveLength(6)
    for (const line of relations) expect(line).toContain('onDelete: Cascade')
  })

  test('plugin data is unique per plugin, namespace, owner, collection and key', () => {
    expect(model('PluginData')).toContain(
      '@@unique([pluginId, namespace, ownerType, ownerId, collection, key])',
    )
  })

  test('the people who installed, proposed or decided are plain strings, not foreign keys', () => {
    for (const [m, field] of [
      ['PluginInstall', 'installedBy'],
      ['PluginOverride', 'createdBy'],
      ['PluginOverride', 'decidedBy'],
    ]) {
      const line = model(m).split('\n').find((l) => l.trim().startsWith(`${field} `))
      expect(line, `${m}.${field}`).toBeDefined()
      expect(line).not.toContain('@relation')
    }
  })

  test.each(['User', 'Project'])('%s owns the plugin rows that must die with it', (owner) => {
    const body = model(owner)
    expect(body).toMatch(/^\s+pluginData\s+PluginData\[\]$/m)
    expect(body).toMatch(/^\s+pluginOverrides\s+PluginOverride\[\]$/m)
  })

  // Postgres does not index a foreign key by itself; without these, deleting one user or
  // project scans the whole plugin table for rows to cascade.
  test.each([
    ['PluginData', ['userId', 'projectId']],
    ['PluginOverride', ['pluginId', 'userId', 'projectId']],
  ])('%s indexes its foreign keys', (m, cols) => {
    for (const c of cols) expect(model(m)).toMatch(new RegExp(`@@(index|unique)\\(\\[${c}[,\\]]`))
  })

  test('revokedReason exists and enabled defaults to false', () => {
    const body = model('PluginInstall')
    expect(body).toMatch(/^\s+revokedReason\s+String\?/m)
    expect(body).toMatch(/^\s+enabled\s+Boolean\s+@default\(false\)/m)
  })
})

describe('the constraint script', () => {
  test('runs from the entrypoint after db push and after the engagement trigger', () => {
    const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))
    expect(entry).toBeDefined()
    const push = entry!.indexOf('db push')
    const engagement = entry!.indexOf('apply-engagement-immutability.mjs')
    const plugins = entry!.indexOf('apply-plugin-constraints.mjs')
    expect(push).toBeGreaterThan(-1)
    expect(plugins).toBeGreaterThan(engagement)
    expect(engagement).toBeGreaterThan(push)
    // Not fatal: a failed script must not stop the webapp from serving.
    expect(entry!).toMatch(/apply-plugin-constraints\.mjs 2>&1 \|\| echo "\[plugins\] constraint script failed"/)
  })

  test('the one-time user-skill toggle backfill runs after db push and before the server, never fatally', () => {
    const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))!
    const push = entry.indexOf('db push')
    const backfill = entry.indexOf('backfill-user-skill-toggles.mjs')
    const server = entry.indexOf('exec node scripts/serve.cjs')
    expect(backfill).toBeGreaterThan(push)
    expect(server).toBeGreaterThan(backfill)
    // No `|| exit`: the script logs a failure and the next boot retries it.
    expect(entry).toMatch(/node scripts\/backfill-user-skill-toggles\.mjs 2>&1\\n/)
  })

  test('uses an index name Prisma never generates', () => {
    expect(script).toContain("const INDEX = 'plugin_overrides_one_active'")
    expect('plugin_overrides_one_active').not.toMatch(/_(key|idx|pkey|fkey)$/)
  })

  test('owner and scope checks also refuse a NULL foreign key (a NULL CHECK result passes)', () => {
    expect(script).toContain("name: 'plugin_data_owner_ck2'")
    expect(script).toContain("name: 'plugin_overrides_scope_ck2'")
    expect(script).toMatch(/owner_type = 'user' AND user_id IS NOT NULL AND user_id = owner_id/)
    expect(script).toMatch(/scope_type = 'project' AND project_id IS NOT NULL AND project_id = scope_id/)
  })

  test('an operation id and its lease are set and cleared together', () => {
    expect(script).toContain("name: 'plugin_installs_lease_ck1'")
  })

  test('the one-active index is partial on status active, per point, scope and target', () => {
    expect(script).toContain(
      "(extension_point, scope_type, scope_id, target_key) WHERE status = 'active'",
    )
  })
})
