/**
 * The owner catalog's key list (step 5.7, SH-26): a collaborator's project form learns which of the
 * owner's API keys are set from it, by name, so it must name every key the owner's settings hold
 * and nothing else. It follows the secrets the settings route masks (SECRET_FIELDS), less the two
 * instance tunnel credentials no project setting reads: a key added there and not here would read as
 * "missing" to every collaborator, and a column named here that is not a secret would be a value
 * the catalog has no reason to look at.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { OWNER_KEY_FIELDS, catalogMcpServers, providerHasKey } from './ownerCatalog'

const WEBAPP = join(__dirname, '..', '..')
/** Instance credentials (the tunnel), never a project's: the settings route masks them, the catalog leaves them out. */
const INSTANCE_ONLY = ['ngrokAuthtoken', 'chiselAuth']

function settingsRouteSecretFields(): string[] {
  const source = readFileSync(join(WEBAPP, 'src/app/api/users/[id]/settings/route.ts'), 'utf8')
  const list = /const SECRET_FIELDS = \[([\s\S]*?)\] as const/.exec(source)
  if (!list) throw new Error('SECRET_FIELDS not found in the settings route')
  return [...list[1].matchAll(/'([A-Za-z]+)'/g)].map((m) => m[1])
}

function userSettingsColumns(): Set<string> {
  const schema = readFileSync(join(WEBAPP, 'prisma/schema.prisma'), 'utf8')
  const model = /\nmodel UserSettings \{([\s\S]*?)\n\}/.exec(schema)
  if (!model) throw new Error('model UserSettings not found')
  return new Set([...model[1].matchAll(/^\s+([A-Za-z]+)\s+String\b/gm)].map((m) => m[1]))
}

describe('OWNER_KEY_FIELDS', () => {
  test("names every secret the settings route masks, less the instance tunnel credentials", () => {
    const masked = settingsRouteSecretFields()
    expect(masked.length).toBeGreaterThan(40)
    for (const f of INSTANCE_ONLY) expect(masked).toContain(f)
    expect([...OWNER_KEY_FIELDS].sort()).toEqual(masked.filter((f) => !INSTANCE_ONLY.includes(f)).sort())
  })

  test('each is a string column of UserSettings, named once', () => {
    const columns = userSettingsColumns()
    for (const f of OWNER_KEY_FIELDS) expect([f, columns.has(f)]).toEqual([f, true])
    expect(new Set(OWNER_KEY_FIELDS).size).toBe(OWNER_KEY_FIELDS.length)
  })
})

describe('providerHasKey', () => {
  const row = { apiKey: '', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '' }
  test.each([
    ['an API key', { apiKey: 'k' }, true],
    ['blanks only', { apiKey: '   ' }, false],
    ['a Bedrock bearer token', { awsBearerToken: 't' }, true],
    ['a Bedrock IAM pair', { awsAccessKeyId: 'a', awsSecretKey: 's' }, true],
    ['half an IAM pair', { awsAccessKeyId: 'a' }, false],
    ['nothing', {}, false],
  ])('%s -> %s', (_what, over, expected) => {
    expect(providerHasKey({ ...row, ...over })).toBe(expected)
  })
})

describe('catalogMcpServers', () => {
  test('keeps the id, name, enabled, phases and tool names; every other field of a server or a tool is dropped', () => {
    expect(catalogMcpServers([{
      id: 's', name: 'S', enabled: false, transport: 'sse', url: 'u', headers: { h: 'v' }, auth: { type: 'bearer', token: 't' },
      command: 'c', args: ['a'], env: { E: 'v' }, cwd: 'd', description: 'x', tags: ['t'], default_phases: ['exploitation'],
      tools: [{ name: 't1', purpose: 'p', when_to_use: 'w', args_format: 'a', description: 'd', default_phases: ['post_exploitation'] }],
    }])).toEqual([
      { id: 's', name: 'S', enabled: false, default_phases: ['exploitation'], tools: [{ name: 't1', default_phases: ['post_exploitation'] }] },
    ])
  })

  test('a server without `enabled` is enabled (the schema default); a missing name reads as the id', () => {
    expect(catalogMcpServers([{ id: 's' }])).toEqual([{ id: 's', name: 's', enabled: true, default_phases: [], tools: [] }])
  })
})
