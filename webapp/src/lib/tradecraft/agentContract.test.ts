/**
 * The webapp side of the webapp <-> agent contract (T1.3). Both sides parse every valid
 * fixture of agentic/tests/fixtures/tradecraft_contract/ and refuse every invalid one, and
 * both compare their enum lists with its enums.json (agentic/tests/test_tradecraft_contract.py
 * is the agent's half).
 *
 * @vitest-environment node
 */
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, expect, test } from 'vitest'
import * as c from './agentContract'

const REPO = path.resolve(__dirname, '../../../..')
const FIXTURES = path.join(REPO, 'agentic/tests/fixtures/tradecraft_contract')
const read = (name: string) => JSON.parse(readFileSync(path.join(FIXTURES, name), 'utf8'))
const ENUMS = read('enums.json')
const VALID = readdirSync(FIXTURES).filter(f => f.endsWith('.valid.json')).sort()
const INVALID: { model: keyof typeof c.CONTRACT_SCHEMAS; why: string; value: unknown }[] = read('invalid.json')
const schemaOf = (file: string) => c.CONTRACT_SCHEMAS[file.split('.')[0] as keyof typeof c.CONTRACT_SCHEMAS]

describe('the shared fixtures', () => {
  test.each(VALID)('%s parses', (file) => {
    const schema = schemaOf(file)
    expect(schema, `${file}: no schema of that name`).toBeDefined()
    const r = schema.safeParse(read(file))
    expect(r.success, r.success ? '' : JSON.stringify(r.error.issues)).toBe(true)
  })

  test('every top-level schema has a valid fixture', () => {
    const covered = new Set(VALID.map(f => f.split('.')[0]))
    expect(Object.keys(c.CONTRACT_SCHEMAS).filter(n => !covered.has(n)).sort())
      .toEqual(['CatalogResource', 'Credentials', 'JobStartRequest', 'Secrets'])
  })

  test.each(INVALID.map(x => [`${x.model}: ${x.why}`, x] as const))('%s is refused', (_, x) => {
    expect(c.CONTRACT_SCHEMAS[x.model].safeParse(x.value).success).toBe(false)
  })
})

describe('the rules', () => {
  const batch = (n: number) => {
    const job = read('JobStartBatch.valid.json').jobs[0]
    return { jobs: Array.from({ length: n }, (_, i) => ({ ...job, job_id: `job_fake_${i}` })) }
  }

  test('a batch holds 1 to 200 jobs', () => {
    expect(c.JobStartBatch.safeParse(batch(200)).success).toBe(true)
    expect(c.JobStartBatch.safeParse(batch(201)).success).toBe(false)
    expect(c.JobStartBatch.safeParse(batch(0)).success).toBe(false)
  })

  test('the owner\'s own run carries its logins; a collaborator\'s and an acting administrator\'s do not', () => {
    const owner = read('V2Catalog.valid.json')
    expect(c.V2Catalog.parse(owner).resources.some(r => r.has_login && r.credentials !== null)).toBe(true)
    expect(c.V2Catalog.safeParse({ ...owner, person_id: 'someone_else' }).success).toBe(false)
    expect(c.V2Catalog.safeParse({ ...owner, actor_id: 'user_admin_fake' }).success).toBe(false)
    const publicOnly = { ...owner, resources: owner.resources.filter((r: { has_login: boolean }) => !r.has_login) }
    expect(c.V2Catalog.safeParse({ ...publicOnly, actor_id: 'user_admin_fake' }).success).toBe(true)
  })

  test('every slug the webapp makes is accepted, page-ID safe (R-138)', () => {
    const trailing = 'hacktricks-mirror-windows-local-privilege-escalation-and-active-'
    for (const ok of ['hacktricks', 'patt-2', 'resource', '0day', trailing, `${trailing}-2`]) expect(c.SLUG_RE.test(ok), ok).toBe(true)
    for (const bad of ['', '-x', 'Patt', 'pa tt', 'a:b', 'a_b', 'x'.repeat(201)]) expect(c.SLUG_RE.test(bad), bad).toBe(false)
  })

  test('a catalog over the 200-resource cap parses: the cap is checked on add only (OQ-20)', () => {
    const base = read('V2Catalog.collaborator.valid.json').resources[0]
    const resources = Array.from({ length: 250 }, (_, i) => ({ ...base, id: `res_${i}`, slug: `res-${i}` }))
    const r = c.V2Catalog.safeParse({ v2: true, owner_id: 'o', person_id: 'p', resources })
    expect(r.success).toBe(true)
  })

  test('RunCatalog takes either shape', () => {
    expect(c.RunCatalog.safeParse(read('LegacyCatalog.valid.json')).success).toBe(true)
    expect(c.RunCatalog.safeParse(read('V2Catalog.valid.json')).success).toBe(true)
    expect(c.RunCatalog.safeParse({ v2: 'yes' }).success).toBe(false)
  })

  test('the legacy columns are the 7.7.2 columns of user_tradecraft_resources, relation aside', () => {
    const release = JSON.parse(readFileSync(path.join(REPO, 'webapp/src/lib/authz/__fixtures__/schema-7.7.2-fields.json'), 'utf8'))
    const fields = Object.entries(release.models.UserTradecraftResource.fields as Record<string, { type: string }>)
      .filter(([, f]) => f.type !== 'User').map(([name]) => name)
    expect([...c.LEGACY_RESOURCE_COLUMNS].sort()).toEqual(fields.sort())
  })

  test('the deadlines and the webapp timeouts (D-52)', () => {
    expect(c.AGENT_DEADLINES_SEC).toEqual({ checkUrl: 60, previewFocus: 120, readNow: 45 })
    expect(c.WEBAPP_TIMEOUTS_MS).toEqual({ checkUrl: 75_000, previewFocus: 135_000, readNow: 60_000 })
  })

  test('a preview may carry the settings a refresh would read; a body without them is unchanged', () => {
    const preview = read('PreviewRequest.valid.json')
    expect(c.PreviewRequest.parse(preview)).not.toHaveProperty('settings')
    const withSettings = { ...preview, settings: { 'focus.alwaysSkip': 'news, marketing' } }
    expect(c.PreviewRequest.parse(withSettings).settings).toEqual({ 'focus.alwaysSkip': 'news, marketing' })
    expect(c.PreviewRequest.safeParse({ ...preview, settings: ['focus.alwaysSkip'] }).success).toBe(false)
  })

  test('routes', () => {
    expect(c.AGENT_ROUTES.jobs).toBe('/tradecraft/v2/jobs')
    expect(c.AGENT_ROUTES.cancelJob('a/b')).toBe('/tradecraft/v2/jobs/a%2Fb/cancel')
    expect(c.AGENT_ROUTES.convert('u1')).toBe('/tradecraft/v2/users/u1/convert')
  })
})

describe('enum lists equal enums.json', () => {
  test('every list and the contract version', () => {
    const mine: Record<string, readonly string[]> = {
      jobKinds: c.JOB_KINDS, jobStatuses: c.JOB_STATUSES, unfinishedJobStatuses: c.UNFINISHED_JOB_STATUSES, jobStages: c.JOB_STAGES,
      errorCodes: c.ERROR_CODES, storageModes: c.STORAGE_MODES, siteTypes: c.SITE_TYPES, summarySources: c.SUMMARY_SOURCES,
      priorities: c.PRIORITIES, skipReasons: c.SKIP_REASONS, indexKinds: c.INDEX_KINDS, previewDecisions: c.PREVIEW_DECISIONS,
      readSources: c.READ_SOURCES, provenances: c.PROVENANCES, purposes: c.PURPOSES,
    }
    expect(Object.keys(ENUMS).sort()).toEqual([...Object.keys(mine), 'contractVersion'].sort())
    for (const [name, list] of Object.entries(mine)) expect([...list], name).toEqual(ENUMS[name])
    expect(c.CONTRACT_VERSION).toBe(ENUMS.contractVersion)
  })

  test('the loop driver guide names neither tradecraft purpose (TD-19)', () => {
    const guide = readFileSync(path.join(REPO, 'webapp/src/lib/mcp/loopSkill.ts'), 'utf8')
    for (const p of c.PURPOSES) expect(guide).not.toContain(p)
  })
})
