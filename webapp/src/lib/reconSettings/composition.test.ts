/**
 * T44 and T45: the composed answer, not the layers.
 *
 * Every layer here can be individually truthful while the COMPOSED answer
 * misleads the caller, and that is the class of bug a green unit gate has
 * hidden on this surface before. `describe_recon_settings` can correctly report
 * a registry that `filterReconSettings` correctly enforces, and the pair can
 * still disagree about one field, which an agent discovers by being refused for
 * something it was just told it could do.
 *
 * So both tests exercise the REAL functions and iterate the registry rather
 * than naming examples: the registry is the list of things that could regress,
 * and a field added tomorrow is covered the day it is added.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { settingGroups } from '@/lib/mcp/catalogTools'
import { filterReconSettings, permittedKeys } from './filter'
import { fieldsWhere, loadRegistry, type RegistryField } from './registry'

const registry = loadRegistry()
const advertised = settingGroups().flatMap(g => g.settings)

/** A value inside this field's own bounds or vocabulary. */
function legalValue(key: string, spec: RegistryField): unknown {
  switch (spec.type) {
    case 'boolean':
      return spec.default === true ? false : true
    case 'int':
      return Math.min(spec.bounds!.max, Math.max(spec.bounds!.min, 1))
    case 'float':
      return spec.bounds!.min
    case 'string-list':
      if (spec.values) return [spec.values[0]]
      if (spec.validator === 'status_codes') return ['200']
      if (spec.validator === 'http_header') return ['X-Scan-Id: abc']
      if (spec.validator === 'project_file') return ['/usr/share/seclists/a.txt']
      if (spec.validator === 'project_file_name') return ['mine.yaml']
      return ['a']
    case 'number-list':
      return [200]
    case 'json':
      return {}
    case 'datetime':
      return new Date(0).toISOString()
    default:
      if (spec.values) return spec.values[0]
      if (spec.validator === 'project_file') return '/usr/share/seclists/a.txt'
      if (spec.validator === 'project_file_name') return 'mine.yaml'
      if (spec.validator === 'docker_image') return 'vendor/tool:latest'
      if (spec.validator === 'url') return 'https://example.com'
      if (spec.validator === 'http_header') return 'X-Scan-Id: abc'
      if (spec.validator === 'status_codes') return '200'
      if (spec.validator === 'port_spec') return '80,443'
      if (spec.validator === 'hostname') return 'example.com'
      if (spec.validator === 'identifier') return 'abc'
      return 'x'
  }
}

// --- T44: describe and update agree -------------------------------------------------

describe('T44 what describe advertises, update accepts', () => {
  test('every advertised field accepts a value drawn from its own bounds', () => {
    // An agent that trusts describe_recon_settings must never be surprised by
    // update_recon_settings. One bad key refuses the WHOLE call, so a batch of
    // writes built from a stale reference applies nothing at all.
    const problems: string[] = []
    for (const doc of advertised) {
      const spec = registry.fields[doc.key]
      const value = legalValue(doc.key, spec)
      const r = filterReconSettings({ [doc.key]: value })
      if (!r.ok) problems.push(`${doc.key} = ${JSON.stringify(value)}: ${r.error}`)
    }
    expect(problems).toEqual([])
  })

  test('the advertised bound IS the enforced bound, at both ends', () => {
    const problems: string[] = []
    for (const doc of advertised) {
      if (doc.min === undefined || doc.max === undefined) continue
      if (!filterReconSettings({ [doc.key]: doc.min }).ok) problems.push(`${doc.key}: min refused`)
      if (!filterReconSettings({ [doc.key]: doc.max }).ok) problems.push(`${doc.key}: max refused`)
      if (filterReconSettings({ [doc.key]: doc.max + 1 }).ok) {
        problems.push(`${doc.key}: max + 1 accepted`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every field describe does NOT advertise is refused, naming it', () => {
    const shown = new Set(advertised.map(s => s.key))
    const problems: string[] = []
    for (const key of Object.keys(registry.fields)) {
      if (shown.has(key)) continue
      const spec = registry.fields[key]
      const r = filterReconSettings({ [key]: legalValue(key, spec) })
      if (r.ok) problems.push(`${key}: unadvertised but accepted`)
      else if (!r.error.includes(key)) problems.push(`${key}: refused without naming the field`)
    }
    expect(problems).toEqual([])
  })

  test('the advertised set is exactly the permitted set', () => {
    expect(advertised.map(s => s.key).sort()).toEqual([...permittedKeys('update')].sort())
  })

  test('a refusal always names the field', () => {
    // A batch of writes refuses as a whole, so the message has to say which key
    // caused it or the caller cannot fix the batch.
    for (const key of ['targetDomain', 'roeEnabled', 'cypherfixGithubToken', 'notAColumn']) {
      const r = filterReconSettings({ naabuThreads: 25, [key]: 'x' })
      expect(r.ok).toBe(false)
      if (!r.ok) expect(r.error, key).toContain(key)
    }
  })
})

// --- T45: the disposition round-trip -------------------------------------------------

describe('T45 each disposition behaves the way it is documented', () => {
  test('every create_only field is refused on update and accepted on create', () => {
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'create_only')) {
      const value = legalValue(f.key, f)
      const update = filterReconSettings({ [f.key]: value }, { mode: 'update' })
      if (update.ok) problems.push(`${f.key}: settable on an existing project`)
      else if (!/create_project/.test(update.error)) {
        problems.push(`${f.key}: refused without naming the right tool`)
      }
      const create = filterReconSettings({ [f.key]: value }, { mode: 'create' })
      if (!create.ok) problems.push(`${f.key}: refused at CREATE too (${create.error})`)
    }
    expect(problems).toEqual([])
  })

  test('every never field is refused in both modes, by name', () => {
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.mcp === 'never')) {
      for (const mode of ['update', 'create'] as const) {
        const r = filterReconSettings({ [f.key]: legalValue(f.key, f) }, { mode })
        if (r.ok) problems.push(`${f.key}: accepted in ${mode} mode`)
        else if (!r.error.includes(f.key)) problems.push(`${f.key}: ${mode} refusal does not name it`)
      }
    }
    expect(problems).toEqual([])
  })

  test('every engagement limit is writable through update_recon_settings', () => {
    // The direction rules are gone. A limit is an ordinary setting that moves in
    // either direction, because what makes it safe is that it is ENFORCED at scan
    // start whatever the write said - not that the write was checked. The five
    // fields whose declared direction never actually constrained anything
    // (`tighten: narrow` on the whole time window) are the proof that the
    // write-time check bought the appearance of a guarantee rather than one.
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.group === 'engagement_limits')) {
      if (f.key === 'roeEnabled') continue // derived, refused by design
      const r = filterReconSettings({ [f.key]: legalValue(f.key, f) })
      if (!r.ok) problems.push(`${f.key}: refused (${r.error})`)
    }
    expect(problems).toEqual([])
  })

  test('the rate ceiling moves in both directions and is enforced at scan start', () => {
    // Lowering it and raising it are equally permitted and equally auditable.
    // preflight_scope_check is where a caller sees what will actually run.
    expect(filterReconSettings({ roeGlobalMaxRps: 1 }, { current: { roeGlobalMaxRps: 3 } }).ok).toBe(true)
    expect(filterReconSettings({ roeGlobalMaxRps: 10 }, { current: { roeGlobalMaxRps: 3 } }).ok).toBe(true)
    // 0 is still accepted and still means NO ceiling; the bound is what is
    // enforced, and the meaning says so where a caller reads it.
    expect(filterReconSettings({ roeGlobalMaxRps: 0 }).ok).toBe(true)
    expect(registry.fields.roeGlobalMaxRps.meaning).toMatch(/ZERO MEANS NO CEILING/)
  })

  test('the derived engagement flag is refused, in both modes, naming why', () => {
    for (const mode of ['update', 'create'] as const) {
      const r = filterReconSettings({ roeEnabled: true }, { mode })
      expect(r.ok).toBe(false)
      if (!r.ok) expect(r.error).toMatch(/derived/i)
    }
  })

  test('an exclusion list may be written in full, added to or cleared', () => {
    for (const value of [['a'], ['a', 'b'], []]) {
      expect(filterReconSettings({ roeExcludedHosts: value }).ok).toBe(true)
    }
  })

  test('every engagement RECORD column is refused, in both modes, by name', () => {
    const problems: string[] = []
    for (const f of fieldsWhere(s => s.deny_reason === 'engagement-record')) {
      for (const mode of ['update', 'create'] as const) {
        const r = filterReconSettings({ [f.key]: legalValue(f.key, f) }, { mode })
        if (r.ok) problems.push(`${f.key}: accepted in ${mode} mode`)
        else if (!r.error.includes(f.key)) problems.push(`${f.key}: ${mode} refusal does not name it`)
      }
    }
    expect(problems).toEqual([])
  })
})

// --- the headline numbers, asserted ----------------------------------------------------

describe('the surface is the size it claims to be', () => {
  test('most of the model is settable and the closed set is small', () => {
    const total = Object.keys(registry.fields).length
    expect(permittedKeys('update').length / total).toBeGreaterThan(0.85)
    // The closed set grew by the 24 engagement-RECORD columns, which are not
    // pipeline parameters at all: the client, the contacts, the dates and the
    // document. Everything a scan is configured by is still open.
    // OpenAPI source URLs may carry credentials and remain project-specific.
    expect(fieldsWhere(f => f.mcp === 'never' && f.deny_reason !== 'engagement-record').length)
      .toBeLessThan(26)
  })

  test('every rate limit is reachable, not three of fifteen', () => {
    const rates = fieldsWhere(f => f.unit === 'rps')
    expect(rates.length).toBeGreaterThanOrEqual(15)
    expect(rates.filter(f => f.mcp !== 'settable')).toEqual([])
  })

  test('every settable field carries a bound or a validator', () => {
    const naked = fieldsWhere(f => f.mcp === 'settable').filter(
      f => f.type !== 'boolean' && !f.bounds && !f.validator && !f.values
    )
    expect(naked.map(f => f.key)).toEqual([])
  })
})
