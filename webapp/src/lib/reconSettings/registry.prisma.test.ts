/**
 * The registry against Prisma.
 *
 * Prisma owns which columns exist, their type and their `@default()`. The
 * registry never restates any of that: `recon_settings/build.py` joins it at
 * build time. These tests read the DMMF DIRECTLY rather than the registry's
 * joined copy, so the comparison is between two independent sources and not a
 * tautology, and they are what makes adding a Prisma column fail the build
 * until it has a registry entry.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import {
  loadRegistry,
  fieldKeys,
  fieldsWhere,
  prismaColumns,
  prismaDefaults,
  prismaTypes,
} from './registry'

const registry = loadRegistry()
const fields = registry.fields
const columns = prismaColumns()
const defaults = prismaDefaults()
const types = prismaTypes()

// --- T1 / T2: coverage in both directions -------------------------------------------

describe('T1/T2 the registry covers Prisma exactly', () => {
  test('every Project column has a registry entry', () => {
    const missing = columns.filter(c => !(c in fields)).sort()
    expect(
      missing,
      'New Project column(s) have no registry entry. Add each to ' +
        'recon_settings/registry.yaml with a unit, a phase, a traffic class, an mcp ' +
        'disposition, a meaning, and either bounds or a validator. Then run ' +
        'python3 recon_settings/build.py.'
    ).toEqual([])
  })

  test('no registry entry invents a column Prisma does not have', () => {
    const known = new Set(columns)
    const ghosts = fieldKeys().filter(k => !known.has(k))
    expect(ghosts, 'stale registry entries for columns that no longer exist').toEqual([])
  })

  test('the counts agree', () => {
    expect(fieldKeys().length).toBe(columns.length)
  })
})

// --- T35: the registry's expectations match the column's type ---------------------------

describe('T35 registry expectations match the Prisma type', () => {
  test('the joined type matches what the DMMF reports', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      if (!live) continue
      const expected = live.type + (live.isList ? '[]' : '')
      if (fields[key].prisma_type !== expected) {
        problems.push(`${key}: registry says '${fields[key].prisma_type}', Prisma says '${expected}'`)
      }
    }
    expect(problems, 'the built artifact is stale; run python3 recon_settings/build.py').toEqual([])
  })

  test('a numeric column carries bounds and a non-numeric one does not', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      const f = fields[key]
      if (!live) continue
      const numeric = !live.isList && ['Int', 'Float', 'BigInt', 'Decimal'].includes(live.type)
      if (numeric && !f.bounds) problems.push(`${key}: ${live.type} with no bounds`)
      if (!numeric && f.bounds) problems.push(`${key}: ${live.type} with numeric bounds`)
    }
    expect(problems).toEqual([])
  })

  test('a list or Json column carries a validator or a closed value set', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      const f = fields[key]
      if (!live || f.mcp === 'never') continue
      if (!live.isList && live.type !== 'Json') continue
      if (!f.validator && !f.values) problems.push(`${key}: ${live.type} with nothing to validate it`)
    }
    expect(problems).toEqual([])
  })

  test('a closed value set only appears on a string or string list', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const live = types[key]
      if (!live || !fields[key].values) continue
      if (live.type !== 'String') problems.push(`${key}: values on a ${live.type}`)
    }
    expect(problems).toEqual([])
  })
})

// --- T34: a default that its own bound would refuse -------------------------------------

describe('T34 every Prisma default falls inside its registry bounds', () => {
  test('no default is outside its own bounds unless zero_means says why', () => {
    // This catches the ffufRate class automatically. Its default is 0 and a
    // naive `min: 1` would make the SHIPPED value unrepresentable, so a caller
    // could not restore it. Declaring zero_means is the deliberate answer.
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const f = fields[key]
      const d = defaults[key]
      if (!f.bounds || typeof d !== 'number') continue
      if (d >= f.bounds.min && d <= f.bounds.max) continue
      if (d === 0 && f.zero_means) continue
      problems.push(
        `${key}: default ${d} is outside bounds ${f.bounds.min}..${f.bounds.max}` +
          (d === 0 ? ' (declare zero_means if 0 is a sentinel)' : '')
      )
    }
    expect(problems).toEqual([])
  })

  test('every numeric whose default is 0 declares what 0 means', () => {
    // An agent reading `unit: rps` with no further hint concludes 0 is the
    // gentlest setting, then writes it onto a 3 rps engagement and runs
    // unlimited. That is a scope violation produced by documentation.
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const f = fields[key]
      if (defaults[key] !== 0) continue
      if (typeof defaults[key] !== 'number') continue
      if (!f.zero_means) problems.push(`${key}: default 0 with no zero_means`)
    }
    expect(problems).toEqual([])
  })

  test('the five rates whose zero is unlimited are marked as such', () => {
    // Named rather than derived: these are the ones where 0 is the FASTEST
    // value available, and getting one wrong is a scope violation rather than a
    // documentation nit.
    for (const key of [
      'ffufRate',
      'arjunRateLimit',
      'purednsRateLimit',
      'webCachePoisonMaxRpsPerHost',
    ]) {
      expect(fields[key]?.zero_means, `${key}`).toBe('unlimited')
      expect(fields[key]?.meaning.toLowerCase(), `${key} must say so in words`).toContain('unlimited')
    }
    expect(registry.runtime_only.ORIGIN_DISCOVERY_RATE?.zero_means).toBe('unlimited')
  })

  test('the joined default matches the DMMF', () => {
    const problems: string[] = []
    for (const key of fieldKeys()) {
      const f = fields[key]
      if (!f.has_default) continue
      const live = defaults[key]
      if (live === undefined) continue // a function default: cuid(), now()
      const joined = f.default
      // A Float default is a double on both sides, so compare numerically: the
      // DMMF reports 1.4 as 1.4000000000000001 and a textual compare would
      // report a drift that does not exist.
      const same =
        typeof joined === 'number' && typeof live === 'number'
          ? Math.abs(joined - live) < 1e-9
          : JSON.stringify(joined) === JSON.stringify(live)
      if (!same) {
        problems.push(`${key}: registry has ${JSON.stringify(joined)}, Prisma has ${JSON.stringify(live)}`)
      }
    }
    expect(problems, 'the built artifact is stale; run python3 recon_settings/build.py').toEqual([])
  })
})

// --- the disposition sets, sized against the model ---------------------------------------

describe('the dispositions cover the model', () => {
  test('every column has exactly one disposition', () => {
    const counts = { settable: 0, create_only: 0, never: 0 }
    for (const key of fieldKeys()) counts[fields[key].mcp] += 1
    expect(counts.settable + counts.create_only + counts.never).toBe(columns.length)
    // The headline: most of the model is reachable, and what is not is a short,
    // named list plus ONE class - the engagement record, which is the contract
    // rather than a pipeline parameter.
    expect(counts.settable).toBeGreaterThan(600)
    const record = fieldsWhere(f => f.deny_reason === 'engagement-record').length
    // OpenAPI source and discovery headers are two credential-bearing columns.
    expect(counts.never - record).toBeLessThan(27)
  })

  test('there is no tighten-only disposition left to hold anything', () => {
    for (const key of fieldKeys()) {
      expect(['settable', 'create_only', 'never']).toContain(fields[key].mcp)
    }
  })

  test('P4: every roe* column is a limit or a record, and nothing is both', () => {
    // The `roe` PREFIX stopped being a classification. Fifteen of these columns
    // are enforced limits and are ordinary settings; the rest are the contract
    // and are UI-only. The columns keep their names - renaming fifteen buys
    // nothing and costs a migration - so anything keyed on the prefix now
    // survives that split by accident rather than by design, which is why every
    // control that needs "the limits" asks the registry GROUP.
    const roe = columns.filter(c => c.startsWith('roe')).sort()
    expect(roe.length).toBeGreaterThan(30)

    const unclassified = roe.filter(
      c => fields[c].group !== 'engagement_limits' && fields[c].deny_reason !== 'engagement-record'
    )
    // roeDocumentData is the one that is neither: it is the document's own bytes,
    // written by the endpoint that receives the file. A JSON-RPC settings write
    // cannot carry bytes at all, so it was a type error waiting behind a
    // validator that described it as a string.
    expect(unclassified).toEqual(['roeDocumentData'])
    expect(fields.roeDocumentData.mcp).toBe('never')
    expect(fields.roeDocumentData.deny_reason).toBe('upload-managed')

    const both = roe.filter(
      c => fields[c].group === 'engagement_limits' && fields[c].deny_reason === 'engagement-record'
    )
    expect(both).toEqual([])
  })

  test('P4: no engagement-record column is writable through any MCP path', () => {
    for (const f of fieldsWhere(s => s.deny_reason === 'engagement-record')) {
      expect(f.mcp, f.key).toBe('never')
    }
  })

  test('P4: no engagement-limit column is refused by an MCP path', () => {
    for (const f of fieldsWhere(s => s.group === 'engagement_limits')) {
      // roeEnabled is the deliberate exception: derived, written by nothing.
      if (f.key === 'roeEnabled') {
        expect(f.mcp).toBe('never')
        expect(f.deny_reason).toBe('derived')
        continue
      }
      expect(f.mcp, f.key).toBe('settable')
    }
  })

  test('the scope columns are create_only, never settable', () => {
    for (const key of [
      'targetDomain', 'subdomainList', 'targetIps', 'ipMode',
      'domainBatchMode', 'domainBatchHosts',
      'targetGuardrailEnabled', 'verifyDomainOwnership',
      'githubTargetOrg', 'gvmScanTargets', 'supplyChainRepoUrl',
    ]) {
      expect(fields[key]?.mcp, key).toBe('create_only')
    }
  })
})
