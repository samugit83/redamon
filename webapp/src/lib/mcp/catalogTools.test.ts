/**
 * describe_recon_settings, and the registry properties the presets rest on.
 *
 * Both are projections of constants this build already ships, so the things
 * that can go wrong are not "the data is missing" but:
 *
 *  - the projection LEAKS, advertising fields the surface denies (which also
 *    hands an external agent a map of the denied surface);
 *  - the projection drifts from what `update_recon_settings` actually accepts,
 *    so a caller is told a bound that is not the enforced one;
 *  - a preset is described as applicable when the denied part of it is the part
 *    that made it safe.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import { McpScopeError, __resetRateLimiter } from '@/lib/mcpAuth'
import { McpToolError } from './errors'
import { filterReconSettings, permittedKeys } from '@/lib/reconSettings/filter'
import { SCAN_MODULE_VALUES, SEVERITY_VALUES } from '@/lib/reconSettings/validators'
import { engagementLimitFields, field } from '@/lib/reconSettings/registry'
import {
  __resetCatalogCache,
  describeReconSettings,
  settingGroups,
} from './catalogTools'
import type { McpContext } from './tools'
import { RECON_PRESETS } from '@/lib/recon-presets'

const ctx = (scopes: string[] = ['recon:read']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes: scopes as never,
  },
})

const allSettings = () => settingGroups().flatMap(g => g.settings)

beforeEach(() => {
  __resetRateLimiter()
  __resetCatalogCache()
})

describe('describe_recon_settings covers exactly the settable surface', () => {
  test('every settable field is described, once', () => {
    const keys = allSettings().map(s => s.key).sort()
    expect(keys).toEqual([...permittedKeys('update')].sort())
  })

  test('no field this surface refuses is advertised as settable', () => {
    // Not merely useless: advertising a field the caller will then be refused
    // for is the exact surprise describe_recon_settings exists to prevent. The
    // SET changed with the registry - the scope and the Rules of Engagement are
    // still refused, a rate limit no longer is, and a container image is no
    // setting at all.
    const described = new Set(allSettings().map(s => s.key))
    for (const refused of [
      'targetDomain', 'targetIps', 'ipMode',        // scope: create_project owns it
      'roeEnabled',                                 // derived from the limits that ARE set
      'roeClientName', 'roeClientContactEmail',     // the engagement RECORD, UI-only
      'updateGraphDb',                              // a debug switch, not tuning
      'cypherfixGithubToken', 'activationState',    // never a pipeline parameter
      'jsReconUploadedFiles',                       // upload-managed
      'nucleiDockerImage',                          // images are fixed, not settings
    ]) {
      expect(described.has(refused), `${refused} must not be advertised`).toBe(false)
    }
  })

  test('the fields that were opened ARE advertised', () => {
    // The headline, asserted from the caller's side.
    const described = new Set(allSettings().map(s => s.key))
    for (const opened of [
      'naabuRateLimit', 'takeoverRateLimit', 'ffufRate',   // every rate, not 3 of 15
      'httpxCustomHeaders',                                 // open; the validator checks it
      'ffufWordlist',                                       // open; the path is validated
      'stealthMode', 'nucleiTags', 'arjunTimeout',
    ]) {
      expect(described.has(opened), `${opened} should be advertised`).toBe(true)
    }
  })

  test('the described bound IS the enforced bound', () => {
    // The failure this prevents: a caller told a max it is then refused for.
    for (const s of allSettings()) {
      if (s.kind !== 'number') continue
      expect(filterReconSettings({ [s.key]: s.max }).ok, `${s.key} max`).toBe(true)
      expect(filterReconSettings({ [s.key]: s.min }).ok, `${s.key} min`).toBe(true)
      expect(filterReconSettings({ [s.key]: (s.max as number) + 1 }).ok, `${s.key} over max`).toBe(false)
    }
  })

  test('the described enum values ARE the accepted values', () => {
    for (const s of allSettings()) {
      if (!s.values) continue
      // A scalar enum takes ONE of its values; a list takes an array of them.
      // Passing the whole vocabulary to a scalar was the old shape and only
      // worked while every enumerated field happened to be a list.
      const spec = field(s.key)!
      const good = spec.type === 'string' ? s.values[0] : [...s.values]
      const bad = spec.type === 'string' ? 'definitely-not-a-value' : ['definitely-not-a-value']
      expect(filterReconSettings({ [s.key]: good }).ok, `${s.key} accepts its own value`).toBe(true)
      expect(filterReconSettings({ [s.key]: bad }).ok, `${s.key} refuses a foreign value`).toBe(false)
    }
  })

  test('a list field with a free-form vocabulary advertises none', () => {
    // Status-code lists take "200" or "200-299", which is not a closed set; a
    // bogus `values` array there would be a lie the validator contradicts.
    const codes = allSettings().find(s => /MatchCodes|FilterCodes|StatusCodes$/.test(s.key))
    expect(codes).toBeDefined()
    expect(codes!.values).toBeUndefined()
  })

  test('numbers carry bounds and non-numbers do not', () => {
    for (const s of allSettings()) {
      if (s.kind === 'int' || s.kind === 'float') {
        expect(typeof s.min, s.key).toBe('number')
        expect(typeof s.max, s.key).toBe('number')
      } else {
        expect(s.min, s.key).toBeUndefined()
      }
    }
  })

  test('every field carries a unit, a phase and a traffic class', () => {
    // The semantics layer. A field with `unit: rps` and `traffic: active` is
    // one an engagement ceiling applies to, and an agent cannot work that out
    // from a name.
    const UNITS = new Set([
      'rps', 'seconds', 'minutes', 'milliseconds', 'threads', 'count', 'bytes',
      'depth', 'percent', 'ratio', 'port', 'none',
    ])
    for (const s of allSettings()) {
      expect(UNITS.has(s.unit), `${s.key} has unit '${s.unit}'`).toBe(true)
      expect(['none', 'passive', 'active'], s.key).toContain(s.traffic)
      expect(s.phase.length, s.key).toBeGreaterThan(0)
    }
  })

  test('a rate the ceiling rewrites says so', () => {
    const byKey = new Map(allSettings().map(s => [s.key, s]))
    for (const key of ['naabuRateLimit', 'takeoverRateLimit', 'jsluiceVerifyRateLimit']) {
      expect(byKey.get(key)?.roeCapped, key).toBe(true)
    }
  })

  test('a rate whose zero means unlimited says so in the field AND in words', () => {
    // The single largest new-bug risk the registry documents: an agent reading
    // `unit: rps` with no further hint concludes 0 is the gentlest setting,
    // then writes it onto a 3 rps engagement and runs unlimited.
    const byKey = new Map(allSettings().map(s => [s.key, s]))
    for (const key of ['ffufRate', 'arjunRateLimit', 'purednsRateLimit']) {
      expect(byKey.get(key)?.zeroMeans, key).toBe('unlimited')
      expect(byKey.get(key)?.meaning.toLowerCase(), key).toContain('unlimited')
    }
  })

  test('every field has a meaning and it is a sentence', () => {
    for (const s of allSettings()) {
      expect(s.meaning.length, `${s.key} has no meaning`).toBeGreaterThan(19)
    }
  })

  test('a timeout whose unit is not seconds says so in words', () => {
    // Found by the unit-coherence check against prose that already existed.
    // A reader who assumes seconds writes a value off by 60 or by 1000.
    const byKey = new Map(allSettings().map(s => [s.key, s]))
    expect(byKey.get('amassTimeout')?.unit).toBe('minutes')
    expect(byKey.get('amassTimeout')?.meaning).toMatch(/MINUTES/)
    expect(byKey.get('naabuTimeout')?.unit).toBe('milliseconds')
    expect(byKey.get('naabuTimeout')?.meaning).toMatch(/MILLISECONDS/)
  })

  test('every settable field lands in a named tool group', () => {
    // Grouping is by the TOOL a field configures, which is the thing an agent
    // is actually choosing. A field whose tool has no title would group under a
    // bare identifier; the registry's own tests stop that upstream.
    const orphans = settingGroups()
      .filter(g => !g.group || g.group === 'Other')
      .flatMap(g => g.settings.map(s => s.key))
    expect(orphans).toEqual([])
  })
})

describe('describe_recon_settings teaches the two-level model', () => {
  test('it names the silent no-op, because that is the failure it exists to prevent', async () => {
    const notes = (await describeReconSettings(ctx())).notes.join(' ')
    expect(notes).toMatch(/scanModules/)
    expect(notes).toMatch(/naabuEnabled and masscanEnabled both false/)
    expect(notes).toMatch(/silent no-op/i)
  })

  test('it lists the phases and the two enum vocabularies', async () => {
    const r = await describeReconSettings(ctx())
    expect(r.phases.map(p => p.module)).toEqual([...SCAN_MODULE_VALUES])
    for (const p of r.phases) expect(p.what.length, p.module).toBeGreaterThan(10)
    expect(r.enums.scanModules).toEqual(SCAN_MODULE_VALUES)
    expect(r.enums.severity).toEqual(SEVERITY_VALUES)
  })

  test('it reports no current values, so it cannot disagree with get_recon_settings', async () => {
    const serialised = JSON.stringify(await describeReconSettings(ctx()))
    expect(serialised).not.toMatch(/"value"|"current"/)
  })

  test('a group filter narrows without inventing', async () => {
    const r = await describeReconSettings(ctx(), { group: 'nuclei' })
    expect(r.groups.length).toBeGreaterThan(0)
    for (const g of r.groups) expect(g.group.toLowerCase()).toContain('nuclei')
  })

  test('an unmatched group is an error naming the fix, not an empty list', async () => {
    await expect(describeReconSettings(ctx(), { group: 'no-such-group' }))
      .rejects.toThrow(/no settings group matches/i)
  })

  test('it needs recon:read', async () => {
    await expect(describeReconSettings(ctx([]))).rejects.toBeInstanceOf(McpScopeError)
  })

  test('it lists the hostname-policy caps among the scope fields update_project_scope changes', async () => {
    const r = await describeReconSettings(ctx())
    const byKey = Object.fromEntries(r.scopeFields.map(s => [s.key, s]))
    expect(byKey.ipHostnameMaxScanned).toMatchObject({ min: 1, max: 2000, unit: 'count', default: 100,
      changedBy: 'update_project_scope' })
    expect(byKey.ipHostnamePassiveMaxNames).toMatchObject({ min: 1, max: 10000, default: 500 })
    expect(byKey.ipHostnameMode.values).toEqual(['ip_only', 'record_only', 'record_filter', 'scan_all'])
    // Not advertised as settable through update_recon_settings.
    expect(allSettings().map(s => s.key)).not.toContain('ipHostnameMaxScanned')
  })

  test('a group filter reaches the scope fields too', async () => {
    const r = await describeReconSettings(ctx(), { group: 'ipHostname' })
    expect(r.scopeFields.map(s => s.key).sort()).toEqual([
      'ipHostnameExclude', 'ipHostnameInclude', 'ipHostnameMaxScanned', 'ipHostnameMode',
      'ipHostnamePassiveExpand', 'ipHostnamePassiveMaxNames', 'ipHostnameScanAllConfirmed',
    ])
  })

  test('it reads no tenant data at all', async () => {
    // Same shape as graph_schema: derived from code, so it still answers when
    // the databases are down. prisma is mocked to {} here, so touching it throws.
    await expect(describeReconSettings(ctx())).resolves.toBeTruthy()
  })
})

// list_recon_presets moved to presetTools.ts with its tests (presetTools.test.ts).
// What stays here are the registry properties the presets rest on.

describe('the built-in presets fit the settable surface', () => {
  test('the quiet half of every stealth preset is settable', () => {
    // Named fields rather than a count: these are the ones whose absence once
    // made a half-applied stealth preset LOUDER than the preset asked for.
    const QUIET = [
      'naabuRateLimit', 'nucleiRateLimit', 'httpxRateLimit', 'katanaRateLimit',
      'ffufRate', 'arjunRateLimit', 'naabuPassiveMode', 'amassActive', 'amassBrute',
    ]
    const settable = new Set(permittedKeys('update'))
    expect(QUIET.filter(k => !settable.has(k))).toEqual([])
  })

  test('what a preset still cannot set is scope and the engagement record, by name', () => {
    const settable = new Set(permittedKeys('update'))
    for (const key of ['targetDomain', 'ipMode', 'roeEnabled', 'roeClientName']) {
      expect(settable.has(key), key).toBe(false)
    }
  })

  test('an engagement LIMIT is settable but no preset carries one', () => {
    // Settable, because the form reaches it and the two doors must match.
    // Absent from every preset, because a limit belongs to ONE engagement rather
    // than to a reusable configuration, and a preset that carried one would
    // overwrite the rate ceiling of whatever project it was loaded into.
    expect(new Set(permittedKeys('update')).has('roeGlobalMaxRps')).toBe(true)
    const limits = new Set(engagementLimitFields().map(f => f.key))
    for (const p of RECON_PRESETS) {
      const carried = Object.keys(p.parameters ?? {}).filter(k => limits.has(k))
      expect(carried, p.id).toEqual([])
    }
  })

  test('T46: every preset value a caller could write passes its registry bound', () => {
    // A preset carrying an out-of-bounds value would otherwise fail only at
    // apply time, in front of a user.
    const settable = new Set(permittedKeys('update'))
    const problems: string[] = []
    for (const p of RECON_PRESETS) {
      for (const [key, value] of Object.entries(p.parameters ?? {})) {
        if (!settable.has(key)) continue
        const r = filterReconSettings({ [key]: value })
        if (!r.ok) problems.push(`${p.id}/${key}: ${r.error}`)
      }
    }
    expect(problems).toEqual([])
  })
})
