import { describe, test, expect } from 'vitest'
import { matchesTargetFilter, resolveIpModeForPreset, type TargetFilter } from './targeting'
import { RECON_PRESETS } from './index'
import type { ReconPreset } from './types'

// Minimal preset factory - only the fields targeting logic reads.
function preset(
  targetProfile: ReconPreset['targetProfile'],
  environment: ReconPreset['environment']
): ReconPreset {
  return {
    id: `${targetProfile}-${environment}`,
    name: 'x',
    icon: '',
    shortDescription: 'x',
    fullDescription: 'x',
    targetProfile,
    environment,
    parameters: {},
  }
}

describe('matchesTargetFilter', () => {
  test("'all' matches every combination", () => {
    for (const p of [
      preset('domain', 'external'),
      preset('ip', 'external'),
      preset('both', 'either'),
      preset('ip', 'internal'),
    ]) {
      expect(matchesTargetFilter(p, 'all')).toBe(true)
    }
  })

  test("'domain' matches domain and both, not pure ip", () => {
    expect(matchesTargetFilter(preset('domain', 'external'), 'domain')).toBe(true)
    expect(matchesTargetFilter(preset('both', 'either'), 'domain')).toBe(true)
    expect(matchesTargetFilter(preset('ip', 'external'), 'domain')).toBe(false)
    expect(matchesTargetFilter(preset('ip', 'internal'), 'domain')).toBe(false)
  })

  test("'ip' matches public-reachable ip/both, excludes internal-only", () => {
    expect(matchesTargetFilter(preset('ip', 'external'), 'ip')).toBe(true)
    expect(matchesTargetFilter(preset('ip', 'either'), 'ip')).toBe(true)
    expect(matchesTargetFilter(preset('both', 'external'), 'ip')).toBe(true)
    expect(matchesTargetFilter(preset('both', 'either'), 'ip')).toBe(true)
    expect(matchesTargetFilter(preset('domain', 'external'), 'ip')).toBe(false)
  })

  // Regression guard: an internal preset is IP-typed but must NOT show under the
  // public 'External IP' tab - it belongs only under 'Local network'. If the
  // environment clause is ever dropped this test goes red.
  test("internal preset is excluded from 'ip' and included in 'internal'", () => {
    const internal = preset('ip', 'internal')
    expect(matchesTargetFilter(internal, 'ip')).toBe(false)
    expect(matchesTargetFilter(internal, 'internal')).toBe(true)
  })

  test("'internal' matches only environment==='internal'", () => {
    expect(matchesTargetFilter(preset('ip', 'internal'), 'internal')).toBe(true)
    expect(matchesTargetFilter(preset('ip', 'external'), 'internal')).toBe(false)
    expect(matchesTargetFilter(preset('both', 'either'), 'internal')).toBe(false)
    expect(matchesTargetFilter(preset('domain', 'external'), 'internal')).toBe(false)
  })
})

describe('matchesTargetFilter against the real registry', () => {
  test('every preset shows under the All tab', () => {
    for (const p of RECON_PRESETS) {
      expect(matchesTargetFilter(p, 'all')).toBe(true)
    }
  })

  test("the Local network tab shows exactly the internal-network preset", () => {
    const ids = RECON_PRESETS.filter((p) => matchesTargetFilter(p, 'internal')).map((p) => p.id)
    expect(ids).toEqual(['internal-network'])
  })

  test("the External IP tab includes large-network but not internal-network", () => {
    const ids = RECON_PRESETS.filter((p) => matchesTargetFilter(p, 'ip')).map((p) => p.id)
    expect(ids).toContain('large-network')
    expect(ids).not.toContain('internal-network')
  })

  test('no filter tab is ever empty (every tab has at least one preset)', () => {
    for (const filter of ['all', 'domain', 'ip', 'internal'] as TargetFilter[]) {
      const count = RECON_PRESETS.filter((p) => matchesTargetFilter(p, filter)).length
      expect(count).toBeGreaterThan(0)
    }
  })
})

describe('resolveIpModeForPreset', () => {
  test('create mode: ip forces on, domain forces off, both leaves alone', () => {
    expect(resolveIpModeForPreset('ip', 'create')).toBe(true)
    expect(resolveIpModeForPreset('domain', 'create')).toBe(false)
    expect(resolveIpModeForPreset('both', 'create')).toBeUndefined()
  })

  // ipMode is locked after project creation, so a preset applied in edit mode
  // must never change it - regardless of the preset's profile.
  test('edit mode: never changes ipMode for any profile', () => {
    expect(resolveIpModeForPreset('ip', 'edit')).toBeUndefined()
    expect(resolveIpModeForPreset('domain', 'edit')).toBeUndefined()
    expect(resolveIpModeForPreset('both', 'edit')).toBeUndefined()
  })

  test('the internal-network preset forces IP mode on when applied at create', () => {
    const internal = RECON_PRESETS.find((p) => p.id === 'internal-network')!
    expect(resolveIpModeForPreset(internal.targetProfile, 'create')).toBe(true)
  })
})

// Strategy row 5: a preset must not wipe a Domain-batch project's host list.
// resolveIpModeForPreset is the ONE place a preset can change the target mode.
// A 'domain' preset returning false would flip a batch project back to
// single-domain targeting, silently discarding the operator's hostname list
// (targetDomain is empty there, so the project would end up with no target).
describe('resolveIpModeForPreset: Domain batch projects', () => {
  test('a domain preset leaves a batch project alone', () => {
    expect(resolveIpModeForPreset('domain', 'create', 'batch')).toBeUndefined()
  })

  test('a both-profile preset leaves a batch project alone', () => {
    expect(resolveIpModeForPreset('both', 'create', 'batch')).toBeUndefined()
  })

  test('an explicitly IP-targeted preset may still switch a batch to IP mode', () => {
    expect(resolveIpModeForPreset('ip', 'create', 'batch')).toBe(true)
  })

  test('edit mode never changes the target mode, batch included', () => {
    expect(resolveIpModeForPreset('ip', 'edit', 'batch')).toBeUndefined()
    expect(resolveIpModeForPreset('domain', 'edit', 'batch')).toBeUndefined()
  })

  test('single-domain and IP projects behave exactly as before', () => {
    expect(resolveIpModeForPreset('domain', 'create', 'domain')).toBe(false)
    expect(resolveIpModeForPreset('ip', 'create', 'domain')).toBe(true)
    expect(resolveIpModeForPreset('both', 'create', 'domain')).toBeUndefined()
    expect(resolveIpModeForPreset('domain', 'create', 'ip')).toBe(false)
  })

  test('omitting the mode defaults to single-domain behaviour', () => {
    // Existing call sites pass two arguments; they must not change meaning.
    expect(resolveIpModeForPreset('domain', 'create')).toBe(false)
    expect(resolveIpModeForPreset('ip', 'create')).toBe(true)
  })
})
