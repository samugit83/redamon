import type { PresetTargetProfile, ReconPreset } from './types'

/**
 * Pure targeting logic for recon presets, extracted so it is unit-testable
 * without rendering the modal or the project form:
 *  - which presets a target-type filter shows, and
 *  - whether applying a preset should flip the project's Start-from-IP toggle.
 */

export type TargetFilter = 'all' | 'domain' | 'ip' | 'internal'

/** Does a preset belong in a given target-type filter tab? */
export function matchesTargetFilter(preset: ReconPreset, filter: TargetFilter): boolean {
  switch (filter) {
    case 'all':
      return true
    case 'domain':
      return preset.targetProfile === 'domain' || preset.targetProfile === 'both'
    case 'ip':
      // IP-capable AND reaches the public internet (external OSINT/enrichment
      // make sense). Internal-only presets are excluded here on purpose - they
      // live under the 'internal' tab.
      return (
        (preset.targetProfile === 'ip' || preset.targetProfile === 'both') &&
        (preset.environment === 'external' || preset.environment === 'either')
      )
    case 'internal':
      return preset.environment === 'internal'
    default:
      return true
  }
}

/**
 * The Start-from-IP value a preset should impose when applied, or `undefined`
 * to leave the user's current choice untouched.
 *
 * - Only in create mode: `ipMode` is locked after project creation, so a preset
 *   applied in edit mode must never change it.
 * - 'ip' presets force IP mode on, 'domain' presets force it off.
 * - 'both' presets are target-agnostic and leave the toggle as the user set it.
 *
 * This is the ONLY place a preset influences ipMode: the preset apply path
 * strips ipMode/targetIps from `parameters` (they are user-owned identity
 * fields), so the decision has to be driven from the preset's metadata here.
 */
export function resolveIpModeForPreset(
  targetProfile: PresetTargetProfile,
  mode: 'create' | 'edit',
  /** The project's current target mode. A Domain batch is a domain target, so a
   *  'domain' preset must NOT force it back to single-domain mode: that would
   *  silently discard the operator's hostname list. */
  currentMode: 'domain' | 'ip' | 'batch' = 'domain'
): boolean | undefined {
  if (mode !== 'create') return undefined
  if (currentMode === 'batch') {
    // Only an explicitly IP-targeted preset may pull a batch out of domain
    // targeting; everything else leaves the batch alone.
    return targetProfile === 'ip' ? true : undefined
  }
  if (targetProfile === 'ip') return true
  if (targetProfile === 'domain') return false
  return undefined
}
