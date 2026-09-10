import type { Project } from '@prisma/client'

type ProjectFormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

/**
 * Which kind of target a preset is built for. Drives the preset-picker filter
 * chips AND the auto-flip of the project's `ipMode` toggle when a preset is
 * applied (see applyPreset in ProjectForm): 'ip' forces Start-from-IP on,
 * 'domain' forces it off, 'both' leaves the user's current choice untouched.
 * This is metadata only - it is NEVER written into `parameters`, because the
 * preset apply path strips ipMode/targetIps (they are user-owned identity
 * fields). See PRESET_EXCLUDED_FIELDS.
 */
export type PresetTargetProfile = 'domain' | 'ip' | 'both'

/**
 * Where the target lives. 'external' = public internet (domains, public IPs,
 * OSINT and passive sources return data). 'internal' = a local/private network
 * or Active Directory (RFC1918 space, where OSINT/passive lookups are useless).
 * 'either' = the preset works in both contexts. Used only to label and filter
 * presets so a user setting up a local test can find the right starting point.
 */
export type PresetEnvironment = 'external' | 'internal' | 'either'

export interface ReconPreset {
  id: string
  name: string
  icon: string
  image?: string
  shortDescription: string
  fullDescription: string
  targetProfile: PresetTargetProfile
  environment: PresetEnvironment
  parameters: Partial<ProjectFormData>
}
