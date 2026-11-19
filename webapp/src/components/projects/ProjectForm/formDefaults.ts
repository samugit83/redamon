import type { Project } from '@prisma/client'

import { field } from '@/lib/reconSettings/registry'

/**
 * A numeric column's Prisma default, read from the registry: what an input
 * writes when the operator clears it, and what it shows while the project holds
 * no value. A literal in its place drifted from the default in a dozen sections
 * with nothing noticing; `sections/clearedFallbacks.test.ts` holds the literals
 * that remain to the registry.
 */
export function numericDefault(key: keyof Project): number {
  const value = field(key)?.default
  if (typeof value !== 'number') throw new Error(`${key} has no numeric default in the registry`)
  return value
}

/**
 * Minimal fallback defaults - only required fields. Full defaults are fetched
 * from /api/projects/defaults (served by recon backend). Every form state is
 * built on top of these, edit mode included.
 */
export const MINIMAL_DEFAULTS: Partial<Project> = {
  name: '',
  jevProviderId: null,
  description: '',
  targetDomain: '',
  subdomainList: [],
  ipMode: false,
  targetIps: [],
  // Hostnames on target IPs: the Prisma defaults, so a form opened while
  // /defaults is unreachable still sends the strictest policy.
  ipHostnameMode: 'ip_only',
  ipHostnameInclude: [],
  ipHostnameExclude: [],
  ipHostnamePassiveExpand: true,
  ipHostnameScanAllConfirmed: false,
  ipHostnameMaxScanned: 100,
  ipHostnamePassiveMaxNames: 500,
  domainBatchMode: false,
  domainBatchHosts: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}
