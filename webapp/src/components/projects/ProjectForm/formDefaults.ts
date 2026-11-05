import type { Project } from '@prisma/client'

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
  domainBatchMode: false,
  domainBatchHosts: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}
