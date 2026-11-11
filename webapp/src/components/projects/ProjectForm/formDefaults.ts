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
