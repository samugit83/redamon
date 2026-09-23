import type { Project } from '@prisma/client'
import { DEFAULT_OPENAPI_DISCOVERY_PATHS } from '@/lib/openapi-defaults'

/**
 * Minimal fallback defaults - only required fields. Full defaults are fetched
 * from /api/projects/defaults (served by recon backend). Every form state is
 * built on top of these, edit mode included.
 */
export const MINIMAL_DEFAULTS: Partial<Project> = {
  name: '',
  description: '',
  targetDomain: '',
  subdomainList: [],
  ipMode: false,
  targetIps: [],
  domainBatchMode: false,
  domainBatchHosts: [],
  scanModules: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
  openapiEnabled: true,
  openapiAutoDiscover: false,
  openapiDiscoveryPaths: [...DEFAULT_OPENAPI_DISCOVERY_PATHS],
  openapiSources: [],
  openapiDiscoveryHeaders: [],
  openapiTimeout: 10,
  openapiMaxDocuments: 50,
}
