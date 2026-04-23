import type { ReconPreset } from './types'
import { API_SECURITY } from './presets/api-security'
import { GRAPHQL_RECON } from './presets/graphql-recon'
import { BUG_BOUNTY_DEEP } from './presets/bug-bounty-deep'
import { BUG_BOUNTY_QUICK } from './presets/bug-bounty-quick'
import { FULL_ACTIVE_SCAN } from './presets/full-active-scan'
import { INFRASTRUCTURE_MAPPER } from './presets/infrastructure-mapper'
import { OSINT_INVESTIGATOR } from './presets/osint-investigator'
import { FULL_MAXIMUM_SCAN } from './presets/full-maximum-scan'
import { FULL_PASSIVE_SCAN } from './presets/full-passive-scan'
import { SECRET_MINER } from './presets/secret-miner'
import { SUBDOMAIN_TAKEOVER } from './presets/subdomain-takeover'
import { CVE_HUNTER } from './presets/cve-hunter'
import { CLOUD_EXPOSURE } from './presets/cloud-exposure'
import { COMPLIANCE_AUDIT } from './presets/compliance-audit'
import { DIRECTORY_DISCOVERY } from './presets/directory-discovery'
import { RED_TEAM_OPERATOR } from './presets/red-team-operator'
import { SECRET_HUNTER } from './presets/secret-hunter'
import { STEALTH_RECON } from './presets/stealth-recon'
import { WEB_APP_PENTESTER } from './presets/web-app-pentester'
import { PARAMETER_INJECTION } from './presets/parameter-injection'
import { DNS_EMAIL_SECURITY } from './presets/dns-email-security'
import { LARGE_NETWORK } from './presets/large-network'

export type { ReconPreset } from './types'

export const RECON_PRESETS: ReconPreset[] = [
  FULL_ACTIVE_SCAN,
  FULL_PASSIVE_SCAN,
  FULL_MAXIMUM_SCAN,
  BUG_BOUNTY_QUICK,
  BUG_BOUNTY_DEEP,
  API_SECURITY,
  GRAPHQL_RECON,
  INFRASTRUCTURE_MAPPER,
  OSINT_INVESTIGATOR,
  WEB_APP_PENTESTER,
  SECRET_MINER,
  SUBDOMAIN_TAKEOVER,
  STEALTH_RECON,
  CVE_HUNTER,
  RED_TEAM_OPERATOR,
  DIRECTORY_DISCOVERY,
  CLOUD_EXPOSURE,
  COMPLIANCE_AUDIT,
  SECRET_HUNTER,
  PARAMETER_INJECTION,
  DNS_EMAIL_SECURITY,
  LARGE_NETWORK,
]

export function getPresetById(id: string): ReconPreset | undefined {
  return RECON_PRESETS.find(p => p.id === id)
}
