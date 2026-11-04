/**
 * The services whose API key accepts extra keys for Key Rotation.
 *
 * The single list behind three consumers that used to keep their own copies:
 * the settings page (which fields get a Key Rotation button), the settings PUT
 * (which `ApiKeyRotationConfig` rows it persists) and the API-keys template
 * (which rotation entries it exports and accepts on import). The copies drifted:
 * the PUT lacked wpscan, securitytrails and viewdns, so extra keys typed for
 * them were accepted by the form and silently dropped on save.
 *
 * `tool` is the `ApiKeyRotationConfig.toolName` recon and the agent read the
 * extra keys under; `field` is the `UserSettings` column of the primary key.
 * Order is the template's order.
 */
export const ROTATION_TOOLS = [
  { tool: 'tavily', field: 'tavilyApiKey', label: 'Tavily' },
  { tool: 'shodan', field: 'shodanApiKey', label: 'Shodan' },
  { tool: 'serp', field: 'serpApiKey', label: 'SerpAPI' },
  { tool: 'nvd', field: 'nvdApiKey', label: 'NVD' },
  { tool: 'vulners', field: 'vulnersApiKey', label: 'Vulners' },
  { tool: 'urlscan', field: 'urlscanApiKey', label: 'URLScan' },
  { tool: 'fofa', field: 'fofaApiKey', label: 'FOFA' },
  { tool: 'otx', field: 'otxApiKey', label: 'AlienVault OTX' },
  { tool: 'netlas', field: 'netlasApiKey', label: 'Netlas' },
  { tool: 'virustotal', field: 'virusTotalApiKey', label: 'VirusTotal' },
  { tool: 'zoomeye', field: 'zoomEyeApiKey', label: 'ZoomEye' },
  { tool: 'criminalip', field: 'criminalIpApiKey', label: 'Criminal IP' },
  { tool: 'securitytrails', field: 'securitytrailsApiKey', label: 'SecurityTrails' },
  { tool: 'viewdns', field: 'viewdnsApiKey', label: 'ViewDNS' },
  { tool: 'quake', field: 'quakeApiKey', label: 'Quake' },
  { tool: 'hunter', field: 'hunterApiKey', label: 'Hunter' },
  { tool: 'publicwww', field: 'publicWwwApiKey', label: 'PublicWWW' },
  { tool: 'hunterhow', field: 'hunterHowApiKey', label: 'HunterHow' },
  { tool: 'onyphe', field: 'onypheApiKey', label: 'Onyphe' },
  { tool: 'driftnet', field: 'driftnetApiKey', label: 'Driftnet' },
  { tool: 'wpscan', field: 'wpscanApiToken', label: 'WPScan' },
  { tool: 'pdcp', field: 'pdcpApiKey', label: 'PDCP' },
  { tool: 'jsmon', field: 'jsmonApiKey', label: 'Jsmon Subdomains' },
] as const

export type RotationToolName = (typeof ROTATION_TOOLS)[number]['tool']

export const ROTATION_TOOL_NAMES: readonly RotationToolName[] = ROTATION_TOOLS.map(t => t.tool)

/** Settings field of the primary key -> its rotation tool. */
export const ROTATION_TOOL_BY_FIELD: Readonly<Record<string, RotationToolName>> = Object.fromEntries(
  ROTATION_TOOLS.map(t => [t.field, t.tool]),
)

export function isRotationTool(name: string): name is RotationToolName {
  return (ROTATION_TOOL_NAMES as readonly string[]).includes(name)
}
