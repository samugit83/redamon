/**
 * The tool that explains the recon pipeline rather than reading a project.
 * (Its sibling, list_recon_presets, reads the user's presets now and lives in
 * presetTools.ts.)
 *
 * `update_recon_settings` was a 126-field API whose only reference manual was
 * `get_recon_settings`, which returns key names and current values: no meaning,
 * no type, no bounds, no enum domains, no grouping. An agent learned a bound by
 * being refused, one field at a time, and because one bad key refuses the WHOLE
 * call, a batch of guesses applied nothing at all.
 *
 * It follows the `graph_schema` shape: no projectId, no database, no tenant
 * data. It is derived from constants in this build, so it still answers when
 * Neo4j and Postgres are down.
 *
 * It is served from `recon_settings/registry.yaml`, which carries the
 * unit, the phase, the traffic class, the engagement-cap flag, the bounds or
 * the validator, and a meaning for every one of the 712 Project columns. The
 * reference manual and the thing it describes are therefore the same file, so
 * an agent that trusts `describe_recon_settings` cannot be surprised by
 * `update_recon_settings`.
 */
import { settableFieldCount } from '@/lib/reconSettings/filter'
import {
  loadRegistry,
  settableFields,
  type RegistryField,
} from '@/lib/reconSettings/registry'
import { SCAN_MODULE_VALUES, SEVERITY_VALUES } from '@/lib/reconSettings/validators'
import { requireScope } from '@/lib/mcpAuth'
import { McpToolError } from '@/lib/mcp/errors'
import { enforceRate, type McpContext } from '@/lib/mcp/tools'

// --- the settings reference -----------------------------------------------------

export interface SettingDoc {
  key: string
  /** The value shape, joined from Prisma at registry build time. */
  kind: string
  min?: number
  max?: number
  /** The closed set of values a list or enum field accepts, when it has one. */
  values?: readonly string[]
  /** The named validator a free-form value is checked against. */
  validator?: string
  unit: string
  phase: string
  /** none | passive | active: whether writing this sends traffic at the target. */
  traffic: string
  /** True when the engagement rate ceiling rewrites this value at scan start. */
  roeCapped?: boolean
  /** 'unlimited' when 0 is the FASTEST value, not the slowest. */
  zeroMeans?: string
  meaning: string
}

export interface SettingGroup {
  group: string
  settings: SettingDoc[]
}

let cachedGroups: SettingGroup[] | null = null

/** One tool's title, for the group heading. */
function groupName(tool: string): string {
  return loadRegistry().tools[tool]?.title ?? tool
}

function toDoc(key: string, spec: RegistryField): SettingDoc {
  return {
    key,
    kind: spec.type,
    ...(spec.bounds ? { min: spec.bounds.min, max: spec.bounds.max } : {}),
    ...(spec.values ? { values: spec.values } : {}),
    ...(spec.validator ? { validator: spec.validator } : {}),
    unit: spec.unit,
    phase: spec.phase,
    traffic: spec.traffic,
    ...(spec.roe_capped ? { roeCapped: true } : {}),
    ...(spec.zero_means ? { zeroMeans: spec.zero_means } : {}),
    meaning: spec.meaning,
  }
}

/**
 * Every settable field, grouped by the tool it configures.
 *
 * Driven by the REGISTRY, which is also what `update_recon_settings` validates
 * against, so the two cannot disagree. Grouping by tool rather than by an
 * arbitrary documentation section means the group an agent reads is the thing
 * it is configuring.
 */
export function settingGroups(): SettingGroup[] {
  if (cachedGroups) return cachedGroups
  const byTool = new Map<string, SettingDoc[]>()
  for (const f of settableFields()) {
    const list = byTool.get(f.tool)
    const doc = toDoc(f.key, f)
    if (list) list.push(doc)
    else byTool.set(f.tool, [doc])
  }
  cachedGroups = [...byTool.entries()]
    .map(([tool, settings]) => ({ group: groupName(tool), settings }))
    .sort((a, b) => a.group.localeCompare(b.group))
  return cachedGroups
}

/** Test seam: the grouping is cached because the registry is constant per build. */
export function __resetCatalogCache(): void {
  cachedGroups = null
}

const PHASE_NOTES: Record<string, string> = {
  domain_discovery: 'Subdomain enumeration and DNS. The phase every later one draws its hosts from.',
  port_scan: 'Port scanning (Naabu, Masscan) and service/banner identification.',
  http_probe: 'HTTP probing and technology fingerprinting of the hosts found so far.',
  resource_enum: 'Crawling, directory fuzzing, parameter and API discovery.',
  vuln_scan: 'Nuclei templates, takeover checks and the CVE / MITRE enrichment that hangs off them.',
  js_recon: 'Not a phase: accepted for older projects and ignored. JavaScript analysis (source maps, ' +
    'secrets, endpoints) runs on jsReconEnabled alone, after resource_enum, on the JS files ' +
    'resource_enum and http_probe found.',
}

const NOTES = [
  'Configuration is TWO levels, and this is the mistake to avoid. `scanModules` decides which ' +
    'pipeline PHASES run at all; the per-tool `*Enabled` flags decide which tools run inside a ' +
    'phase. Setting one without the other is a silent no-op.',
  'Concretely: with "port_scan" in scanModules but naabuEnabled and masscanEnabled both false, ' +
    'the pipeline logs "skipping port scan phase" and continues. The scan runs, nothing is port ' +
    'scanned, and no result field says why. Enable the phase AND at least one tool in it.',
  'A phase that is not in scanModules does not run whatever its tools are set to.',
  'JS recon is the one exception: it is no scanModules phase. jsReconEnabled alone switches it ' +
    'on, and it analyzes the JS files resource_enum and http_probe found, so keep one of them in ' +
    'scanModules. jsluice runs inside resource_enum.',
  'Sections listed as standalone scanners are not pipeline phases and are not gated by ' +
    'scanModules at all; they are separate jobs.',
  'These are the fields THIS surface may write. A key absent from them is refused BY NAME, ' +
    'never silently ignored, and one bad key refuses the whole call - so read the bounds ' +
    'rather than probing for them.',
  'One more field set exists and is not listed here: the engagement scope is fixed at ' +
    'creation and is set through create_project. Writing it through update_recon_settings is ' +
    'refused with a pointer to the right tool.',
  'The engagement LIMITS - roeGlobalMaxRps, roeExcludedHosts, the time window, ' +
    'roeForbiddenTools, roeForbiddenCategories, the allow flags and roeMaxSeverityPhase - ARE ' +
    'listed and ARE settable here, in either direction. What keeps them honest is not a ' +
    'write-time direction rule but that every one of them is enforced at scan start whatever ' +
    'the setting says: a ceiling still caps every rate field it governs, an excluded host is still ' +
    'dropped in three places. Read preflight_scope_check to see the resolved configuration.',
  'The engagement RECORD - the client name, the contacts, the dates, the document - is not ' +
    'here and is not writable by any tool on this surface. It is the contract, a person ' +
    'writes it, and it carries third-party personal data.',
  'A value is VALIDATED and then CAPPED, not blocked. A rate above the engagement ceiling is ' +
    'rewritten to the ceiling at scan start, and a container image outside the shipped ' +
    'allowlist is pinned back to the default. get_recon_settings echoes what you wrote; ' +
    'preflight_scope_check reports what will actually run.',
  'Where zeroMeans is "unlimited", 0 is the FASTEST value the field accepts and not the ' +
    'safest. Under an engagement ceiling a 0 there is rewritten to the ceiling.',
  'Settings apply to the NEXT scan. A scan already running read its settings when it started.',
  'routeExposureEnabled writes two kinds of Vulnerability under one source, route_exposure: ' +
    'leads for the agent (needs_agent_confirmation true, severity info, hidden from reports until ' +
    'confirmed) and findings a signature proves (real severity). It runs whenever active scanning ' +
    'runs, with no scanModules phase of its own, and sends GET and HEAD only.',
  'urlscanEnabled reads public urlscan.io history only; RedAmon never submits a urlscan scan. ' +
    'Its findings (Vulnerability source urlscan_leak: leaked one-time links, sensitive files, ' +
    'open redirects, problem and takeover pages; Secret source urlscan) are "seen on urlscan", ' +
    'never confirmed by RedAmon, never agent leads, and at most high. An Endpoint with ' +
    'quarantined true (a leaked link, a secret in its URL) is never a request target and has no ' +
    'full_url. Without a urlscan key: the last 30 days only, 100 visits per search, at most 1,000 ' +
    'read. urlscanMaxSearches caps the searches per scan for every caller; Origin Discovery\'s ' +
    'urlscan source adds at most 3, and is skipped whenever urlscanEnabled is false.',
  'AI hooks have THREE levels: aiInPipeline, then the per-hook AI flag, then the *UseJev engine. ' +
    'At scan start aiInPipeline forces every per-hook AI flag to its own value; it does not touch ' +
    'the engine fields. A *UseJev flag only switches which engine answers (false = the LLM in ' +
    'aiPipelineModel, true = TypeSafe Jev), and switching one ON is refused unless the project ' +
    'selects a Jev provider (jevProviderId) on its owner\'s account. preflight_scope_check reports ' +
    'each hook\'s effective engine.',
  'Jev-only hooks have TWO levels: aiInPipeline, then the hook\'s own *Jev* flag (ffufJevBasePaths, ' +
    'httpxJevPageType, resourceEnumJevToolHealth, hakrawlerJevSeedOrder, serializedScanJevRank, ' +
    'routeExposureJevRank, routeExposureJevWallCheck, routeExposureJevAssess). ' +
    'They have no LLM engine, aiInPipeline does not set or reset them, and switching one ON is ' +
    'refused unless the project selects a Jev provider (jevProviderId) on its owner\'s account. ' +
    'Page types, base paths and seed order take ' +
    'effect from Jev\'s answers (page-type labels land on the Endpoint, FFuf fuzzes Jev\'s ' +
    'directories, Hakrawler crawls Jev\'s host order, and each serialized-object candidate gets ' +
    'Jev\'s deser_jev_format and deser_jev_exploitability, the order the deserialization skill ' +
    'confirms them in; that ranking needs serializedScanEnabled too). The three route exposure ' +
    'hooks act too, and need routeExposureEnabled: Jev\'s privacy answer fills the request budget ' +
    'after the always-requested floor, and each lead gets Jev\'s route_jev_kind, ' +
    'route_jev_sensitivity and anon_page_class, the order the access_control skill confirms them ' +
    'in (most sensitive first, a login wall, error page or public content last; no lead is ' +
    'ever dropped). The tool-health check records ' +
    'its verdict in the recon output. Without a token, or when Jev cannot answer, each step runs ' +
    'exactly as it does without AI.',
]

/**
 * The shape of the recon configuration, with no values in it.
 *
 * Deliberately no current values: `get_recon_settings` answers that, and
 * duplicating it means two tools disagree the moment one is cached. This one
 * describes the shape, that one reports the state.
 */
export async function describeReconSettings(ctx: McpContext, args: { group?: string } = {}) {
  requireScope(ctx.token, 'recon:read')
  enforceRate(ctx, 'read')

  const all = settingGroups()
  const wanted = args.group?.trim().toLowerCase()
  const groups = wanted
    ? all.filter(g => g.group.toLowerCase().includes(wanted))
    : all

  if (wanted && groups.length === 0) {
    throw new McpToolError(
      `No settings group matches '${args.group}'. Call this tool with no arguments to see the ` +
      `group names.`,
      'bad_args'
    )
  }

  return {
    phases: SCAN_MODULE_VALUES.map(module => ({ module, what: PHASE_NOTES[module] ?? '' })),
    enums: { scanModules: SCAN_MODULE_VALUES, severity: SEVERITY_VALUES },
    groups,
    settableFieldCount: settableFieldCount(),
    dispositions: {
      settable: 'write any time through update_recon_settings',
      create_only: 'the engagement scope: set once by create_project, immutable after',
      never: 'not a pipeline parameter; refused with its class',
    },
    notes: NOTES,
  }
}
