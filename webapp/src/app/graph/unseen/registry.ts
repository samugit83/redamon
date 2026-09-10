/**
 * Which graph nodes back which table tab - the single source of truth for the
 * unseen-rows badges.
 *
 * The badge answers "has anything in this tab changed since I last looked at
 * it", and the only signal every row in every sheet is guaranteed to carry is
 * its write time (see UPDATED_AT_PROPS in the RedZoneTables `updatedAt`
 * module). So a tab's badge is a count of its backing nodes stamped after that
 * user's watermark for that tab.
 *
 * One entry per tab, labels unioned across ALL of the tab's sheets: opening
 * "AI Risk" shows every sheet's toolbar, so its badge covers every sheet too.
 *
 * Adding a tab means adding a row here - `registry.test.ts` fails the build
 * otherwise. That test is the whole reason this file exists rather than the
 * mapping living inside the count route: a feature whose contract is "on every
 * tab" decays one tab at a time when nothing enforces the list.
 */
import type { TableViewMode } from '../components/ViewTabs'

/**
 * Every label a scan writes into a project's graph, from the tenant indexes in
 * `graph_db/schema.py`. Backs the two tabs that show the graph as a whole.
 *
 * KBChunk is deliberately absent: it is the imported knowledge-base corpus, not
 * anything a scan found, and loading it would light up every badge with tens of
 * thousands of rows the user cannot act on. CVE / Capec / MitreData / Malware /
 * ThreatPulse look like reference data but are written per project by the
 * enrichment mixins, so they stay.
 */
export const ALL_GRAPH_LABELS = [
  'AttackChain', 'BaseURL', 'Capec', 'Certificate', 'ChainDecision', 'ChainFailure',
  'ChainFinding', 'ChainStep', 'CVE', 'DNSRecord', 'Domain', 'Endpoint', 'Exploit',
  'ExploitGvm', 'ExternalDomain', 'GithubHunt', 'GithubPath', 'GithubRepository',
  'GithubSecret', 'GithubSensitiveFile', 'Header', 'IP', 'JsReconFinding',
  'MalPackageFinding', 'Malware', 'MitreData', 'MultiscannerBucket',
  'MultiscannerEndpoint', 'MultiscannerFinding', 'MultiscannerImage',
  'MultiscannerModel', 'MultiscannerRepository', 'MultiscannerScan', 'Package',
  'Parameter', 'Port', 'SbomDocument', 'Secret', 'Service', 'Subdomain',
  'Technology', 'ThreatPulse', 'Traceroute', 'UserInput', 'Vulnerability',
] as const

/**
 * Tabs with no badge, and why.
 *
 * Recon Delta and Scans are not row tables over the graph: Delta compares two
 * scan versions on demand and Scans lists orchestrator jobs from Postgres.
 * Neither has "rows the user has not seen yet" to count.
 */
export const UNBADGED_TABS: readonly TableViewMode[] = ['reconDelta', 'scanSchedule', 'triage']

/**
 * The tabs that carry a badge.
 *
 * How each one is COUNTED lives next to the counting, in
 * `api/analytics/unseen/sources.ts`: two whole-graph tabs count nodes by label,
 * the rest invoke their own route and count the rows it returns. That split
 * matters and it is not cosmetic - counting the filtered sheets by label is
 * exactly the bug this list used to encode, where four new Vulnerability nodes
 * badged four unrelated tabs that all opened empty.
 */
export const BADGED_TABS = [
  'nodeDetails', 'all', 'jsRecon', 'aiSurface', 'aiRisk', 'killChain', 'blastRadius',
  'takeover', 'secrets', 'netInitAccess', 'graphql', 'webInitAccess', 'paramMatrix',
  'sharedInfra', 'dnsEmail', 'threatIntel', 'jsDepSignals', 'supplyChainSca',
  'dnsDrift', 'webCachePoison',
] as const satisfies readonly Exclude<TableViewMode, 'reconDelta' | 'scanSchedule' | 'triage'>[]

export type BadgedTab = (typeof BADGED_TABS)[number]

/** A user's per-tab watermarks: the instant they last saw each tab. */
export type UnseenMarks = Partial<Record<string, string>>

/** What the count endpoint returns. */
export interface UnseenResponse {
  /** Server time, the only clock a watermark may ever be stamped from. */
  now: string
  counts: Partial<Record<string, number>>
  /** The one number for the tab bar. Never a plain sum of `counts` - see `barTotal`. */
  total: number
}
