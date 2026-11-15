/**
 * AI Navigator's read tools (plan §7.8). Each declares the permissions it needs (ALL of them: the
 * one that guards the same data in the UI and, where it differs, the one whose `mcpScopes` grants
 * the scope the MCP function asks), the exact MCP scopes that function asks, and the minimum project
 * level. The tool route checks every permission with can(), fresh, before a handler runs;
 * registry.test.ts holds the scopes equal to the functions' own `requireScope`.
 *
 * Read-only by construction: no tool here writes, starts anything or reaches past RedAmon. A new
 * tool declares its permissions, its exact MCP scopes and its level, and gets a refusal test. It
 * may never take a process-wide resource (the graph snapshot slots): `compare_scan_versions` takes
 * two stored versions only.
 *
 * Descriptions are LLM-facing content written for the Navigator's own tool names.
 */
import prisma from '@/lib/prisma'
import type { PermissionId, ProjectLevel } from '@/lib/authz/permissions'
import type { McpScope } from '@/lib/mcpAuth'
import type { McpContext } from '@/lib/mcp/tools'
import { UNTRUSTED_DATA_NOTE } from '@/lib/mcp/toolText'
import {
  getProjectActivity, getReconSettings, getReconStatus, graphSummary, listRemediations, queryGraph,
} from '@/lib/mcp/tools'
import { FINDING_SECTIONS, listFindings, listMuted } from '@/lib/mcp/findingTools'
import { DISPOSITIONS } from '@/lib/triage/disposition'
import { getAttackSurfaceOverview, getBlastRadius, listExploitPaths } from '@/lib/mcp/analyticsTools'
import { compareScanVersions, listScanVersions } from '@/lib/mcp/versionTools'
import { getScanStatus, SCANNER_NAMES } from '@/lib/mcp/scannerTools'
import { getTriageStatus } from '@/lib/mcp/triageTools'
import { listGraphViews } from '@/lib/mcp/viewTools'
import { describeReconSettings } from '@/lib/mcp/catalogTools'
import type { DataRoute } from '../constants'
import {
  RUN_CYPHER_TIMEOUT_S, TOOL_TIMEOUT_S, WORKSPACE_MAX_ENTRIES, WORKSPACE_READ_MAX_BYTES, WORKSPACE_TREE_MAX_DEPTH,
} from '../constants'
import type { ArgsSchema } from './validate'
import { workspaceList, workspaceRead, workspaceTree } from './workspace'

export interface ToolRunContext {
  mcp: McpContext
  projectId: string
  /** The project's owner: the tenant of every read. */
  tenantId: string
}

export type ToolArgs = Record<string, string | number | boolean>

export interface NavigatorTool {
  name: string
  route: DataRoute
  description: string
  parameters: ArgsSchema
  permissions: readonly PermissionId[]
  mcpScopes: readonly McpScope[]
  level: ProjectLevel
  timeoutS: number
  /** A rule the schema cannot say; a refusal sentence, or null. */
  check?: (args: ToolArgs) => string | null
  handler: (ctx: ToolRunContext, args: ToolArgs) => Promise<unknown>
}

const NO_ARGS: ArgsSchema = { type: 'object', properties: {}, additionalProperties: false }
const str = (args: ToolArgs, key: string) => (typeof args[key] === 'string' ? (args[key] as string) : undefined)
const num = (args: ToolArgs, key: string) => (typeof args[key] === 'number' ? (args[key] as number) : undefined)

const COVERAGE_NOTE = 'Muted (suppressed) findings never appear here; the absence of data is not proof of absence.'

const TOOLS: readonly NavigatorTool[] = [
  {
    name: 'graph_summary', route: 'graph', permissions: ['graph:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'Start here for any question about this project\'s graph: counts per node type, what was scanned ' +
      'and the coverage of each scanner, so you know what the project actually contains. ' + UNTRUSTED_DATA_NOTE,
    handler: (c) => graphSummary(c.mcp, c.projectId),
  },
  {
    name: 'list_findings', route: 'graph', permissions: ['triage:read', 'graph:read'], mcpScopes: ['recon:read'],
    level: 'R', timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, properties: {
        limit: { type: 'integer', minimum: 1, maximum: 100, description: 'How many (default 25).' },
        offset: { type: 'integer', minimum: 0, maximum: 10000 },
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        section: { type: 'string', enum: FINDING_SECTIONS, description: '"resolved" means a scanner stopped reporting it, not that it was fixed.' },
        disposition: { type: 'string', enum: DISPOSITIONS },
      },
    },
    description: 'What the scans FOUND on this project (vulnerabilities, CVE matches, secrets, misconfigurations...), ' +
      'in triage order. Read `triageState`: "never_run" means nothing is scored yet and the order is scanner severity only. ' +
      '`disposition` "reportable" means proven or confirmed by a person; "candidate" means verify first. ' +
      `${COVERAGE_NOTE} ${UNTRUSTED_DATA_NOTE}`,
    handler: (c, a) => listFindings(c.mcp, c.projectId, {
      limit: num(a, 'limit'), offset: num(a, 'offset'), severity: str(a, 'severity'), section: str(a, 'section'),
      disposition: str(a, 'disposition') as (typeof DISPOSITIONS)[number] | undefined,
    }),
  },
  {
    name: 'list_muted_findings', route: 'graph', permissions: ['triage:read'], mcpScopes: ['triage:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: { type: 'object', additionalProperties: false, properties: { detail: { type: 'boolean' } } },
    description: 'The findings a person muted (suppressed as noise) on this project, which every other tool hides. ' + UNTRUSTED_DATA_NOTE,
    handler: (c, a) => listMuted(c.mcp, c.projectId, { detail: a.detail === true }),
  },
  {
    name: 'attack_surface_overview', route: 'graph', permissions: ['graph:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'The Insights overview of the attack surface: exposed services, technologies, risky ports and the ' +
      'severity mix, aggregated. ' + UNTRUSTED_DATA_NOTE,
    handler: (c) => getAttackSurfaceOverview(c.mcp, c.projectId),
  },
  {
    name: 'list_exploit_paths', route: 'graph', permissions: ['graph:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'Paths from an exposed entry point to a vulnerability or secret in this project\'s graph. ' + UNTRUSTED_DATA_NOTE,
    handler: (c) => listExploitPaths(c.mcp, c.projectId),
  },
  {
    name: 'blast_radius', route: 'graph', permissions: ['graph:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'Which assets each vulnerable technology or host would expose if compromised. ' + UNTRUSTED_DATA_NOTE,
    handler: (c) => getBlastRadius(c.mcp, c.projectId),
  },
  {
    name: 'run_cypher', route: 'graph', permissions: ['graph:cypher', 'graph:read'], mcpScopes: ['recon:read', 'graph:cypher'],
    level: 'R', timeoutS: RUN_CYPHER_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, required: ['cypher'], properties: {
        cypher: { type: 'string', maxLength: 4000, description: 'One read-only Cypher query; label every node pattern; add LIMIT.' },
      },
    },
    description: 'Run one READ-ONLY Cypher query on this project\'s graph, for specific questions the typed tools do not ' +
      'answer. Tenant isolation is applied for you: label every node pattern (MATCH (s:Subdomain)), never a bare (n) ' +
      'except to look a node up by id(n). A query the scoper cannot prove scoped is refused: fix it and retry once. ' +
      'On a project shared with the user it needs Raw data & files. ' + `${COVERAGE_NOTE} ${UNTRUSTED_DATA_NOTE}`,
    handler: (c, a) => queryGraph(c.mcp, c.projectId, { cypher: str(a, 'cypher') }),
  },
  {
    name: 'recon_status', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'Whether a recon is running on this project, its phase, and how the last one ended.',
    handler: (c) => getReconStatus(c.mcp, c.projectId),
  },
  {
    name: 'scan_status', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, required: ['scanner'], properties: {
        scanner: { type: 'string', enum: SCANNER_NAMES },
      },
    },
    description: 'The status of one of the separate scanners on this project (GVM, GitHub secret hunt, supply chain, ' +
      'TruffleHog, AI attack surface, partial recon): running or not, when it last ran and how it ended.',
    handler: (c, a) => getScanStatus(c.mcp, c.projectId, str(a, 'scanner') ?? ''),
  },
  {
    name: 'list_scan_versions', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: { type: 'object', additionalProperties: false, properties: { limit: { type: 'integer', minimum: 1, maximum: 50 } } },
    description: 'The stored scan versions of this project (the scan history), newest first, with their ids and counts.',
    handler: (c, a) => listScanVersions(c.mcp, c.projectId, { limit: num(a, 'limit') }),
  },
  {
    name: 'compare_scan_versions', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, required: ['from', 'to'], properties: {
        from: { type: 'string', maxLength: 64, description: 'The older version id, from list_scan_versions.' },
        to: { type: 'string', maxLength: 64, description: 'The newer version id, from list_scan_versions.' },
      },
    },
    description: 'What changed between two STORED scan versions: nodes added and removed per type. For "what changed ' +
      'since the last scan" compare the two newest versions from list_scan_versions. The live graph cannot be compared.',
    check: (a) => {
      for (const side of ['from', 'to']) {
        const v = str(a, side)
        if (!v || v.toLowerCase() === 'current') return 'Compare two stored versions by id, from list_scan_versions; the live graph cannot be compared here.'
      }
      return null
    },
    handler: (c, a) => compareScanVersions(c.mcp, c.projectId, { from: str(a, 'from'), to: str(a, 'to') }),
  },
  {
    name: 'recon_settings', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'The recon pipeline settings in force on this project: targets, which tools are on and their options.',
    handler: (c) => getReconSettings(c.mcp, c.projectId),
  },
  {
    name: 'describe_recon_settings', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: { type: 'object', additionalProperties: false, properties: { group: { type: 'string', maxLength: 60 } } },
    description: 'What each recon setting means (the settings catalog), optionally for one group. Static, no project data.',
    handler: (c, a) => describeReconSettings(c.mcp, { group: str(a, 'group') }),
  },
  {
    name: 'project_activity', route: 'records', permissions: ['recon:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'Recent activity on this project: scans, agent runs, triage runs and their times.',
    handler: (c) => getProjectActivity(c.mcp, c.projectId),
  },
  {
    name: 'list_remediations', route: 'records', permissions: ['remediation:read', 'triage:read'], mcpScopes: ['triage:read'],
    level: 'R', timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, properties: {
        status: { type: 'string', maxLength: 30 },
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        limit: { type: 'integer', minimum: 1, maximum: 100 },
        offset: { type: 'integer', minimum: 0, maximum: 10000 },
      },
    },
    description: 'The remediations (CypherFix fix list) of this project, with their status and severity. ' + UNTRUSTED_DATA_NOTE,
    handler: (c, a) => listRemediations(c.mcp, c.projectId, {
      status: str(a, 'status'), severity: str(a, 'severity'), limit: num(a, 'limit'), offset: num(a, 'offset'),
    }),
  },
  {
    name: 'triage_status', route: 'records', permissions: ['triage:read'], mcpScopes: ['triage:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'The Priority Board\'s state: whether AI triage ran, when, whether it is running, and the counts it scored.',
    handler: (c) => getTriageStatus(c.mcp, c.projectId),
  },
  {
    name: 'list_graph_views', route: 'records', permissions: ['graph:read'], mcpScopes: ['recon:read'], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'The saved graph views of this project (names and descriptions).',
    handler: (c) => listGraphViews(c.mcp, c.projectId),
  },
  {
    name: 'list_reports', route: 'records', permissions: ['reports:read'], mcpScopes: [], level: 'R',
    timeoutS: TOOL_TIMEOUT_S, parameters: NO_ARGS,
    description: 'The pentest reports generated for this project, newest first (title, format, date). Not their content.',
    handler: async (c) => ({
      reports: await prisma.report.findMany({
        where: { projectId: c.projectId },
        orderBy: { createdAt: 'desc' },
        take: 50,
        select: { id: true, title: true, format: true, createdAt: true },
      }),
    }),
  },
  {
    name: 'workspace_tree', route: 'workspace', permissions: ['workspace:read'], mcpScopes: [], level: 'R*',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, properties: {
        path: { type: 'string', maxLength: 300, description: 'A folder relative to the workspace root (default the root).' },
        maxDepth: { type: 'integer', minimum: 1, maximum: WORKSPACE_TREE_MAX_DEPTH },
      },
    },
    description: 'The folder tree of this project\'s agent workspace (notes, tool outputs, uploads).',
    handler: (c, a) => workspaceTree(c.projectId, str(a, 'path') ?? '.', num(a, 'maxDepth') ?? 3, WORKSPACE_MAX_ENTRIES),
  },
  {
    name: 'workspace_list', route: 'workspace', permissions: ['workspace:read'], mcpScopes: [], level: 'R*',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, properties: {
        path: { type: 'string', maxLength: 300 },
        limit: { type: 'integer', minimum: 1, maximum: WORKSPACE_MAX_ENTRIES },
      },
    },
    description: 'The files and folders in one folder of this project\'s agent workspace, with sizes and dates.',
    handler: (c, a) => workspaceList(c.projectId, str(a, 'path') ?? '.', num(a, 'limit') ?? WORKSPACE_MAX_ENTRIES),
  },
  {
    name: 'workspace_read', route: 'workspace', permissions: ['workspace:read'], mcpScopes: [], level: 'R*',
    timeoutS: TOOL_TIMEOUT_S,
    parameters: {
      type: 'object', additionalProperties: false, required: ['path'], properties: {
        path: { type: 'string', maxLength: 300, description: 'A text file relative to the workspace root.' },
      },
    },
    description: `Read one TEXT file of this project's agent workspace (at most ${WORKSPACE_READ_MAX_BYTES} bytes; binary ` +
      'files are refused). Secrets in it may be masked. ' + UNTRUSTED_DATA_NOTE,
    handler: (c, a) => workspaceRead(c.projectId, str(a, 'path') ?? ''),
  },
]

const BY_NAME: ReadonlyMap<string, NavigatorTool> = new Map(TOOLS.map((t) => [t.name, t]))

export function navigatorTools(): readonly NavigatorTool[] {
  return TOOLS
}

export function navigatorTool(name: string): NavigatorTool | undefined {
  return BY_NAME.get(name)
}
