/**
 * The permission registry: every permission a person can hold (feature document §5.1-§5.12,
 * 98 ids), with what the policy, the UI and the upgrade need to know about each one.
 *
 * One vocabulary for route checks, the permission screens, MCP token scopes and the built-in
 * sets (PE-02): `assertKnownPermission` rejects any other string. The plugin platform keeps its
 * own capability names (`lib/plugins/permissions.ts`) and its own `assertPermission` in the
 * Gateway, which is why this check has a different name; the two id sets never overlap (a test).
 *
 * Data only: nothing here reads the database, the switches or the request, so the browser can
 * import it too.
 */
import type { McpScope } from '@/lib/mcpAuth'

/**
 * The project level a permission needs (§5 legend): `R` read; `R*` read plus the raw data and
 * files toggle; `W` read and write; `W+S`, `W+A`, `W+X` write plus the run scans, use AI agent or
 * exploitation and shells toggle; `M` the manage toggle (co-owner); `O` the owner only.
 */
export const PROJECT_LEVELS = ['R', 'R*', 'W', 'W+S', 'W+A', 'W+X', 'M', 'O'] as const
export type ProjectLevel = (typeof PROJECT_LEVELS)[number]

/** The release an entry was introduced in, until the owner names it. */
export const UNRELEASED = 'UNRELEASED'

export interface PermissionMeta {
  /** `admin`: the administration and platform side (§5.1, §5.2), held through an admin profile. */
  kind: 'admin' | 'member'
  /** `project`: checked against the caller's access level on the project the action names. */
  scope: 'instance' | 'project'
  /**
   * For a project permission, the level it needs. An instance permission has none, except one
   * that also acts on a project (`project:share`, `plugins:approve_overrides`): the level it needs
   * on that project.
   */
  level: ProjectLevel | null
  /** What holding it allows, worded for the permission screens. */
  description: string
  /** Reaches other people's data or work; never in a default member set (§4.1 rule 8, PE-05). */
  crossTenant: boolean
  /**
   * Runs in the sandbox every project shares, so it reaches beyond the project without being a
   * platform tool (OQ-46): kept in *Default member* as today, labelled in the UI and the share
   * dialog, step-up when granted by override.
   */
  sandboxShared: boolean
  /** As strong as taking the account over (§4.5, PE-12). */
  takeoverEquivalent: boolean
  /**
   * Never in a built-in profile and never held by an unconfirmed Root. Only `admins:manage` may
   * go into a custom admin profile, put there by Root (OQ-02); a profile write refuses the others.
   */
  rootOnly: boolean
  /** The inbound MCP token scopes this permission absorbs (§5.13). */
  mcpScopes: readonly McpScope[]
  /** §14.8: the release that introduced it. */
  introducedIn: string
  /**
   * §14.8: it stands in front of a feature RedAmon already has (true), so a later release adds a
   * new one of these to custom sets wherever the feature was allowed; false for a feature a later
   * phase of this release builds (sharing, transfer, oversight, audit viewer, quotas, conversation
   * sharing, traffic replay, operations view), which custom sets show as available, not granted.
   */
  gatesExisting: boolean
  /**
   * Closes one of the §3 cross-tenant holes: never added to a custom set automatically, even when
   * it gates an existing feature, or the release would reopen the hole (§14.8); existing holders
   * go through the legacy-grant review (§14.7).
   */
  closesCrossTenantHole: boolean
}

type Flags = Pick<
  PermissionMeta,
  'crossTenant' | 'sandboxShared' | 'takeoverEquivalent' | 'rootOnly' | 'gatesExisting' | 'closesCrossTenantHole'
> & { mcpScopes: McpScope[] }

const NO_FLAGS: Flags = {
  crossTenant: false,
  sandboxShared: false,
  takeoverEquivalent: false,
  rootOnly: false,
  gatesExisting: true,
  closesCrossTenantHole: false,
  mcpScopes: [],
}

function entry(
  kind: PermissionMeta['kind'],
  scope: PermissionMeta['scope'],
  level: ProjectLevel | null,
  description: string,
  flags: Partial<Flags> = {},
): PermissionMeta {
  const { mcpScopes, ...rest } = { ...NO_FLAGS, ...flags }
  return Object.freeze({ kind, scope, level, description, ...rest, mcpScopes: Object.freeze([...mcpScopes]), introducedIn: UNRELEASED })
}

const admin = (description: string, flags?: Partial<Flags>) => entry('admin', 'instance', null, description, flags)
const platform = (description: string, flags?: Partial<Flags>) =>
  admin(description, { crossTenant: true, closesCrossTenantHole: true, ...flags })
const self = (description: string, flags?: Partial<Flags>) => entry('member', 'instance', null, description, flags)
const project = (level: ProjectLevel, description: string, flags?: Partial<Flags>) =>
  entry('member', 'project', level, description, flags)
const NEW_FEATURE = { gatesExisting: false } as const

const REGISTRY = {
  // §5.1 Administration
  'users:read': admin('See the user directory: accounts, type, status, permission sets, last sign-in and project counts.'),
  'users:create': admin('Create or invite members.'),
  'users:edit': admin("Edit a member's name and email."),
  'users:disable': admin('Disable or enable a member: blocks sign-in and revokes their sessions and MCP tokens.'),
  'users:delete': admin('Delete a member, transferring what they own.'),
  'users:reset_credentials': admin('Send a member a reset link or set a temporary password. As strong as taking the account over.', { takeoverEquivalent: true }),
  'users:revoke_sessions': admin('Sign a member out everywhere and revoke their MCP tokens.'),
  'users:assign_permissions': admin('Assign permission sets and overrides to members (only permissions you hold), and review legacy access.'),
  'users:impersonate': admin('Act as a member. As strong as taking the account over.', { takeoverEquivalent: true }),
  'admins:manage': admin('Create, promote, demote, disable and delete administrators, and assign admin profiles.', { rootOnly: true }),
  'roles:manage': admin('Create and edit member permission sets.'),
  'admin_profiles:manage': admin('Create and edit admin profiles.', { rootOnly: true }),
  'audit:read': admin('Read the instance audit log.', NEW_FEATURE),
  'audit:export': admin('Export the instance audit log.', NEW_FEATURE),
  'projects:oversee': admin('Read any project without acting as its owner, at the Read level; audited and visible to the owner.', NEW_FEATURE),
  'projects:administer': admin('Transfer any project, force-remove its shares or delete it (break-glass).', { rootOnly: true, ...NEW_FEATURE }),
  'instance:settings': admin('Change the security policy, the sharing policy and the defaults for new users.', { rootOnly: true }),
  'instance:quotas': admin('Set quotas per permission set or per user.', NEW_FEATURE),
  'root:transfer': admin('Transfer Root to another administrator.', { rootOnly: true }),

  // §5.2 Platform operations: shared by every tenant on the instance
  'platform:plugins': platform('Install, update, enable, disable, roll back and uninstall plugins; read their logs; grant plugin permissions.'),
  'platform:traffic_capture': platform('Configure the instance-wide traffic capture: the capture proxy, egress policy, retention and SCA ignore list.'),
  'platform:tunnels': platform('Configure and enable the ngrok or chisel tunnel every user shares.'),
  'platform:nuclei_templates': platform("Manage every custom Nuclei template: the instance's and other people's."),
  'platform:agent_mcp': platform("Own stdio MCP servers, whose commands run as root inside the shared agent beside every user's data and the platform secrets; reload the agent's MCP servers and manage the system MCP servers."),
  'platform:emergency_stop': platform("Stop every user's running agent runs at once."),
  'platform:shell_sessions': platform('See, use and kill every Metasploit and shell session on the instance.'),
  'platform:kali_terminal': platform("Open the raw Kali terminal: a shared sandbox where every project's files are visible."),
  'platform:operations': platform("See every user's running and queued scans, agent runs and triage runs, and the system load.", NEW_FEATURE),

  // §5.3 Account self-service
  'self:llm_providers': self('Add your own LLM providers and keys.'),
  'self:api_keys': self('Store your own third-party API keys and their rotation.'),
  'self:mcp_servers': self('Register outbound MCP servers for your own agent runs.'),
  'self:mcp_tokens': self('Mint MCP tokens for yourself; their scopes are limited by your permissions.'),
  'self:attack_skills': self('Upload, generate and import your own agent attack skills.'),
  'self:chat_skills': self('Keep your own chat skills.'),
  'self:tradecraft': self('Keep your own tradecraft resources.'),
  'self:presets': self('Keep your own recon presets and mute-rule presets.'),

  // §5.4 Projects: lifecycle and governance
  'project:create': self('Create projects.', { mcpScopes: ['project:create'] }),
  'project:import': self('Import a project archive.'),
  'project:share': entry('member', 'instance', 'M', 'Share your projects and manage their members.', NEW_FEATURE),
  'project:settings': project('W', 'Edit the recon pipeline and agent settings of a project.', { mcpScopes: ['recon:settings'] }),
  'project:rescope': project('M', "Change a project's targets and scope.", { mcpScopes: ['project:rescope'] }),
  'engagement:authorize': project('M', 'Record engagement authorizations.', { mcpScopes: ['engagement:authorize'] }),
  'roe:read': project('R', 'Read the rules of engagement document.'),
  'roe:manage': project('M', 'Upload, replace, remove and parse the rules of engagement document.'),
  'auth_profile:manage': project('M', "Set the project's authenticated-session credentials and record sessions."),
  'project:export': project('M', 'Export the whole project with all its data.'),
  'project:delete': project('O', 'Delete the project and everything in it.'),
  'project:transfer': project('O', 'Give ownership of the project to one of its members.', NEW_FEATURE),

  // §5.5 Recon and scanning
  'recon:read': project('R', 'Read recon status, logs, outputs, deltas and graph inputs, and download results.', { mcpScopes: ['recon:read'] }),
  'recon:scan': project('W+S', 'Start, pause, resume and stop a full recon.', { mcpScopes: ['recon:scan'] }),
  'recon:partial': project('W+S', 'Run a single recon phase (partial recon).', { mcpScopes: ['recon:scan'] }),
  'recon:overwrite': project('W+S', 'Run recon in overwrite mode, discarding the current graph.', { mcpScopes: ['recon:overwrite'] }),
  'recon:schedule': project('W+S', 'Queue scans, schedule them, and cancel or reconfirm queued jobs.', { mcpScopes: ['recon:queue'] }),
  'scan:gvm': project('W+S', 'Run GVM / OpenVAS scans.'),
  'scan:secrets': project('W+S', 'Run the GitHub secret hunt and TruffleHog, and manage their sources and profiles.'),
  'scan:supply_chain': project('W+S', 'Run supply-chain scans, uploads and organisation batches.'),
  'scan:ai_attack': project('W+S', 'Run AI attack-surface scans (spends LLM credits).'),
  'scan:uploads': project('W', 'Upload wordlists and JS recon custom files.'),
  'scan:custom_templates': project('W', 'Upload your own custom Nuclei templates and select your own and instance templates for the project.'),
  'scan:versions': project('W', 'Save, activate, pin and rename scan versions.'),
  'scan:versions_delete': project('M', 'Delete scan versions and clear the scan history.'),
  'preset:apply': project('W', 'Apply a recon preset to the project.', { mcpScopes: ['preset:apply'] }),
  'preset:write': self('Author recon presets.', { mcpScopes: ['preset:write'] }),

  // §5.6 AI agent
  'agent:chat': project('W+A', 'Talk to the agent in the informational and recon phases, in your own conversations.'),
  'agent:approve_phase': project('W+X', 'Approve the move into exploitation and post-exploitation.'),
  'agent:approve_dangerous': project('W+X', 'Answer the confirmations of dangerous agent tools.'),
  'agent:fireteam': project('W+A', 'Use Fireteam multi-agent waves.'),
  'agent:loop': project('W+A', 'Use Agent in the Loop: pick the loop model and drive it over MCP.', { mcpScopes: ['agent:loop'] }),
  'agent:sessions': project('W+X', "Use this project's shell sessions."),
  'agent:kali_exec': project('W+X', 'Run commands in the Kali sandbox over MCP. The sandbox is shared with every other project on this server.', { sandboxShared: true, mcpScopes: ['kali:exec'] }),
  'agent:assistants': project('W+A', 'Use the text-to-Cypher and command assistants (spends LLM credits).'),
  'agent:conversations_share': project('W+A', 'Share your conversations with the members of the project.', NEW_FEATURE),

  // §5.7 Workspace
  'workspace:read': project('R*', "Browse, preview, download and archive the agent's workspace."),
  'workspace:write': project('W', 'Upload, create folders, rename, delete and reset in the workspace; cancel background jobs.'),
  'workspace:import': project('W', 'Import into the workspace from a URL or GitHub.'),

  // §5.8 Graph, Insights and analytics
  'graph:read': project('R', 'See the graph, the Insights dashboards and attack chains.', { mcpScopes: ['recon:read'] }),
  'graph:cypher': project('R', 'Run raw Cypher queries and custom-Cypher graph views.', { mcpScopes: ['graph:cypher'] }),
  'graph:views': project('W', 'Create, edit and delete saved graph views.'),
  'graph:edit': project('M', 'Delete graph nodes, purge orphan chains and wipe the graph.'),

  // §5.9 Triage, mute rules, remediation
  'triage:read': project('R', 'Read the Priority Board, findings, evidence and the muted list.', { mcpScopes: ['triage:read'] }),
  'triage:verdict': project('W', "Record a person's verdict on a finding.", { mcpScopes: ['triage:write'] }),
  'triage:mute': project('W', 'Mute and unmute findings.', { mcpScopes: ['triage:mute'] }),
  'triage:review': project('W', "Submit an agent's review of a finding's score.", { mcpScopes: ['triage:review'] }),
  'triage:run': project('W+A', 'Start or stop an AI triage run (spends LLM credits).', { mcpScopes: ['triage:run'] }),
  'node_filters:manage': project('W', 'Edit, preview, apply, arm and disarm mute rules, and clear exemptions.'),
  'remediation:read': project('R', 'Read remediations.'),
  'remediation:write': project('W', 'Edit, delete and batch remediations.'),
  'codefix:run': project('W+A', 'Generate fixes and pull requests with CypherFix CodeFix.'),

  // §5.10 Reports
  'reports:read': project('R', 'List and download reports.'),
  'reports:generate': project('W', 'Generate reports.'),
  'reports:delete': project('W', 'Delete reports.'),

  // §5.11 Traffic and authenticated sessions
  'traffic:read': project('R*', 'Browse captured traffic: bodies, headers, cookies and credentials.'),
  'traffic:export': project('R*', 'Export captured traffic.'),
  'traffic:delete': project('W', 'Delete captured traffic.'),
  'traffic:replay': project('W+X', 'Replay and fuzz requests through the capture proxy.', NEW_FEATURE),
  'auth_profile:read': project('R', 'See that an authenticated-session profile exists and its details, never its secrets.'),

  // §5.12 Plugins
  'plugins:use': self('See plugin screens and run plugin actions.'),
  'plugins:approve_overrides': entry('member', 'instance', 'M', 'Approve, reject and reset skill text a plugin proposes, for yourself or a project.'),
} as const satisfies Record<string, PermissionMeta>

export type PermissionId = keyof typeof REGISTRY

export const PERMISSIONS: Readonly<Record<PermissionId, PermissionMeta>> = Object.freeze(REGISTRY)

export const PERMISSION_IDS: readonly PermissionId[] = Object.freeze(Object.keys(REGISTRY) as PermissionId[])

const KNOWN: ReadonlySet<string> = new Set(PERMISSION_IDS)

export function isPermissionId(value: unknown): value is PermissionId {
  return typeof value === 'string' && KNOWN.has(value)
}

/** Throws on a string the registry does not hold (PE-02); route and set checks call it before use. */
export function assertKnownPermission(value: unknown): asserts value is PermissionId {
  if (!isPermissionId(value)) {
    const shown = typeof value === 'string' ? JSON.stringify(value.slice(0, 80)) : typeof value
    throw new Error(`Unknown permission: ${shown}`)
  }
}
