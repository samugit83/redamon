/**
 * Project settings classed by risk (feature document §6.2, D-23; SH-08, SH-28, OQ-23): which
 * changes to a project row a person's access allows. Every writer of the project row asks it
 * before the write (step 5.1b); the owner passes every change, so an owner's saves are unchanged.
 *
 * The class of a column is the registry's `share:` (recon_settings/registry.yaml):
 *   - ordinary (absent): Write;
 *   - gate, a safety gate: tightening it needs Write; loosening it needs Manage, and also
 *     Exploitation & shells for the switches that toggle relies on (EXPLOIT_GATES). Without that,
 *     an editor could let the agent exploit with nobody approving, and the toggle would mean
 *     nothing;
 *   - scope, what the engagement targets and permits: narrowing it needs Manage, widening it the
 *     owner (OQ-23 default);
 *   - secret, the owner's credentials and records: the owner.
 * A key the registry does not know needs the owner, so a column added without a class is never
 * an editor's by accident. Two kinds of ordinary column are the owner's too (OWNER_COLUMNS): who
 * owns and wrote the row, and `engagementKind`, who the target belongs to.
 *
 * "Looser" and "wider" are the RoE review's judgment (`wideningReason`): a tighten_only switch
 * against its `roe_safe_value`, the engagement limits by ENGAGEMENT_DIRECTIONS, `roeAllow*` and
 * rate ceilings by their generic rules. OWN_DIRECTIONS covers the fields it does not judge, and
 * the ones its generic `*Enabled` rule gets backwards (turning the target guardrail OFF widens).
 * A gate or scope field with neither is judged as widened on every change (a test keeps that set
 * empty).
 *
 * Pure: the caller hands the row before the write and the values it will write; the decision per
 * level is `meetsLevel`, so the toggles mean the same here as on every route.
 */
import { field, type RegistryField, type ShareClass } from '@/lib/reconSettings/registry'
import { sameValue } from '@/lib/reconSettings/roeParse'
import { validateValue } from '@/lib/reconSettings/validators'
import { formatProblem, wideningReason } from '@/lib/roe/roeWidening'
import { resolveScopeGroups } from '@/lib/scopeGroups'
import { meetsLevel, type ProjectAccess } from './projectAccess'
import type { ProjectLevel } from './permissions'

/** The least a change needs: Write, Manage, Manage with Exploitation & shells, the owner. */
export type SettingsNeed = 'write' | 'manage' | 'manage+exploit' | 'owner'

export interface SettingsFieldRisk {
  key: string
  /** The registry class, or `unknown` for a key the registry does not have. */
  share: ShareClass | 'unknown'
  needs: SettingsNeed
  /** Why a gate change loosens or a scope change widens; null when it does neither. */
  reason: string | null
}

export interface SettingsChange extends SettingsFieldRisk {
  /** The access reaches `needs`. */
  ok: boolean
}

export interface SettingsVerdict {
  /** Every change is allowed. */
  ok: boolean
  /** The keys whose value changes, in key order. */
  changes: SettingsChange[]
  refused: SettingsChange[]
}

/**
 * The gates the Exploitation & shells toggle relies on (§6.2): approval before exploitation and
 * post-exploitation, the dangerous-tool confirmation, the post-exploitation phase, the tool phase
 * map (a dangerous tool opened in an earlier phase runs before those approvals), the tunnels that
 * give a shell its reach, Kali installs and Kali exec over MCP.
 */
export const EXPLOIT_GATES: ReadonlySet<string> = new Set([
  'agentRequireApprovalForExploitation',
  'agentRequireApprovalForPostExploitation',
  'agentRequireToolConfirmation',
  'agentActivatePostExplPhase',
  'agentToolPhaseMap',
  'agentChiselTunnelEnabled',
  'agentNgrokTunnelEnabled',
  'agentKaliInstallEnabled',
  'agentKaliInstallAllowedPackages',
  'agentKaliInstallForbiddenPackages',
  'mcpKaliExecEnabled',
])

export type OwnDirection =
  /** Any change widens: a single target or a mode, where no direction is safer. */
  | 'any'
  /** A list of allowances: an entry added widens. */
  | 'addition'
  /**
   * The single-domain prefixes, judged by the hosts they scan (`resolveScopeGroups`): no prefix
   * enumerates every subdomain, so emptying the list widens it; '.' adds the domain itself.
   */
  | 'subdomains'
  /** A list of exclusions: an entry removed widens. */
  | 'removal'
  /** An allowlist whose empty value allows everything: an entry added, or emptying it, widens. */
  | 'allowlist'
  | 'enable'
  | 'disable'
  /** A cap: raising it widens. */
  | 'raise'
  /** Moving up the field's ordered `values` widens; a value outside them is refused before this. */
  | 'higher'
  /** A value the engagement requires once set: clearing or replacing it widens, a first one narrows. */
  | 'kept'
  /** The agent's tool phase map: a dangerous tool admitted in a phase earlier than any it had loosens. */
  | 'phases'
  /** Recomputed by the server from another field, never trusted from a body: never widens alone. */
  | 'derived'

export const OWN_DIRECTIONS: Readonly<Record<string, OwnDirection>> = {
  targetDomain: 'any',
  ipMode: 'any',
  domainBatchMode: 'any',
  ipHostnameMode: 'any',
  ownershipTxtPrefix: 'any',
  subdomainList: 'subdomains',
  targetIps: 'addition',
  domainBatchHosts: 'addition',
  domainBatchGroups: 'derived',
  ipHostnameInclude: 'addition',
  ipHostnameExclude: 'removal',
  ipHostnameMaxScanned: 'raise',
  ipHostnamePassiveMaxNames: 'raise',
  ipHostnamePassiveExpand: 'enable',
  ipHostnameScanAllConfirmed: 'enable',
  targetGuardrailEnabled: 'disable',
  verifyDomainOwnership: 'disable',
  githubTargetOrg: 'any',
  githubTargetRepos: 'allowlist',
  gvmScanTargets: 'any',
  supplyChainOrgName: 'any',
  supplyChainRepoRef: 'any',
  supplyChainRepoScope: 'any',
  supplyChainRepoUrl: 'any',
  // Derived (non-zero rate ceiling, exclusions or the window): off means no limit applies.
  roeEnabled: 'disable',
  roeSensitiveDataHandling: 'higher',
  engagementIdentityHeader: 'kept',
  cypherfixRequireApproval: 'disable',
  agentToolPhaseMap: 'phases',
  agentKaliInstallAllowedPackages: 'allowlist',
  agentKaliInstallForbiddenPackages: 'removal',
  mcpKaliExecEnabled: 'enable',
}

/** The levels each need asks, every one of them (`meetsLevel`). */
export const NEED_LEVELS: Readonly<Record<SettingsNeed, readonly ProjectLevel[]>> = {
  write: ['W'],
  manage: ['M'],
  'manage+exploit': ['M', 'W+X'],
  owner: ['O'],
}

const NEED_LABEL: Readonly<Record<SettingsNeed, string>> = {
  write: 'Read + Write',
  manage: 'Manage',
  'manage+exploit': 'Manage and Exploitation & shells',
  owner: "the project's owner",
}

const NEED_ORDER: readonly SettingsNeed[] = ['write', 'manage', 'manage+exploit', 'owner']

/**
 * Columns the registry calls ordinary that only the owner changes: who owns and wrote the row
 * (`deny_reason: identity`), and `engagementKind`, fixed at creation because converting a project
 * would claim an authority nobody granted or drop a ceiling a person put there (registry meaning).
 * Every writer strips or stamps these itself; the class is the backstop for one that does not.
 */
function ownerColumn(key: string, spec: RegistryField): boolean {
  return spec.deny_reason === 'identity' || key === 'engagementKind'
}

/** The single-domain target the subdomain prefixes hang under. */
const SCOPE_TARGET = 'targetDomain'

/**
 * The stored columns classifyChange reads beside the changed ones: the RoE window's switch, since
 * a window part widens only while the window is on, and both ends of the daily window, which are
 * judged together (`wideningReason`); and the target the subdomain prefixes are read under. A
 * writer that reads only the changed columns would judge a window edit as narrowing.
 */
export const RISK_CONTEXT_KEYS: readonly string[] = Object.freeze([
  'roeTimeWindowEnabled', 'roeTimeWindowStartTime', 'roeTimeWindowEndTime', SCOPE_TARGET,
])

/** The select of the stored values classifyChange needs to judge a change to `keys`. */
export function riskSelect(keys: Iterable<string>): Record<string, true> {
  const select: Record<string, true> = {}
  for (const key of [...keys, ...RISK_CONTEXT_KEYS]) select[key] = true
  return select
}

/** A list column, or a comma-separated one (the Kali package lists, the GitHub repos). */
function entries(v: unknown): string[] {
  const raw = Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : []
  return raw.map(x => (typeof x === 'string' ? x : JSON.stringify(x)).trim()).filter(Boolean)
}

/** Stands in for a target not set yet (or one the rule refuses): prefixes read alike under any domain. */
const PLACEHOLDER_TARGET = 'example.com'

interface SubdomainScope {
  everySubdomain: boolean
  domainItself: boolean
  prefixes: string[]
}

/** What a subdomain list scans in single-domain mode, by the rule every reader is handed. */
function subdomainScope(list: unknown, targetDomain: unknown): SubdomainScope | null {
  const subdomainList = Array.isArray(list) ? list.map(v => String(v ?? '')) : []
  const resolve = (target: string) => resolveScopeGroups({ targetDomain: target, subdomainList }).groups[0]
  const group = resolve(typeof targetDomain === 'string' ? targetDomain : '') ?? resolve(PLACEHOLDER_TARGET)
  if (!group) return null
  return {
    everySubdomain: group.mode === 'enumerate',
    domainItself: group.includeRoot,
    prefixes: group.exactHosts.map(host => host.slice(0, -(group.scanRoot.length + 1))),
  }
}

function subdomainWidening(before: unknown, after: unknown, targetDomain: unknown): string | null {
  const was = subdomainScope(before, targetDomain)
  const now = subdomainScope(after, targetDomain)
  if (!was || !now) return 'cannot be read as a scope'
  if (now.everySubdomain && !was.everySubdomain) return 'scans every subdomain: a list with no prefix enumerates them all'
  if (now.domainItself && !was.domainItself) return 'adds the domain itself'
  if (was.everySubdomain) return null
  const added = now.prefixes.filter(p => !was.prefixes.includes(p))
  return added.length ? `adds ${added.join(', ')}` : null
}

/**
 * The tools the agent asks a person to confirm before running (`DANGEROUS_TOOLS`,
 * agentic/project_settings.py; a test pins the two lists together).
 */
export const DANGEROUS_AGENT_TOOLS: readonly string[] = Object.freeze([
  'execute_nmap', 'execute_naabu', 'execute_nuclei', 'execute_curl', 'execute_httpx', 'msf_restart', 'kali_shell',
  'metasploit_console', 'execute_code', 'execute_hydra', 'execute_playwright', 'execute_wpscan', 'execute_arjun',
  'execute_ffuf', 'execute_amass', 'execute_gau', 'execute_katana', 'proxy_brain', 'execute_guarddog',
])

/** The agent's phases, earliest first; exploitation and post-exploitation each start behind an approval. */
const AGENT_PHASES: readonly string[] = ['informational', 'exploitation', 'post_exploitation']

/** The phases (as indexes) one map entry admits, as the agent's `phase in entry` reads it. */
function admittedPhases(entry: unknown): number[] {
  const admits = (phase: string): boolean =>
    Array.isArray(entry) ? entry.includes(phase)
      // Python's `in` on text is a substring test: 'post_exploitation' admits exploitation too.
      : typeof entry === 'string' ? entry.includes(phase)
        : entry !== null && typeof entry === 'object' ? Object.prototype.hasOwnProperty.call(entry, phase)
          : false
  return AGENT_PHASES.flatMap((phase, i) => (admits(phase) ? [i] : []))
}

function phaseMapLoosening(before: unknown, after: unknown): string | null {
  const asMap = (v: unknown): Record<string, unknown> =>
    v !== null && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : {}
  const was = asMap(before)
  const now = asMap(after)
  const opened: string[] = []
  for (const tool of DANGEROUS_AGENT_TOOLS) {
    // A tool the map does not name runs in no phase: any phase is earlier than none.
    const earliest = Math.min(...admittedPhases(was[tool]))
    const earlier = admittedPhases(now[tool]).filter(i => i < earliest)
    if (earlier.length) opened.push(`${tool} in ${AGENT_PHASES[earlier[0]]}`)
  }
  return opened.length ? `opens ${opened.join(', ')}, ahead of the approvals its old phases sat behind` : null
}

function ownReason(key: string, direction: OwnDirection, before: unknown, after: unknown, afterRow: Record<string, unknown>): string | null {
  switch (direction) {
    case 'any':
      return 'changes a target'
    case 'addition': {
      const added = entries(after).filter(v => !entries(before).includes(v))
      return added.length ? `adds ${added.join(', ')}` : null
    }
    case 'subdomains':
      return subdomainWidening(before, after, afterRow[SCOPE_TARGET])
    case 'removal': {
      const gone = entries(before).filter(v => !entries(after).includes(v))
      return gone.length ? `removes ${gone.join(', ')}` : null
    }
    case 'allowlist': {
      const was = entries(before)
      if (was.length === 0) return null
      const now = entries(after)
      if (now.length === 0) return 'empties an allowlist, which allows everything'
      const added = now.filter(v => !was.includes(v))
      return added.length ? `adds ${added.join(', ')}` : null
    }
    case 'enable':
      return after === true && before !== true ? 'turns it on' : null
    case 'disable':
      return after !== true && before !== false ? 'turns off a restriction' : null
    case 'raise': {
      const b = Number(before)
      return !Number.isFinite(b) || Number(after) > b ? 'raises a cap' : null
    }
    case 'higher': {
      const order = field(key)?.values ?? []
      return order.indexOf(String(after)) > order.indexOf(String(before)) ? `moves up to ${String(after)}` : null
    }
    case 'kept': {
      const was = typeof before === 'string' ? before.trim() : ''
      const now = typeof after === 'string' ? after.trim() : ''
      if (!was || now === was) return null
      return now ? 'replaces it' : 'clears it'
    }
    case 'phases':
      return phaseMapLoosening(before, after)
    case 'derived':
      return null
  }
}

/**
 * Why the readers would not read `after` as written: outside the field's values or bound, the wrong
 * type, or a time or date not in the format they parse. Such a value sits on no order, so the order
 * cannot call it narrower: an unknown phase cap reads as no cap, an unreadable end date as none.
 * The derived columns are the server's own output, never a caller's.
 */
function unreadable(key: string, spec: RegistryField, after: unknown): string | null {
  if (OWN_DIRECTIONS[key] === 'derived') return null
  const problem = validateValue(key, spec, after) ?? formatProblem(key, after)
  return problem && `${problem}: a value its readers do not read as written`
}

/** Why `before -> after` loosens a gate or widens scope, or null. */
function widens(key: string, before: unknown, after: unknown, beforeRow: Record<string, unknown>, afterRow: Record<string, unknown>): string | null {
  if (Object.prototype.hasOwnProperty.call(OWN_DIRECTIONS, key)) return ownReason(key, OWN_DIRECTIONS[key], before, after, afterRow)
  return wideningReason(key, before, after, beforeRow, afterRow)
}

/**
 * What changing one column needs, whoever asks. `beforeRow` and `afterRow` are the whole row
 * before and after the write, for the rules that read another field (the RoE window's parts).
 */
export function classifyField(
  key: string,
  before: unknown,
  after: unknown,
  beforeRow: Record<string, unknown> = {},
  afterRow: Record<string, unknown> = {},
): SettingsFieldRisk {
  const spec = field(key)
  if (!spec) return { key, share: 'unknown', needs: 'owner', reason: 'not a project setting' }
  const share: ShareClass = spec.share ?? 'ordinary'
  if (share === 'ordinary') {
    return ownerColumn(key, spec)
      ? { key, share, needs: 'owner', reason: 'set by the owner or the server' }
      : { key, share, needs: 'write', reason: null }
  }
  if (share === 'secret') return { key, share, needs: 'owner', reason: "the owner's secret" }
  const reason = unreadable(key, spec, after) ?? widens(key, before, after, beforeRow, afterRow)
  if (share === 'gate') {
    if (!reason) return { key, share, needs: 'write', reason: null }
    return { key, share, needs: EXPLOIT_GATES.has(key) ? 'manage+exploit' : 'manage', reason: `loosens a safety gate: ${reason}` }
  }
  return reason
    ? { key, share, needs: 'owner', reason: `widens the scope: ${reason}` }
    : { key, share, needs: 'manage', reason: null }
}

function reaches(access: ProjectAccess | null | undefined, needs: SettingsNeed): boolean {
  return !!access && NEED_LEVELS[needs].every(level => meetsLevel(access, level))
}

/**
 * Each value in `after` that differs from `before` (the row as stored), and whether `access`
 * may write it. `after` may be partial (a single-field auto-save); the rules that read another
 * field see the row as it will be.
 */
export function classifyChange(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  access: ProjectAccess | null | undefined,
): SettingsVerdict {
  const afterRow = { ...before, ...after }
  const changes: SettingsChange[] = []
  for (const key of Object.keys(after).sort()) {
    if (sameValue(before[key], after[key])) continue
    const risk = classifyField(key, before[key], after[key], before, afterRow)
    changes.push({ ...risk, ok: reaches(access, risk.needs) })
  }
  const refused = changes.filter(c => !c.ok)
  return { ok: refused.length === 0, changes, refused }
}

/** The 403 body of a refused settings change: the §9.8 body plus each refused key and its levels. */
export interface SettingsRefusal {
  error: string
  code: 'forbidden'
  /** The permission of the route or tool that was asked. */
  permission: string
  /** The strictest level the refused changes need: its first level (`O`, `M` or `W`). */
  level: ProjectLevel
  needs: SettingsNeed
  refused: Array<{ key: string; needs: SettingsNeed; levels: readonly ProjectLevel[]; reason: string | null }>
}

/** A reason lists the entries a change adds, which can be a whole target list. */
const brief = (reason: string): string => (reason.length > 160 ? `${reason.slice(0, 159)}…` : reason)

/**
 * The refusal of a verdict, naming each refused key and the level it needs, or null when every
 * change is allowed. Every writer answers it as is: a 403 body, or an MCP tool error's text.
 */
export function settingsRefusal(verdict: SettingsVerdict, permission: string): SettingsRefusal | null {
  if (verdict.ok || verdict.refused.length === 0) return null
  const needs = verdict.refused.reduce<SettingsNeed>(
    (top, c) => (NEED_ORDER.indexOf(c.needs) > NEED_ORDER.indexOf(top) ? c.needs : top), 'write')
  const parts = verdict.refused.map(c => `${c.key} needs ${NEED_LABEL[c.needs]}${c.reason ? ` (${brief(c.reason)})` : ''}`)
  return {
    error: `Your access to this project does not reach ${verdict.refused.length === 1 ? 'this change' : 'these changes'} ` +
      `(${permission}): ${parts.join('; ')}. Nothing was saved.`,
    code: 'forbidden',
    permission,
    level: NEED_LEVELS[needs][0],
    needs,
    refused: verdict.refused.map(c => ({ key: c.key, needs: c.needs, levels: NEED_LEVELS[c.needs], reason: c.reason && brief(c.reason) })),
  }
}
