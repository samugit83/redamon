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
 * an editor's by accident.
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
import { field, type ShareClass } from '@/lib/reconSettings/registry'
import { sameValue } from '@/lib/reconSettings/roeParse'
import { wideningReason } from '@/lib/roe/roeWidening'
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
 * post-exploitation, the dangerous-tool confirmation, the post-exploitation phase, the tunnels
 * that give a shell its reach, Kali installs and Kali exec over MCP.
 */
export const EXPLOIT_GATES: ReadonlySet<string> = new Set([
  'agentRequireApprovalForExploitation',
  'agentRequireApprovalForPostExploitation',
  'agentRequireToolConfirmation',
  'agentActivatePostExplPhase',
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
  /** A list of exclusions: an entry removed widens. */
  | 'removal'
  /** An allowlist whose empty value allows everything: an entry added, or emptying it, widens. */
  | 'allowlist'
  | 'enable'
  | 'disable'
  /** A cap: raising it widens. */
  | 'raise'
  /** Recomputed by the server from another field, never trusted from a body: never widens alone. */
  | 'derived'

export const OWN_DIRECTIONS: Readonly<Record<string, OwnDirection>> = {
  targetDomain: 'any',
  ipMode: 'any',
  domainBatchMode: 'any',
  ipHostnameMode: 'any',
  ownershipTxtPrefix: 'any',
  subdomainList: 'addition',
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
  agentKaliInstallAllowedPackages: 'allowlist',
  agentKaliInstallForbiddenPackages: 'removal',
  mcpKaliExecEnabled: 'enable',
}

const NEED_LEVELS: Readonly<Record<SettingsNeed, readonly ProjectLevel[]>> = {
  write: ['W'],
  manage: ['M'],
  'manage+exploit': ['M', 'W+X'],
  owner: ['O'],
}

/** A list column, or a comma-separated one (the Kali package lists, the GitHub repos). */
function entries(v: unknown): string[] {
  const raw = Array.isArray(v) ? v : typeof v === 'string' ? v.split(',') : []
  return raw.map(x => (typeof x === 'string' ? x : JSON.stringify(x)).trim()).filter(Boolean)
}

function ownReason(direction: OwnDirection, before: unknown, after: unknown): string | null {
  switch (direction) {
    case 'any':
      return 'changes a target'
    case 'addition': {
      const added = entries(after).filter(v => !entries(before).includes(v))
      return added.length ? `adds ${added.join(', ')}` : null
    }
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
    case 'derived':
      return null
  }
}

/** Why `before -> after` loosens a gate or widens scope, or null. */
function widens(key: string, before: unknown, after: unknown, beforeRow: Record<string, unknown>, afterRow: Record<string, unknown>): string | null {
  if (Object.prototype.hasOwnProperty.call(OWN_DIRECTIONS, key)) return ownReason(OWN_DIRECTIONS[key], before, after)
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
  if (share === 'ordinary') return { key, share, needs: 'write', reason: null }
  if (share === 'secret') return { key, share, needs: 'owner', reason: "the owner's secret" }
  const reason = widens(key, before, after, beforeRow, afterRow)
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
