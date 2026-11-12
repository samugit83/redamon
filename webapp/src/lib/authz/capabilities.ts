/**
 * What a person may do at all: the capability layer of feature document §4.2, before any project
 * access (step 3.4; PE-01, PE-13, PE-16, PE-17, PE-27). `can()` (step 3.5) asks it first.
 *
 * With RBAC_PERMISSIONS_ENABLED on:
 *   - the confirmed Root holds every permission, an unconfirmed one all but the Root-only ones
 *     (2.6's `rootStanding`); Root never depends on stored data, so no set or override counts;
 *   - an admin holds the admin profile (none recorded = *Full admin*) plus a member side, which
 *     is their own sets (never assigned = *Default member*, §14.3) and overrides;
 *   - a member holds their sets (never assigned = the instance default set, else *Default
 *     member*; assigned but every set gone = *No access*), their legacy grants (§14.7, until
 *     step 3.15 converts them) and unexpired override grants; an unexpired deny wins over all;
 *   - the instance caps remove what the instance has switched off;
 *   - an account that is not active holds nothing.
 * Dangling data fails closed: a set or profile that is gone, or of the wrong kind, gives nothing.
 *
 * With the switch off every account resolves to its account type's default, which is what it can
 * do today (PE-27, DV-30): members *Default member* and their legacy grants, admins *Full admin* +
 * *Default member*, Root as Phase 2 has it; with the identity switch off too there is no Root and
 * every admin keeps `admins:manage`, Phase 1's rule (admins manage admins, with step-up).
 *
 * Reads: the account (the principal, cached, carrying its assignments and overrides), the Root
 * for an admin (root.ts, cached), and for a custom set or the instance default set one read each,
 * cached here for the same bound (RBAC_AUTHZ_CACHE_MS). Built-in sets are code: no read. A failed
 * read throws: it never resolves to a grant.
 */
import prisma from '@/lib/prisma'
import { agentInTheLoopEnabled } from '@/lib/agentInTheLoop'
import { mcpServerEnabled } from '@/lib/mcpServerEnabled'
import { rbacFlags } from './flags'
import { now } from './clock'
import { principalCacheTtl, type Principal } from './principal'
import { accountTypeOf, loadInstanceRoot, INSTANCE_SETTINGS_ROW, type AccountType } from './root'
import { PERMISSIONS, PERMISSION_IDS, assertKnownPermission, isPermissionId, type PermissionId } from './permissions'
import { builtinSet, DEFAULT_MEMBER_SET_ID, FULL_ADMIN_PROFILE_ID, NO_ACCESS_SET_ID } from './builtinSets'
import type { LegacyGrant } from './updateReview'

/** What the resolution reads of an account: a principal loadPrincipal returned. */
export type CapabilityPrincipal = Pick<Principal, 'id' | 'role' | 'status' | 'adminProfileId' | 'legacyGrants'>
  & Partial<Pick<Principal, 'permissionSets' | 'permissionOverrides'>>

export interface SetInForce {
  id: string
  name: string
  kind: 'member' | 'admin'
  /**
   * `assigned`: the account's own row (or admin profile); `instance_default`: never assigned, the
   * instance's default set for members; `default`: the account type's default; `dangling`: *No
   * access*, because every set assigned is gone.
   */
  via: 'assigned' | 'instance_default' | 'default' | 'dangling'
}

export type InstanceCapSetting = 'MCP_SERVER_ENABLED' | 'AGENT_IN_THE_LOOP_ENABLED'

/** Why a permission is held or not (PE-16, UI-12): every grant and deny that applies to it. */
export type CapabilityReason =
  | { effect: 'grant'; kind: 'root' }
  | { effect: 'grant' | 'deny'; kind: 'root_unconfirmed' }
  | { effect: 'grant'; kind: 'set'; set: SetInForce }
  | { effect: 'grant'; kind: 'legacy_grant'; grant: string }
  | { effect: 'grant'; kind: 'phase1_admin' }
  | { effect: 'grant' | 'deny'; kind: 'override'; expiresAt: Date | null; reason: string | null }
  | { effect: 'deny'; kind: 'instance_cap'; setting: InstanceCapSetting }
  | { effect: 'deny'; kind: 'inactive'; status: string }
  /** No set or grant holds it: the sets in force, for "your set X has no Y". */
  | { effect: 'deny'; kind: 'not_granted'; sets: readonly SetInForce[] }

export interface PermissionExplanation {
  permission: PermissionId
  held: boolean
  reasons: readonly CapabilityReason[]
}

export interface Capabilities {
  userId: string
  accountType: AccountType
  /** True when the person's sets and overrides decide (permissions switch on). */
  enforced: boolean
  /** The admin profile first, then the member sets. */
  sets: readonly SetInForce[]
  /** Ids an assignment, the admin profile or the instance default names that are no set of that kind. */
  missingSets: readonly string[]
  /** In registry order. */
  held: readonly PermissionId[]
  /** Throws on a string the registry does not hold (PE-02). */
  has(permission: PermissionId): boolean
  explain(permission: PermissionId): PermissionExplanation
  /** Every permission, in registry order. */
  explainAll(): readonly PermissionExplanation[]
}

const LEGACY_PERMISSION: ReadonlyMap<string, PermissionId> = new Map<LegacyGrant, PermissionId>([
  ['kali_terminal', 'platform:kali_terminal'],
  ['shell_sessions', 'platform:shell_sessions'],
  ['tunnels', 'platform:tunnels'],
])

const ROOT: CapabilityReason = Object.freeze({ effect: 'grant', kind: 'root' })
const ROOT_UNCONFIRMED_GRANT: CapabilityReason = Object.freeze({ effect: 'grant', kind: 'root_unconfirmed' })
const ROOT_UNCONFIRMED_DENY: CapabilityReason = Object.freeze({ effect: 'deny', kind: 'root_unconfirmed' })
const PHASE1_ADMIN: CapabilityReason = Object.freeze({ effect: 'grant', kind: 'phase1_admin' })

interface StoredSet {
  kind: string
  name: string
  permissions: readonly string[]
}

const setCache = new Map<string, { set: StoredSet | null; expiresAt: number }>()
let defaultSetCache: { id: string | null; expiresAt: number } | null = null
// Raised by every invalidation: a read that started before one is returned but not kept.
let generation = 0
// Set ids come from rows, so they are few; the cap only bounds a pathological instance.
const MAX_CACHED_SETS = 10_000

const warned = new Set<string>()
function warnMissingSet(id: string, kind: string): void {
  const line = `[rbac] permission set ${JSON.stringify(id.slice(0, 80))} is gone or not a ${kind} set: its holders resolve without it`
  if (warned.has(line)) return
  warned.add(line)
  console.warn(line)
}

/** A writer of a permission set or of the instance default set (step 3.11): the next read goes to the database. */
export function invalidatePermissionSets(): void {
  generation += 1
  setCache.clear()
  defaultSetCache = null
}

/** Tests only. */
export function clearCapabilityCachesForTests(): void {
  invalidatePermissionSets()
  warned.clear()
}

async function storedSets(ids: readonly string[]): Promise<ReadonlyMap<string, StoredSet | null>> {
  const ttl = principalCacheTtl()
  const at = now().getTime()
  const out = new Map<string, StoredSet | null>()
  const wanted: string[] = []
  // A `builtin:` id the code does not hold is no row either: a custom set's id is a cuid.
  for (const id of new Set(ids.filter((i) => !i.startsWith('builtin:')))) {
    const hit = ttl > 0 ? setCache.get(id) : undefined
    if (hit && hit.expiresAt > at) out.set(id, hit.set)
    else wanted.push(id)
  }
  if (wanted.length === 0) return out
  const startedAt = generation
  const rows = await prisma.permissionSet.findMany({
    where: { id: { in: wanted } },
    select: { id: true, kind: true, name: true, permissions: true },
  })
  const found = new Map(rows.map((r) => [r.id, Object.freeze({ kind: r.kind, name: r.name, permissions: Object.freeze([...r.permissions]) })]))
  const keep = ttl > 0 && startedAt === generation
  if (keep && setCache.size + wanted.length > MAX_CACHED_SETS) setCache.clear()
  for (const id of wanted) {
    const set = found.get(id) ?? null
    out.set(id, set)
    if (keep) setCache.set(id, { set, expiresAt: now().getTime() + ttl })
  }
  return out
}

async function instanceDefaultSetId(): Promise<string | null> {
  const ttl = principalCacheTtl()
  if (ttl > 0 && defaultSetCache && defaultSetCache.expiresAt > now().getTime()) return defaultSetCache.id
  const startedAt = generation
  const row = await prisma.instanceSettings.findUnique({
    where: { id: INSTANCE_SETTINGS_ROW },
    select: { defaultMemberSetId: true },
  })
  const id = row?.defaultMemberSetId ?? null
  if (ttl > 0 && startedAt === generation) defaultSetCache = { id, expiresAt: now().getTime() + ttl }
  return id
}

/**
 * The permissions a set of this kind gives, or null when `id` names no set of this kind. A custom
 * set keeps only the known permissions of its kind; of the Root-only ones only `admins:manage`
 * may sit in a custom admin profile (OQ-02), so any other is dropped.
 */
function setContents(
  id: string,
  kind: SetInForce['kind'],
  stored: ReadonlyMap<string, StoredSet | null>,
): { name: string; permissions: readonly PermissionId[] } | null {
  const builtin = builtinSet(id)
  if (builtin) return builtin.kind === kind ? builtin : null
  const set = stored.get(id)
  if (!set || set.kind !== kind) return null
  const permissions = set.permissions.filter((p): p is PermissionId =>
    isPermissionId(p) && PERMISSIONS[p].kind === kind && (!PERMISSIONS[p].rootOnly || p === 'admins:manage'))
  return { name: set.name, permissions }
}

/**
 * Whether an override may grant this permission to this account: any member permission; a
 * platform tool to a member only (the §14.7 legacy grants become such overrides, D-20); never an
 * administration permission (an admin profile's, D-19), and nothing on an admin's admin side,
 * which its one profile states whole (D-20). A deny is honoured whatever it names.
 */
function overrideMayGrant(permission: PermissionId, accountType: AccountType): boolean {
  const meta = PERMISSIONS[permission]
  return meta.kind === 'member' || (accountType === 'member' && meta.crossTenant)
}

class Ledger {
  readonly reasons = new Map<PermissionId, CapabilityReason[]>()
  readonly sets: SetInForce[] = []
  readonly missing: string[] = []

  add(permission: PermissionId, reason: CapabilityReason): void {
    const list = this.reasons.get(permission)
    if (list) list.push(reason)
    else this.reasons.set(permission, [reason])
  }

  grantSet(set: SetInForce, permissions: readonly PermissionId[]): void {
    const frozen = Object.freeze({ ...set })
    this.sets.push(frozen)
    const reason: CapabilityReason = Object.freeze({ effect: 'grant', kind: 'set', set: frozen })
    for (const p of permissions) this.add(p, reason)
  }

  defaultSet(id: string): void {
    const set = builtinSet(id)!
    this.grantSet({ id: set.id, name: set.name, kind: set.kind, via: 'default' }, set.permissions)
  }

  missingSet(id: string, kind: SetInForce['kind']): void {
    this.missing.push(id)
    warnMissingSet(id, kind)
  }

  /** The member sets assigned (an empty list = never assigned, handled by the caller). */
  assignedMemberSets(ids: readonly string[], stored: ReadonlyMap<string, StoredSet | null>): void {
    let found = 0
    for (const id of ids) {
      const set = setContents(id, 'member', stored)
      if (!set) {
        this.missingSet(id, 'member')
        continue
      }
      found += 1
      this.grantSet({ id, name: set.name, kind: 'member', via: 'assigned' }, set.permissions)
    }
    if (found === 0) this.noAccess()
  }

  noAccess(): void {
    const set = builtinSet(NO_ACCESS_SET_ID)!
    this.grantSet({ id: set.id, name: set.name, kind: 'member', via: 'dangling' }, set.permissions)
  }
}

function requireAssignments(principal: CapabilityPrincipal): asserts principal is CapabilityPrincipal & Required<Pick<Principal, 'permissionSets' | 'permissionOverrides'>> {
  if (principal.permissionSets === undefined || principal.permissionOverrides === undefined) {
    // Reading "no rows" here as "never assigned" would widen a restricted account to the default.
    throw new Error('capabilities: the account was read without its permission sets and overrides')
  }
}

/** What `principal` may do at all, and why (`explain`). */
export async function resolveCapabilities(principal: CapabilityPrincipal): Promise<Capabilities> {
  const flags = rbacFlags()
  const enforced = flags.permissions
  if (enforced) requireAssignments(principal)
  // Root is an admin (root.ts), so a member costs no instance read.
  const root = principal.role === 'admin' ? await loadInstanceRoot() : null
  const accountType = accountTypeOf(principal, root)
  const ledger = new Ledger()

  if (enforced && principal.status !== 'active') {
    const inactive: CapabilityReason = Object.freeze({ effect: 'deny', kind: 'inactive', status: principal.status })
    for (const p of PERMISSION_IDS) ledger.add(p, inactive)
    return result(principal.id, accountType, enforced, ledger)
  }

  if (accountType === 'root') {
    for (const p of PERMISSION_IDS) {
      if (root!.confirmed) ledger.add(p, ROOT)
      else ledger.add(p, PERMISSIONS[p].rootOnly ? ROOT_UNCONFIRMED_DENY : ROOT_UNCONFIRMED_GRANT)
    }
  } else if (!enforced) {
    if (accountType === 'admin') {
      ledger.defaultSet(FULL_ADMIN_PROFILE_ID)
      ledger.defaultSet(DEFAULT_MEMBER_SET_ID)
      if (!flags.identity) ledger.add('admins:manage', PHASE1_ADMIN)
    } else {
      ledger.defaultSet(DEFAULT_MEMBER_SET_ID)
      addLegacyGrants(principal, ledger)
    }
  } else {
    requireAssignments(principal)
    const profileId = accountType === 'admin' ? principal.adminProfileId : null
    const stored = await storedSets(profileId ? [profileId, ...principal.permissionSets] : principal.permissionSets)
    if (accountType === 'admin') {
      if (profileId === null) {
        ledger.defaultSet(FULL_ADMIN_PROFILE_ID)
      } else {
        const profile = setContents(profileId, 'admin', stored)
        if (profile) ledger.grantSet({ id: profileId, name: profile.name, kind: 'admin', via: 'assigned' }, profile.permissions)
        else ledger.missingSet(profileId, 'admin')
      }
      if (principal.permissionSets.length > 0) ledger.assignedMemberSets(principal.permissionSets, stored)
      else ledger.defaultSet(DEFAULT_MEMBER_SET_ID)
    } else {
      if (principal.permissionSets.length > 0) ledger.assignedMemberSets(principal.permissionSets, stored)
      else await instanceDefault(ledger)
      addLegacyGrants(principal, ledger)
    }
    addOverrides(principal.permissionOverrides, accountType, ledger)
  }

  if (enforced) {
    if (!mcpServerEnabled()) ledger.add('self:mcp_tokens', Object.freeze({ effect: 'deny', kind: 'instance_cap', setting: 'MCP_SERVER_ENABLED' }))
    if (!agentInTheLoopEnabled()) ledger.add('agent:loop', Object.freeze({ effect: 'deny', kind: 'instance_cap', setting: 'AGENT_IN_THE_LOOP_ENABLED' }))
  }
  return result(principal.id, accountType, enforced, ledger)
}

async function instanceDefault(ledger: Ledger): Promise<void> {
  const id = await instanceDefaultSetId()
  if (id === null) {
    ledger.defaultSet(DEFAULT_MEMBER_SET_ID)
    return
  }
  const set = setContents(id, 'member', await storedSets([id]))
  if (set) {
    ledger.grantSet({ id, name: set.name, kind: 'member', via: 'instance_default' }, set.permissions)
  } else {
    ledger.missingSet(id, 'member')
    ledger.noAccess()
  }
}

function addLegacyGrants(principal: CapabilityPrincipal, ledger: Ledger): void {
  for (const grant of principal.legacyGrants) {
    const permission = LEGACY_PERMISSION.get(grant)
    if (permission) ledger.add(permission, Object.freeze({ effect: 'grant', kind: 'legacy_grant', grant }))
  }
}

function addOverrides(overrides: Required<Principal>['permissionOverrides'], accountType: AccountType, ledger: Ledger): void {
  const at = now().getTime()
  for (const o of overrides) {
    if (!isPermissionId(o.permission)) continue
    if (o.expiresAt !== null && o.expiresAt.getTime() <= at) continue
    const reason = { kind: 'override', expiresAt: o.expiresAt, reason: o.reason } as const
    if (o.effect === 'deny') ledger.add(o.permission, Object.freeze({ effect: 'deny', ...reason }))
    else if (o.effect === 'grant' && overrideMayGrant(o.permission, accountType)) ledger.add(o.permission, Object.freeze({ effect: 'grant', ...reason }))
  }
}

function result(userId: string, accountType: AccountType, enforced: boolean, ledger: Ledger): Capabilities {
  const sets = Object.freeze([...ledger.sets])
  const decided = (p: PermissionId): boolean => {
    const reasons = ledger.reasons.get(p) ?? []
    return reasons.some((r) => r.effect === 'grant') && !reasons.some((r) => r.effect === 'deny')
  }
  const held = Object.freeze(PERMISSION_IDS.filter(decided))
  const holds = new Set<PermissionId>(held)
  const notGranted: CapabilityReason = Object.freeze({ effect: 'deny', kind: 'not_granted', sets })
  let explanations: Map<PermissionId, PermissionExplanation> | null = null
  const explained = (): Map<PermissionId, PermissionExplanation> => {
    explanations ??= new Map(PERMISSION_IDS.map((p) => {
      const reasons = ledger.reasons.get(p) ?? []
      const withWhy = holds.has(p) || reasons.some((r) => r.effect === 'deny') ? reasons : [...reasons, notGranted]
      return [p, Object.freeze({ permission: p, held: holds.has(p), reasons: Object.freeze([...withWhy]) })]
    }))
    return explanations
  }
  return Object.freeze({
    userId,
    accountType,
    enforced,
    sets,
    missingSets: Object.freeze([...ledger.missing]),
    held,
    has(permission: PermissionId): boolean {
      assertKnownPermission(permission)
      return holds.has(permission)
    },
    explain(permission: PermissionId): PermissionExplanation {
      assertKnownPermission(permission)
      return explained().get(permission)!
    },
    explainAll(): readonly PermissionExplanation[] {
      return Object.freeze([...explained().values()])
    },
  })
}
