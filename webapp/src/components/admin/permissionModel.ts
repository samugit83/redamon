/**
 * What the permission screens read and send (step 3.13): the shapes of `GET/PUT
 * /api/users/[id]/permissions`, `GET /api/admin/permission-sets` and `GET /api/admin/admin-profiles`
 * (step 3.11), and the client mirror of the rules the server applies to a change, so a screen
 * disables what the server would refuse and asks for the password before it does. The server stays
 * the authority: a stale or wrong mirror costs a refusal, never a permission.
 */
import { PERMISSIONS, isPermissionId, type PermissionId } from '@/lib/authz/permissions'
import { adminSide, isStrictSubset, stepUpPermissionsIn } from '@/lib/authz/hierarchy'
import { builtinSet, NO_ACCESS_SET_ID } from '@/lib/authz/builtinSets'

export type SetVia = 'assigned' | 'instance_default' | 'default' | 'dangling'

export interface SetInForceView {
  id: string
  name: string
  kind: 'member' | 'admin'
  via: SetVia
}

export type ReasonView =
  | { effect: 'grant'; kind: 'root' }
  | { effect: 'grant' | 'deny'; kind: 'root_unconfirmed' }
  | { effect: 'grant'; kind: 'set'; set: SetInForceView }
  | { effect: 'grant'; kind: 'legacy_grant'; grant: string }
  | { effect: 'grant'; kind: 'phase1_admin' }
  | { effect: 'grant' | 'deny'; kind: 'override'; expiresAt: string | null; reason: string | null }
  | { effect: 'deny'; kind: 'instance_cap'; setting: string }
  | { effect: 'deny'; kind: 'inactive'; status: string }
  | { effect: 'deny'; kind: 'not_granted'; sets: SetInForceView[] }

export interface ExplanationView {
  permission: PermissionId
  held: boolean
  reasons: ReasonView[]
}

export type OverrideEffect = 'grant' | 'deny'

export interface OverrideView {
  permission: PermissionId
  effect: OverrideEffect
  /** ISO; null = no expiry. */
  expiresAt: string | null
  reason: string | null
}

export type AccountType = 'root' | 'admin' | 'member'

/** GET /api/users/[id]/permissions. */
export interface AccountPermissionsView {
  userId: string
  accountType: AccountType
  enforced: boolean
  assignment: { sets: string[]; overrides: OverrideView[]; adminProfileId?: string | null }
  sets: SetInForceView[]
  missingSets: string[]
  held: PermissionId[]
  explain: ExplanationView[]
}

/** One row of GET /api/admin/permission-sets or /api/admin/admin-profiles. */
export interface SetOption {
  id: string
  kind: 'member' | 'admin'
  name: string
  description: string | null
  permissions: PermissionId[]
  builtin: boolean
  holders: number
  instanceDefault: boolean
}

export interface SetList {
  sets: SetOption[]
  /** Member sets only: null = *Default member*. */
  instanceDefaultSetId?: string | null
}

export const FULL_ADMIN_PROFILE = 'builtin:full-admin'
export const DEFAULT_MEMBER_SET = 'builtin:default-member'

export const permissionsUrl = (userId: string) => `/api/users/${encodeURIComponent(userId)}/permissions`

/**
 * The member sets offered when giving someone a set. *Default member* is left out: it is what "no
 * set ticked" already means (the baseline every member had before permission sets) and it holds
 * exactly what *Red-team operator* holds, so offering both only read as two different roles. It
 * stays listed where `keep` names it (an account that already holds it), and the server still
 * accepts it.
 */
export function offeredMemberSets(sets: readonly SetOption[], keep: readonly string[] = []): SetOption[] {
  return sets.filter((s) => s.kind === 'member' && (s.id !== DEFAULT_MEMBER_SET || keep.includes(s.id)))
}

/** The admin profile an assignment records (null: *Full admin*). */
export function profileOf(view: AccountPermissionsView): string | null {
  return view.assignment.adminProfileId ?? null
}

/**
 * What a person may give (permissionAdmin.ts `givable`): what they hold, and what only an instance
 * cap removes, which it removes from the target too.
 */
export function givableFrom(explain: readonly ExplanationView[]): ReadonlySet<PermissionId> {
  return new Set(explain
    .filter((e) => e.held || (e.reasons.some((r) => r.effect === 'grant')
      && e.reasons.every((r) => r.effect === 'grant' || r.kind === 'instance_cap')))
    .map((e) => e.permission))
}

/** What of `permissions` the person cannot give, in the order given. */
export function notGivable(permissions: readonly PermissionId[], givable: ReadonlySet<PermissionId>): PermissionId[] {
  return permissions.filter((p) => !givable.has(p))
}

/** May this person give an admin this profile (hierarchy.ts `canAssignProfile`)? */
export function profileAssignable(me: AccountPermissionsView, givable: ReadonlySet<PermissionId>, profile: readonly PermissionId[]): boolean {
  if (me.accountType === 'root' && givable.has('admins:manage')) return true
  if (!givable.has('admins:manage')) return false
  return isStrictSubset(profile, adminSide([...givable]))
}

const SET_VIA: Record<SetVia, string> = {
  assigned: 'assigned',
  instance_default: 'the instance default, no set assigned',
  default: 'the default, no set assigned',
  dangling: 'every set assigned is gone',
}

export function setInForceText(set: SetInForceView): string {
  const what = set.kind === 'admin' ? 'admin profile' : 'set'
  return `${what} ${set.name} (${SET_VIA[set.via]})`
}

function when(iso: string | null): string {
  return iso ? ` until ${new Date(iso).toLocaleString()}` : ''
}

const CAP_TEXT: Record<string, string> = {
  MCP_SERVER_ENABLED: 'the MCP server is switched off on this instance (MCP_SERVER_ENABLED)',
  AGENT_IN_THE_LOOP_ENABLED: 'Agent in the Loop is switched off on this instance (AGENT_IN_THE_LOOP_ENABLED)',
}

/** One "because" line (PE-16, UI-12): why a permission is held or not. */
export function reasonText(r: ReasonView): string {
  switch (r.kind) {
    case 'root':
      return 'Root holds every permission'
    case 'root_unconfirmed':
      return r.effect === 'grant'
        ? 'Root, not yet confirmed: every permission but Root\'s own'
        : 'Root\'s own permission: Root must be confirmed first'
    case 'set':
      return `granted by the ${setInForceText(r.set)}`
    case 'legacy_grant':
      return `granted by the legacy access ${r.grant}, kept from before permission sets`
    case 'phase1_admin':
      return 'admins manage admins while the identity switch is off'
    case 'override':
      return `${r.effect === 'grant' ? 'granted' : 'denied'} by an override${when(r.expiresAt)}${r.reason ? `: ${r.reason}` : ''}`
    case 'instance_cap':
      return CAP_TEXT[r.setting] ?? `switched off on this instance (${r.setting})`
    case 'inactive':
      return `the account is ${r.status}`
    case 'not_granted':
      return r.sets.length
        ? `no set in force holds it (${r.sets.map((s) => s.name).join(', ')})`
        : 'no set in force holds it'
  }
}

export interface Draft {
  sets: string[]
  overrides: OverrideView[]
  profile: string | null
}

const isLive = (o: OverrideView, at: number) => o.expiresAt === null || Date.parse(o.expiresAt) > at

/** The draft a screen starts from: the assignment, without overrides that already expired (the PUT refuses a past expiry). */
export function draftOf(view: AccountPermissionsView, at = Date.now()): Draft {
  return {
    sets: [...view.assignment.sets],
    overrides: view.assignment.overrides.filter((o) => isLive(o, at)).map((o) => ({ ...o })),
    profile: profileOf(view),
  }
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  const sa = [...a].sort()
  const sb = [...b].sort()
  return sa.length === sb.length && sa.every((x, i) => x === sb[i])
}
const overrideKey = (o: OverrideView) => `${o.permission}|${o.effect}|${o.expiresAt ? Date.parse(o.expiresAt) : ''}|${o.reason ?? ''}`

/** The PUT body for what changed (each key replaces that part), or null when nothing did. */
export function changeBody(view: AccountPermissionsView, draft: Draft): Record<string, unknown> | null {
  const start = draftOf(view)
  const body: Record<string, unknown> = {}
  if (!sameList(start.sets, draft.sets)) body.sets = [...draft.sets]
  // Sending the overrides replaces them all, so the expired ones the draft left out go too.
  if (!sameList(start.overrides.map(overrideKey), draft.overrides.map(overrideKey))) {
    body.overrides = draft.overrides.map((o) => ({ permission: o.permission, effect: o.effect, expiresAt: o.expiresAt, reason: o.reason }))
  }
  if (view.accountType === 'admin' && draft.profile !== start.profile) body.adminProfileId = draft.profile
  return Object.keys(body).length ? body : null
}

/**
 * What a change gives, as the server counts it (userPermissionAdmin.ts): the added sets' contents,
 * grants that are new, back after expiring or lengthened, denies lifted, and a new profile's contents.
 */
export function givingOf(
  view: AccountPermissionsView,
  draft: Draft,
  sets: readonly SetOption[],
  profiles: readonly SetOption[],
  at = Date.now(),
): PermissionId[] {
  const out = new Set<PermissionId>()
  const byId = new Map([...sets, ...profiles].map((s) => [s.id, s]))
  for (const id of draft.sets) {
    if (!view.assignment.sets.includes(id)) for (const p of byId.get(id)?.permissions ?? []) out.add(p)
  }
  const before = new Map(view.assignment.overrides.map((o) => [o.permission, o]))
  const after = new Map(draft.overrides.map((o) => [o.permission, o]))
  for (const o of draft.overrides) {
    if (o.effect !== 'grant') continue
    const p = before.get(o.permission)
    const held = p && p.effect === 'grant' && isLive(p, at)
    const longer = p && p.expiresAt !== null && (o.expiresAt === null || Date.parse(o.expiresAt) > Date.parse(p.expiresAt))
    if (!held || longer) out.add(o.permission)
  }
  for (const p of view.assignment.overrides) {
    if (p.effect !== 'deny' || !isLive(p, at)) continue
    const n = after.get(p.permission)
    const still = n && n.effect === 'deny' && (n.expiresAt === null || (p.expiresAt !== null && Date.parse(n.expiresAt) >= Date.parse(p.expiresAt)))
    if (!still) out.add(p.permission)
  }
  if (view.accountType === 'admin' && draft.profile !== profileOf(view)) {
    for (const p of byId.get(draft.profile ?? FULL_ADMIN_PROFILE)?.permissions ?? []) out.add(p)
  }
  return [...out]
}

/** The server takes the person's password for any change to an admin, and for these permissions (ID-25). */
export function stepUpNeeded(view: AccountPermissionsView, giving: readonly PermissionId[]): PermissionId[] | 'admin' | null {
  if (view.accountType === 'admin') return 'admin'
  const listed = stepUpPermissionsIn(giving)
  return listed.length ? listed : null
}

/*
 * The preview (capabilities.ts `resolveCapabilities`, client side): what the account would hold once
 * the draft is saved. The form decides the sets, the admin profile and the overrides; everything
 * else (Root standing, legacy grants, instance switches, an inactive account) is carried over from
 * the saved explanation as it is. A preview only: the server decides on save.
 */

/** Reasons the form cannot change. */
const FIXED_REASONS: ReadonlySet<ReasonView['kind']> = new Set(['root', 'root_unconfirmed', 'legacy_grant', 'phase1_admin', 'instance_cap', 'inactive'])

export interface PreviewSource {
  /** GET /api/admin/permission-sets, or null when it could not be read. */
  sets: SetList | null
  /** GET /api/admin/admin-profiles (admin targets), or null when it could not be read. */
  profiles: SetList | null
}

export interface Preview {
  explain: ExplanationView[]
  sets: SetInForceView[]
}

/**
 * The contents of a set of this kind: built-ins from code, custom sets from the list (keeping only
 * known permissions of that kind, as the server does). `undefined`: the list that would say is unread.
 */
function contentsOf(id: string, kind: 'member' | 'admin', list: SetList | null): { name: string; permissions: PermissionId[] } | null | undefined {
  const builtin = builtinSet(id)
  if (builtin) return builtin.kind === kind ? { name: builtin.name, permissions: [...builtin.permissions] } : null
  if (!list) return undefined
  const row = list.sets.find((x) => x.id === id && x.kind === kind)
  if (!row) return null
  return {
    name: row.name,
    permissions: row.permissions.filter((p) => isPermissionId(p) && PERMISSIONS[p].kind === kind && (!PERMISSIONS[p].rootOnly || p === 'admins:manage')),
  }
}

/** What the account would hold with the draft saved, or null when a set the draft names cannot be read. */
export function previewOf(view: AccountPermissionsView, draft: Draft, source: PreviewSource, at = Date.now()): Preview | null {
  if (view.accountType === 'root') return { explain: view.explain, sets: view.sets }
  const inForce: SetInForceView[] = []
  const setGrants = new Map<PermissionId, ReasonView[]>()
  const overrideReasons = new Map<PermissionId, ReasonView[]>()
  const push = (map: Map<PermissionId, ReasonView[]>, p: PermissionId, r: ReasonView) => {
    const list = map.get(p)
    if (list) list.push(r)
    else map.set(p, [r])
  }
  const grantSet = (set: SetInForceView, permissions: readonly PermissionId[]) => {
    inForce.push(set)
    for (const p of permissions) push(setGrants, p, { effect: 'grant', kind: 'set', set })
  }
  const named = (id: string, kind: 'member' | 'admin', via: SetVia): boolean | null => {
    const set = contentsOf(id, kind, kind === 'admin' ? source.profiles : source.sets)
    if (set === undefined) return null
    if (set === null) return false
    grantSet({ id, name: set.name, kind, via }, set.permissions)
    return true
  }
  const noAccess = () => grantSet({ id: NO_ACCESS_SET_ID, name: builtinSet(NO_ACCESS_SET_ID)?.name ?? 'No access', kind: 'member', via: 'dangling' }, [])

  if (view.accountType === 'admin') {
    if (draft.profile === null) named(FULL_ADMIN_PROFILE, 'admin', 'default')
    else if (named(draft.profile, 'admin', 'assigned') === null) return null
  }
  if (draft.sets.length > 0) {
    let found = 0
    for (const id of draft.sets) {
      const done = named(id, 'member', 'assigned')
      if (done === null) return null
      if (done) found += 1
    }
    if (found === 0) noAccess()
  } else if (view.accountType === 'admin') {
    named(DEFAULT_MEMBER_SET, 'member', 'default')
  } else {
    if (!source.sets) return null
    const id = source.sets.instanceDefaultSetId ?? null
    if (id === null) named(DEFAULT_MEMBER_SET, 'member', 'default')
    else if (named(id, 'member', 'instance_default') === false) noAccess()
  }

  for (const o of draft.overrides) {
    if (!isPermissionId(o.permission) || !isLive(o, at)) continue
    const r: ReasonView = { effect: o.effect, kind: 'override', expiresAt: o.expiresAt, reason: o.reason }
    const meta = PERMISSIONS[o.permission]
    if (o.effect === 'deny' || meta.kind === 'member' || (view.accountType === 'member' && meta.crossTenant)) push(overrideReasons, o.permission, r)
  }

  const explain = view.explain.map((e): ExplanationView => {
    const fixed = e.reasons.filter((r) => FIXED_REASONS.has(r.kind))
    const reasons: ReasonView[] = [
      ...(setGrants.get(e.permission) ?? []),
      ...fixed.filter((r) => r.effect === 'grant'),
      ...(overrideReasons.get(e.permission) ?? []),
      ...fixed.filter((r) => r.effect === 'deny'),
    ]
    const denied = reasons.some((r) => r.effect === 'deny')
    const held = reasons.some((r) => r.effect === 'grant') && !denied
    if (!held && !denied) reasons.push({ effect: 'deny', kind: 'not_granted', sets: inForce })
    return { permission: e.permission, held, reasons }
  })
  return { explain, sets: inForce }
}

/** What saving would add to and take from the permissions held, in registry order. */
export function heldDiff(before: readonly ExplanationView[], after: readonly ExplanationView[]): { gained: PermissionId[]; lost: PermissionId[] } {
  const was = new Set(before.filter((e) => e.held).map((e) => e.permission))
  const will = new Set(after.filter((e) => e.held).map((e) => e.permission))
  return {
    gained: after.filter((e) => e.held && !was.has(e.permission)).map((e) => e.permission),
    lost: before.filter((e) => e.held && !will.has(e.permission)).map((e) => e.permission),
  }
}

export interface DraftChanges {
  setsAdded: string[]
  setsRemoved: string[]
  overridesAdded: OverrideView[]
  overridesRemoved: OverrideView[]
  /** The same permission, with another effect, expiry or reason. */
  overridesChanged: OverrideView[]
  /** Admin targets: the profile before and after (null = *Full admin*), when it changed. */
  profile: { from: string | null; to: string | null } | null
  count: number
}

/** The edits the draft makes to the saved assignment, item by item. */
export function draftChanges(view: AccountPermissionsView, draft: Draft): DraftChanges {
  const start = draftOf(view)
  const before = new Map(start.overrides.map((o) => [o.permission, o]))
  const after = new Map(draft.overrides.map((o) => [o.permission, o]))
  const setsAdded = draft.sets.filter((id) => !start.sets.includes(id))
  const setsRemoved = start.sets.filter((id) => !draft.sets.includes(id))
  const overridesAdded = draft.overrides.filter((o) => !before.has(o.permission))
  const overridesRemoved = start.overrides.filter((o) => !after.has(o.permission))
  const overridesChanged = draft.overrides.filter((o) => {
    const was = before.get(o.permission)
    return was !== undefined && overrideKey(was) !== overrideKey(o)
  })
  const profile = view.accountType === 'admin' && draft.profile !== start.profile ? { from: start.profile, to: draft.profile } : null
  const count = setsAdded.length + setsRemoved.length + overridesAdded.length + overridesRemoved.length + overridesChanged.length + (profile ? 1 : 0)
  return { setsAdded, setsRemoved, overridesAdded, overridesRemoved, overridesChanged, profile, count }
}

/** How a set's contents compare with the other sets of its kind, to say what overlaps what. */
export function setRelations(set: SetOption, all: readonly SetOption[]): { same: SetOption[]; includes: SetOption[]; within: SetOption[] } {
  const mine = new Set(set.permissions)
  const out = { same: [] as SetOption[], includes: [] as SetOption[], within: [] as SetOption[] }
  for (const other of all) {
    if (other.id === set.id || other.kind !== set.kind || other.permissions.length === 0 || mine.size === 0) continue
    const theirs = new Set(other.permissions)
    const inMine = other.permissions.every((p) => mine.has(p))
    const inTheirs = set.permissions.every((p) => theirs.has(p))
    if (inMine && inTheirs) out.same.push(other)
    else if (inMine) out.includes.push(other)
    else if (inTheirs) out.within.push(other)
  }
  return out
}
