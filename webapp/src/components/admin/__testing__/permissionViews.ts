/**
 * Answers of the permission APIs (step 3.11) for the permission screens' tests (step 3.13): an
 * account's view built from what it holds, and the set and profile lists from the built-ins.
 */
import { PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { BUILTIN_ADMIN_PROFILES, BUILTIN_MEMBER_SETS, builtinSet } from '@/lib/authz/builtinSets'
import type { AccountPermissionsView, ExplanationView, OverrideView, ReasonView, SetInForceView, SetOption } from '../permissionModel'

export const setsOf = (...ids: string[]): PermissionId[] => [...new Set(ids.flatMap((id) => [...builtinSet(id)!.permissions]))]

interface ViewInput {
  userId: string
  accountType?: 'root' | 'admin' | 'member'
  /** Sets in force (built-in ids), their `via`. */
  sets?: Array<{ id: string; via?: SetInForceView['via'] }>
  assigned?: string[]
  overrides?: OverrideView[]
  profile?: string | null
  /** Extra permissions held, each with this reason. */
  extra?: Array<{ permission: PermissionId; reason: ReasonView }>
  /** Permissions held only but for an instance cap. */
  capped?: PermissionId[]
}

export function viewOf(input: ViewInput): AccountPermissionsView {
  const accountType = input.accountType ?? 'member'
  const inForce: SetInForceView[] = (input.sets ?? []).map(({ id, via = 'assigned' }) => {
    const b = builtinSet(id)!
    return { id, name: b.name, kind: b.kind, via }
  })
  const reasons = new Map<PermissionId, ReasonView[]>()
  const add = (p: PermissionId, r: ReasonView) => reasons.set(p, [...(reasons.get(p) ?? []), r])
  for (const s of inForce) for (const p of builtinSet(s.id)!.permissions) add(p, { effect: 'grant', kind: 'set', set: s })
  for (const e of input.extra ?? []) add(e.permission, e.reason)
  for (const p of input.capped ?? []) add(p, { effect: 'deny', kind: 'instance_cap', setting: 'MCP_SERVER_ENABLED' })
  for (const o of input.overrides ?? []) {
    add(o.permission, { effect: o.effect, kind: 'override', expiresAt: o.expiresAt, reason: o.reason })
  }
  const explain: ExplanationView[] = PERMISSION_IDS.map((permission) => {
    const rs = reasons.get(permission) ?? []
    const held = rs.some((r) => r.effect === 'grant') && !rs.some((r) => r.effect === 'deny')
    return {
      permission,
      held,
      reasons: rs.length ? rs : [{ effect: 'deny', kind: 'not_granted', sets: inForce }],
    }
  })
  return {
    userId: input.userId,
    accountType,
    enforced: true,
    assignment: {
      sets: input.assigned ?? inForce.filter((s) => s.via === 'assigned' && s.kind === 'member').map((s) => s.id),
      overrides: input.overrides ?? [],
      ...(accountType === 'admin' ? { adminProfileId: input.profile ?? null } : {}),
    },
    sets: inForce,
    missingSets: [],
    held: explain.filter((e) => e.held).map((e) => e.permission),
    explain,
  }
}

/** GET /api/admin/permission-sets: the built-ins, then `custom`. */
export function memberSetList(custom: SetOption[] = [], instanceDefaultSetId: string | null = null) {
  return {
    kind: 'member',
    sets: [
      ...BUILTIN_MEMBER_SETS.map((s): SetOption => ({
        id: s.id, kind: 'member', name: s.name, description: s.description, permissions: [...s.permissions], builtin: true,
        holders: 0, instanceDefault: s.id === instanceDefaultSetId,
      })),
      ...custom.map((c) => ({ ...c, instanceDefault: c.id === instanceDefaultSetId })),
    ],
    instanceDefaultSetId,
  }
}

/** GET /api/admin/admin-profiles: the built-ins, then `custom`. */
export function profileList(custom: SetOption[] = []) {
  return {
    kind: 'admin',
    sets: [
      ...BUILTIN_ADMIN_PROFILES.map((s): SetOption => ({
        id: s.id, kind: 'admin', name: s.name, description: s.description, permissions: [...s.permissions], builtin: true,
        holders: 0, instanceDefault: false,
      })),
      ...custom,
    ],
  }
}

export const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
