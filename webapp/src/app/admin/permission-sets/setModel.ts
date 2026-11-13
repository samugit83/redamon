/**
 * What the permission sets and admin profiles pages read, send and mirror (step 6.3; GV-02, GV-03):
 * the shapes of `GET /api/admin/permission-sets` and `/api/admin/admin-profiles` (step 3.11,
 * permissionSetAdmin.ts `SetView`), and the client copy of the rules that module applies, so a
 * screen offers only what the server would take. The server stays the authority: a stale mirror
 * costs a refusal, never a permission.
 */
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { PERMISSION_AREAS, type PermissionArea } from '@/lib/authz/permissionAreas'
import { stepUpPermissionsIn } from '@/lib/authz/hierarchy'
import { DEFAULT_MEMBER_SET } from '@/components/admin/permissionModel'

export type SetKind = 'member' | 'admin'

/** One row of the list (permissionSetAdmin.ts `SetView`). */
export interface SetRow {
  id: string
  kind: SetKind
  name: string
  description: string | null
  permissions: PermissionId[]
  builtin: boolean
  clonedFrom: string | null
  createdAt: string | null
  updatedAt: string | null
  /** Member sets: accounts assigned it. Profiles: admins holding it (*Full admin* also those with none recorded). */
  holders: number
  instanceDefault: boolean
}

export interface SetListAnswer {
  kind?: SetKind
  sets: SetRow[]
  /** Member sets only: null = the built-in *Default member*. */
  instanceDefaultSetId?: string | null
}

/** permissionSetAdmin.ts MAX_NAME / MAX_DESCRIPTION. */
export const MAX_NAME = 80
export const MAX_DESCRIPTION = 500

/**
 * What a set of this kind may hold (permissionSetAdmin.ts `parsePermissions`): permissions of its
 * kind, and of Root's own only `admins:manage`, which Root may opt to put in a profile (OQ-02).
 */
export function pickable(kind: SetKind): PermissionId[] {
  return PERMISSION_IDS.filter((p) => PERMISSIONS[p].kind === kind && (!PERMISSIONS[p].rootOnly || p === 'admins:manage'))
}

export function pickableAreas(kind: SetKind): Array<{ area: PermissionArea; permissions: PermissionId[] }> {
  const allowed = new Set(pickable(kind))
  return PERMISSION_AREAS
    .map((area) => ({ area, permissions: area.permissions.filter((p) => allowed.has(p)) }))
    .filter((g) => g.permissions.length > 0)
}

/**
 * An edit adds only what the editor may give (PE-11); what the set already holds may stay, or go
 * and come back, since that adds nothing.
 */
export function addable(permission: PermissionId, original: readonly PermissionId[], givable: ReadonlySet<PermissionId>): boolean {
  return givable.has(permission) || original.includes(permission)
}

export function addedBy(original: readonly PermissionId[], next: readonly PermissionId[]): PermissionId[] {
  const before = new Set(original)
  const wanted = new Set(next)
  return PERMISSION_IDS.filter((p) => wanted.has(p) && !before.has(p))
}

export interface Draft {
  name: string
  description: string
  permissions: PermissionId[]
}

/**
 * A clone starts from the source's permissions the editor may give; a creation must hold nothing
 * else, so the rest is named rather than sent to be refused.
 */
export function cloneStart(source: SetRow, givable: ReadonlySet<PermissionId>): { draft: Draft; leftOut: PermissionId[] } {
  return {
    draft: {
      name: `Copy of ${source.name}`.slice(0, MAX_NAME),
      description: source.description ?? '',
      permissions: source.permissions.filter((p) => givable.has(p)),
    },
    leftOut: source.permissions.filter((p) => !givable.has(p)),
  }
}

const descriptionOf = (draft: Draft) => draft.description.trim() || null
const inOrder = (ids: readonly PermissionId[]) => addedBy([], ids)

export function createBody(draft: Draft, cloneFrom?: string): Record<string, unknown> {
  return {
    name: draft.name.trim(),
    description: descriptionOf(draft),
    permissions: inOrder(draft.permissions),
    ...(cloneFrom ? { cloneFrom } : {}),
  }
}

/** The PUT body of what changed (each key replaces that part), or null when nothing did. */
export function editBody(set: SetRow, draft: Draft): Record<string, unknown> | null {
  const body: Record<string, unknown> = {}
  if (draft.name.trim() !== set.name) body.name = draft.name.trim()
  if (descriptionOf(draft) !== (set.description ?? null)) body.description = descriptionOf(draft)
  const next = inOrder(draft.permissions)
  const before = inOrder(set.permissions)
  if (next.length !== before.length || next.some((p, i) => p !== before[i])) body.permissions = next
  return Object.keys(body).length ? body : null
}

/**
 * When the server takes the person's password: every profile write is the confirmed Root's
 * (`requireRootPower`); a member set's edit when it adds a cross-tenant tool, an exploitation
 * approval, sessions or Kali exec (ID-25). A new member set holds nobody, so creating it asks none:
 * assigning it does.
 */
export function passwordNeeded(kind: SetKind, mode: 'create' | 'edit', added: readonly PermissionId[]): 'root' | PermissionId[] | null {
  if (kind === 'admin') return 'root'
  if (mode === 'create') return null
  const listed = stepUpPermissionsIn(added)
  return listed.length ? listed : null
}

export function defaultSetId(list: Pick<SetListAnswer, 'instanceDefaultSetId'>): string {
  return list.instanceDefaultSetId ?? DEFAULT_MEMBER_SET
}
