/**
 * The registry's areas (feature document §5.1-§5.12), for the screens that list or pick
 * permissions (step 3.13: the override picker, the effective permissions, My permissions).
 *
 * Each area starts at its first permission in registry order and runs to the next area's first,
 * so a permission added to the registry lands in the area of the section it was written in. Data
 * only: the browser imports it.
 */
import { PERMISSION_IDS, type PermissionId } from './permissions'

export interface PermissionArea {
  id: string
  title: string
  permissions: readonly PermissionId[]
}

const STARTS: ReadonlyArray<readonly [PermissionId, string, string]> = [
  ['users:read', 'administration', 'Administration'],
  ['platform:plugins', 'platform', 'Platform operations'],
  ['self:llm_providers', 'self', 'Your own account'],
  ['project:create', 'projects', 'Projects'],
  ['recon:read', 'recon', 'Recon and scanning'],
  ['agent:chat', 'agent', 'AI agent'],
  ['workspace:read', 'workspace', 'Workspace'],
  ['graph:read', 'graph', 'Graph and analytics'],
  ['triage:read', 'triage', 'Triage and remediation'],
  ['reports:read', 'reports', 'Reports'],
  ['traffic:read', 'traffic', 'Traffic and authenticated sessions'],
  ['plugins:use', 'plugins', 'Plugins'],
]

function build(): readonly PermissionArea[] {
  const at = STARTS.map(([first]) => PERMISSION_IDS.indexOf(first))
  return Object.freeze(STARTS.map(([, id, title], i) => Object.freeze({
    id,
    title,
    permissions: Object.freeze(PERMISSION_IDS.slice(at[i], i + 1 < at.length ? at[i + 1] : undefined)),
  })))
}

export const PERMISSION_AREAS: readonly PermissionArea[] = build()

const AREA_OF: ReadonlyMap<PermissionId, PermissionArea> = new Map(
  PERMISSION_AREAS.flatMap((a) => a.permissions.map((p) => [p, a] as const)),
)

export function areaOf(permission: PermissionId): PermissionArea {
  return AREA_OF.get(permission)!
}

/** `items` grouped by area, areas and permissions in registry order; empty areas left out. */
export function groupByArea<T extends { permission: PermissionId }>(items: readonly T[]): Array<{ area: PermissionArea; items: T[] }> {
  const by = new Map(items.map((x) => [x.permission, x]))
  return PERMISSION_AREAS
    .map((area) => ({ area, items: area.permissions.filter((p) => by.has(p)).map((p) => by.get(p)!) }))
    .filter((g) => g.items.length > 0)
}
