/**
 * What a screen may offer on a project, from the person's own access to it (`myAccess`, the
 * project GET, GET /api/projects rows and GET /api/projects/[id]/my-access, step 4.3): the browser's
 * copy of `meetsLevel`'s table (lib/authz/projectAccess.ts) and the words a control refused by the
 * access level shows (step 4.11).
 *
 * No `myAccess` means RBAC_SHARING_ENABLED is off (DV-30): the person's own project, as before
 * sharing, so nothing is refused here. The route still decides every action; this only stops a
 * screen offering what its route will refuse.
 *
 * Data only: no React, no request, so tests and server code can import it too.
 */
import type { MyAccess, WriteToggles } from '@/lib/authz/projectAccess'
import { PERMISSIONS, type PermissionId, type ProjectLevel } from '@/lib/authz/permissions'
import { sharedByLabel } from '@/lib/sharedProjects'

/** The toggle each toggled write level needs (§6.2), as `meetsLevel` reads it, with its words. */
const LEVEL_TOGGLE: Readonly<Partial<Record<ProjectLevel, { toggle: keyof WriteToggles; words: string }>>> = {
  'W+S': { toggle: 'runScans', words: 'Run scans' },
  'W+A': { toggle: 'useAgent', words: 'Use AI agent' },
  'W+X': { toggle: 'exploit', words: 'Exploitation & shells' },
  M: { toggle: 'manage', words: 'Manage' },
}

/**
 * Whether `access` reaches `level`: `meetsLevel`'s rows, kept together with it. Read + Write reaches
 * `R`, `R*` and `W`, a toggled level with its toggle as the server answered it (`myAccess.toggles`,
 * so the run toggles read off until the server opens them), never `O`.
 */
export function myAccessMeets(access: MyAccess | null | undefined, level: ProjectLevel | null): boolean {
  if (!access || level === null) return true
  if (access.level === 'owner') return true
  if (access.level === 'write') {
    if (level === 'R' || level === 'R*' || level === 'W') return true
    const toggle = LEVEL_TOGGLE[level]?.toggle
    return toggle !== undefined && access.toggles?.[toggle] === true
  }
  if (access.level !== 'read') return false
  if (level === 'R') return true
  return level === 'R*' && access.toggles?.rawData === true
}

/**
 * "Read access, shared by <owner>" (P4-03), naming what the access lacks when the control needs the
 * Raw data & files toggle, and how an admin reads a project nobody shared with them. A Read + Write
 * share names the toggle the control needs, or that only the owner may do it (step 5.2).
 */
export function readAccessNotice(access: MyAccess, level: ProjectLevel | null = null): string {
  const owner = sharedByLabel({ myAccess: access })
  if (access.level === 'write') {
    if (level === 'O') return `Read + Write access, shared by ${owner}; only the owner can do this`
    const missing = level ? LEVEL_TOGGLE[level]?.words : undefined
    return `Read + Write access${missing ? ` without ${missing}` : ''}, shared by ${owner}`
  }
  const raw = level === 'R*' && access.toggles?.rawData !== true ? ' without Raw data & files' : ''
  if (access.via === 'oversight') return `Read access${raw} through oversight; the project belongs to ${owner}`
  if (access.via === 'break_glass') return `Read access${raw} through break-glass; the project belongs to ${owner}`
  return `Read access${raw}, shared by ${owner}`
}

/** The notice for `permission` on a project reached through `access`, or null when the level allows it. */
export function levelRefusalText(access: MyAccess | null | undefined, permission: PermissionId): string | null {
  const level = PERMISSIONS[permission]?.level ?? null
  if (!access || myAccessMeets(access, level)) return null
  return readAccessNotice(access, level)
}

/** Whether two answers say the same thing, so an unchanged poll answer re-renders nothing. */
export function sameMyAccess(a: MyAccess | null | undefined, b: MyAccess | null | undefined): boolean {
  if (!a || !b) return a === b
  const toggles = ['rawData', 'runScans', 'useAgent', 'exploit', 'manage'] as const
  return a.level === b.level
    && a.via === b.via
    && toggles.every(t => (a.toggles?.[t] === true) === (b.toggles?.[t] === true))
    && (a.owner?.name ?? null) === (b.owner?.name ?? null)
    && (a.owner?.email ?? null) === (b.owner?.email ?? null)
}
