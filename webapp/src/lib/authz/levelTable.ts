/**
 * The level table (feature document §5 legend, §6.2): which project levels an access reaches. In a
 * module of its own, with no import that runs, so the settings classification (settingsRisk.ts)
 * can be read by the project form in the browser too: projectAccess.ts, which re-exports this,
 * reads the database.
 */
import type { ProjectAccessLevel, ProjectAccessToggles, WriteToggles } from './projectAccess'
import type { ProjectLevel } from './permissions'

/** The toggle each toggled write level needs (§6.2). */
const LEVEL_TOGGLE: Readonly<Partial<Record<ProjectLevel, keyof WriteToggles>>> = {
  'W+S': 'runScans',
  'W+A': 'useAgent',
  'W+X': 'exploit',
  M: 'manage',
}

/**
 * Whether the access reaches the level a permission needs (§5 legend, §6.2): the owner every
 * level; `write` reaches `R`, `R*` (write includes Raw data & files) and `W`, `W+S` / `W+A` / `W+X`
 * with their toggle and `M` with Manage, never `O`; `read` reaches `R`, and `R*` with Raw data &
 * files. A kind of access without its own row here (or a missing toggle) fails closed.
 */
export function meetsLevel(
  access: { level: ProjectAccessLevel; toggles?: ProjectAccessToggles | null },
  needed: ProjectLevel,
): boolean {
  if (access.level === 'owner') return true
  if (access.level === 'write') {
    if (needed === 'R' || needed === 'R*' || needed === 'W') return true
    const toggle = LEVEL_TOGGLE[needed]
    return toggle !== undefined && access.toggles?.[toggle] === true
  }
  if (access.level !== 'read') return false
  if (needed === 'R') return true
  return needed === 'R*' && access.toggles?.rawData === true
}
