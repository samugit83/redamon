/**
 * How the projects page reads a list row's own access (`myAccess`, GET /api/projects, step 4.5):
 * which rows are shared with the person, the level badge of a shared card, and who shared it.
 * A row without `myAccess` (RBAC_SHARING_ENABLED off) is the person's own, as before sharing.
 */
import type { MyAccess } from '@/lib/authz/projectAccess'

export interface WithMyAccess {
  myAccess?: MyAccess | null
  user?: { name?: string | null; email?: string | null } | null
}

export function isSharedWithMe(row: WithMyAccess): boolean {
  return !!row.myAccess && row.myAccess.level !== 'owner'
}

/** The person's own rows and the shared ones, each in list order. */
export function splitProjectList<T extends WithMyAccess>(rows: readonly T[]): { owned: T[]; shared: T[] } {
  const owned: T[] = []
  const shared: T[] = []
  for (const row of rows) (isSharedWithMe(row) ? shared : owned).push(row)
  return { owned, shared }
}

export function accessBadge(myAccess: MyAccess): string {
  if (myAccess.level === 'owner') return 'Owner'
  // Step 4.14: the "All projects (oversight)" list names how an admin reaches each project.
  if (myAccess.via === 'oversight') return 'Oversight (Read)'
  if (myAccess.via === 'break_glass') return 'Break-glass (Read + Raw data)'
  return myAccess.toggles.rawData ? 'Read + Raw data' : 'Read'
}

/** The owner of a shared row as "Name (email)", from myAccess, else the row's owner. */
export function sharedByLabel(row: WithMyAccess): string {
  const fromAccess = row.myAccess?.owner
  const who = fromAccess?.name || fromAccess?.email ? fromAccess : row.user
  const name = who?.name || null
  const email = who?.email || null
  if (name && email) return `${name} (${email})`
  return name ?? email ?? 'another account'
}
