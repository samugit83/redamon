/**
 * The owner check of a per-user row: a preset, a mute-rule preset, a conversation's author, a
 * user-scope override set. The row names its owner's id and only that account may use it: the
 * effective user, under act-as the account acted as. It is not a project check: who may reach a
 * project is `projectAccess()`'s answer, and a per-user row stays its owner's whoever else may
 * reach its project.
 *
 * The owner helpers of access.ts and the plugin platform share this one strict rule, so it fails
 * closed in one place: an exact match of two non-empty ids, and a filter that matches nothing for
 * a subject without an id.
 */
import type { ProjectAccessSubject } from './projectAccess'

/** Whether `subject` owns a row whose owner id is `ownerId`. An empty or missing id owns nothing. */
export function ownsRow(subject: ProjectAccessSubject, ownerId: unknown): boolean {
  return typeof ownerId === 'string' && ownerId !== '' && ownerId === subject.userId
}

/** A Prisma where-fragment on a row's `userId`: the subject's own id, or `in: []`, which matches no row. */
export type RowOwnerFilter = { userId: string | { in: string[] } }

/**
 * The where-fragment that scopes a list of per-user rows to the subject's own. Prisma drops a
 * filter whose value is undefined, so a subject without an id would list every account's rows:
 * it gets `in: []` instead.
 */
export function rowOwnerFilter(subject: ProjectAccessSubject): RowOwnerFilter {
  const id: unknown = subject.userId
  if (typeof id !== 'string' || id === '') return { userId: { in: [] } }
  return { userId: id }
}
