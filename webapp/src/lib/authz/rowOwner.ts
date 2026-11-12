/**
 * The owner check of a per-user row: a preset, a mute-rule preset, a conversation (its author's),
 * a user-scope override set. The row names its owner's id and only that account may use it: the
 * effective user, under act-as the account acted as. It is not a project check: a project goes
 * through `projectAccess()`, which Phase 4 widens with shares; a per-user row stays its owner's
 * (Phase 5 lets an author share a conversation, through its own table).
 *
 * The owner helpers of access.ts and the plugin platform delegate to it (step 3.6), so one strict
 * rule serves them: an exact match of two non-empty ids.
 */
import type { ProjectAccessSubject } from './projectAccess'

/** Whether `subject` owns a row whose owner id is `ownerId`. An empty or missing id owns nothing. */
export function ownsRow(subject: ProjectAccessSubject, ownerId: unknown): boolean {
  return typeof ownerId === 'string' && ownerId !== '' && ownerId === subject.userId
}

/** The Prisma where-fragment that scopes a list of per-user rows to the subject's own. */
export function rowOwnerFilter(subject: ProjectAccessSubject): { userId: string } {
  return { userId: subject.userId }
}
