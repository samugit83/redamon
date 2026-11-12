/**
 * The project layer of the policy (feature document §4.2, §6.1): how far a person may go on one
 * project. `can()` asks it for every permission that acts on a project, and the owner helpers of
 * access.ts, triageClient.ts, mcpAuth.ts and the plugin platform delegate to it, so one function
 * decides who sees a project.
 *
 * Owner-only, since a project has no members: the owner sees the project and holds every level;
 * anyone else, and a project that does not exist, get the same null, so the caller answers 404
 * for both and a stranger cannot tell that a project exists.
 *
 * The person is the effective user: under act-as, the account acted as (`getEffectiveUser`).
 * One read by primary key; a failed read throws, it never reads as access.
 */
import prisma from '@/lib/prisma'
import type { ProjectLevel } from './permissions'

/** Whose data the request touches: the account acted as, else the signed-in account (EffectiveUser). */
export interface ProjectAccessSubject {
  userId: string
}

export interface ProjectAccess {
  project: { id: string; userId: string }
  /** `owner` is the only level: a project has no members to hold a lesser one. */
  level: 'owner'
}

/** The access `subject` has to the project, or null when they cannot see it or it does not exist. */
export async function projectAccess(subject: ProjectAccessSubject, projectId: string): Promise<ProjectAccess | null> {
  if (!projectId || !subject.userId) return null
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, userId: true },
  })
  if (!project || project.userId !== subject.userId) return null
  return Object.freeze({ project: Object.freeze({ id: project.id, userId: project.userId }), level: 'owner' as const })
}

/**
 * Whether the access reaches the level a permission needs (§5 legend). The owner reaches every
 * level; any other access reaches none, so a kind of access added without its own level table
 * fails closed.
 */
export function meetsLevel(access: ProjectAccess, _needed: ProjectLevel): boolean {
  return access.level === 'owner'
}
