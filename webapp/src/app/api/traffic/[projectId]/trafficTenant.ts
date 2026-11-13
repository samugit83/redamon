/**
 * Whose rows a project's captured traffic is (step 4.9; SH-23, T9): its owner's. Every ingest path
 * stamps the owner as the row's `userId`: `ingest/route.ts` writes `project.userId`, and the proxy's
 * ingest worker the verified tag's user, the person whose scan or agent run it is, which only the
 * owner starts. So a read collaborator with Raw data & files reads the owner's rows, and the owner
 * reads exactly the rows it read before, under its own id. A writer that ever stamps someone else
 * (a collaborator's own run) must stamp the owner instead, or its rows stay out of every read.
 *
 * The owner comes from the access the guard decided (`auth.access.project.userId`, read from the
 * database), never from the caller or the request.
 */
import type { PermissionContext } from '@/lib/authz/guards'

export function trafficTenant(auth: PermissionContext): string {
  const owner = auth.access?.project.userId
  if (!owner) throw new Error('[rbac] a traffic route needs a context that checked its project')
  return owner
}

/** The where-fragment every traffic read starts from: the project's rows, under its owner. */
export function trafficRows(projectId: string, auth: PermissionContext): { projectId: string; userId: string } {
  return { projectId, userId: trafficTenant(auth) }
}
