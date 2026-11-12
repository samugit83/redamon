/**
 * The tenant a triage or mute-rule route acts for, from the context `requirePermission` answered
 * on the project (step 3.9): the project's owner, whose graph holds its nodes, and the project.
 * The same answer `requireProjectOwner` gives, so the graph calls and audit rows do not change.
 *
 * Its own module, importing triageClient only as a type: route tests replace triageClient whole.
 */
import type { PermissionContext } from '@/lib/authz/guards'
import type { TriageCaller } from '@/lib/triageClient'

export function triageCaller(auth: PermissionContext): TriageCaller {
  const project = auth.access?.project
  if (!project) throw new Error('triageCaller needs a context that checked a project')
  return { userId: project.userId, projectId: project.id }
}
