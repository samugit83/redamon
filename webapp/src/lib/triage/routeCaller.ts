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

/**
 * The person a triage write is attributed to (step 5.2; SH-24, SH-25): the effective user, never the
 * tenant. On a shared project a collaborator's mute and verdict name the collaborator (`muted_by`,
 * `triage_verdict_by`, the audit actor) while the graph keeps the owner as tenant. For the owner, and
 * an admin acting as the owner, it is the owner, exactly as before. Under act-as a share reaches
 * read only (D-22), so an acting admin never writes on someone else's project here.
 */
export function triagePerson(auth: PermissionContext): string {
  return auth.effective.userId
}
