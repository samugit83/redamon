/**
 * Every check a Navigator route makes before it touches a thread (plan §7.3), in one place:
 *
 *   1. `navigator:use` on the project, refusing oversight and break-glass inside the guard, before
 *      the `project.oversee` row would be written (D12); act-as gets can()'s intersection, Read at most;
 *   2. the access is the owner's or a share's (defence in depth behind 1);
 *   3. Root's switch is on (D15);
 *   4. the owner's policy lets this person in (D3).
 *
 * The context it answers keeps the tenant (the project's owner: every data read) and the person
 * (the effective user: threads, limits, the model) apart, and the login the request came from,
 * which a run is bound to.
 */
import { NextResponse } from 'next/server'
import type { PermissionContext } from '@/lib/authz/guards'
import { navigatorAllowedFor } from '@/lib/authz/navigatorPolicy'
import type { ProjectAccess } from '@/lib/authz/projectAccess'
import { sessionDeviceId } from '@/lib/authz/deviceSessions'
import { internalError } from '@/lib/routeErrors'
import { navigatorEnabled } from './switch'
import { navigatorError } from './responses'
import type { RunLogin } from './runRegistry'

export interface NavigatorContext {
  auth: PermissionContext
  /** The project's owner: the tenant of every graph, file and record read. */
  tenantId: string
  /** The effective user: owns the thread, spends the model, counts against the limits. */
  personId: string
  /** The real signed-in admin under act-as, else null. */
  actorId: string | null
  projectId: string
  access: ProjectAccess
  login: RunLogin
}

/**
 * Steps 2-5, on what the route's own `requirePermission(request, 'navigator:use', { projectId,
 * allowOversight: false })` answered (the call stays in the route, where the route manifest and the
 * static guard tests read it). Its 403 `oversight_not_allowed` reads as `navigator_not_available`.
 */
export async function navigatorContext(auth: PermissionContext | NextResponse): Promise<NavigatorContext | NextResponse> {
  if (auth instanceof NextResponse) {
    if (auth.status === 403) {
      const body = await auth.clone().json().catch(() => null) as { code?: string } | null
      if (body?.code === 'oversight_not_allowed') return navigatorError('navigator_not_available', 403)
    }
    return auth
  }
  const access = auth.access
  if (!access || (access.via !== 'owner' && access.via !== 'share')) return navigatorError('navigator_not_available', 403)
  try {
    if (!(await navigatorEnabled())) return navigatorError('navigator_disabled', 403)
    if (!(await navigatorAllowedFor(access))) return navigatorError('owner_disallowed', 403)
  } catch (err) {
    return internalError(err, 'Could not check AI Navigator access')
  }
  return {
    auth,
    tenantId: access.project.userId,
    personId: auth.effective.userId,
    actorId: auth.actingAs ? auth.principal.id : null,
    projectId: access.project.id,
    access,
    login: {
      userId: auth.principal.id,
      sessionVersion: auth.principal.sessionVersion,
      deviceSessionId: sessionDeviceId(auth.session),
      actAsStartId: auth.actAsStartId ?? null,
    },
  }
}
