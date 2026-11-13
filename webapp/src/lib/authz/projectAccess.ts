/**
 * The project layer of the policy (feature document §4.2, §6.1): how far a person may go on one
 * project. `can()` asks it for every permission that acts on a project, and the owner helpers of
 * access.ts, triageClient.ts, mcpAuth.ts and the plugin platform delegate to it, so one function
 * decides who sees a project.
 *
 * The answer (step 4.3; SH-02, SH-03, SH-14, SH-16, SH-18, D-22):
 *   - the owner: `owner`, every level;
 *   - with sharing in force (RBAC_SHARING_ENABLED and Root's `sharingPolicy.enabled`), anyone else:
 *     a live share (unexpired on the clock, the collaborator's account active) is `read`, with Raw
 *     data & files when the row says so (a row at `write` reads as `read` until Phase 5 gives write
 *     its level); an unexpired break-glass row of someone who still holds `projects:administer` is
 *     `read` with Raw data; holding `projects:oversee` is `read` without it. The strongest wins,
 *     and a share before oversight, which its callers audit (step 4.14);
 *   - otherwise nothing. With sharing not in force no share, break-glass or account row is read
 *     (with the switch off, not the policy either): the answer is the owner's alone, as in Phase 3.
 * Anyone left out, and a project that does not exist, get the same null, so the caller answers 404
 * for both and a stranger cannot tell that a project exists.
 *
 * The person is the effective user: under act-as, the account acted as (`getEffectiveUser`), so a
 * project reached through that account's share is `read`, never more (D-22), and the acting
 * admin's own oversight never applies. `project.userId` is the owner: the tenant of every graph,
 * traffic and credential read (T9).
 *
 * Nothing is cached here: a revoked or expired share ends with the next request (expiry is judged on
 * every read; step 4.15's sweep only deletes the rows). The owner's request costs one read by primary
 * key; anyone else's, with sharing in force, the policy (cached), the share by primary key, and
 * unless the share gives Raw data the break-glass rows and the person's capabilities (cached). A
 * failed read throws, it never reads as access.
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'
import { loadPrincipal } from './principal'
import { resolveCapabilities, type Capabilities, type CapabilityPrincipal } from './capabilities'
import { sharingPolicyInForce } from './sharingPolicy'
import type { ProjectLevel } from './permissions'

/** Whose data the request touches: the account acted as, else the signed-in account (EffectiveUser). */
export interface ProjectAccessSubject {
  userId: string
}

/** `owner` reaches every level; `read` the read levels (`R`, and `R*` with Raw data & files). */
export type ProjectAccessLevel = 'owner' | 'read'

/** What gave the access. A route that used `oversight` writes its audit row (step 4.14). */
export type ProjectAccessVia = 'owner' | 'share' | 'break_glass' | 'oversight'

export interface ProjectAccessToggles {
  /** Raw data & files (§6.1): traffic, workspace files, raw scan outputs, step content (`R*`). */
  rawData: boolean
}

export interface ProjectAccess {
  /** The project and its owner (`userId`), the tenant of its data. */
  project: { id: string; userId: string }
  level: ProjectAccessLevel
  toggles: Readonly<ProjectAccessToggles>
  via: ProjectAccessVia
}

export interface ProjectAccessOptions {
  /** A critical check (can()'s `fresh`): the policy, the person's account and sets are read again. */
  fresh?: boolean
  /**
   * The person as this request already read them (can() passes it), for the capabilities oversight
   * and break-glass need; used only when it is the subject, else the account is read.
   */
  principal?: CapabilityPrincipal | null
}

/** The share kinds that give access; a stored kind outside them (a later release's, a bad write) gives nothing. */
export const SHARE_ACCESS: ReadonlySet<string> = new Set(['read', 'write'])

function answer(project: { id: string; userId: string }, level: ProjectAccessLevel, rawData: boolean, via: ProjectAccessVia): ProjectAccess {
  return Object.freeze({
    project: Object.freeze({ id: project.id, userId: project.userId }),
    level,
    toggles: Object.freeze({ rawData }),
    via,
  })
}

/** The access `subject` has to the project, or null when they cannot see it or it does not exist. */
export async function projectAccess(
  subject: ProjectAccessSubject,
  projectId: string,
  opts: ProjectAccessOptions = {},
): Promise<ProjectAccess | null> {
  if (!projectId || !subject.userId) return null
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { id: true, userId: true },
  })
  if (!project) return null
  if (project.userId === subject.userId) return answer(project, 'owner', true, 'owner')
  if (!(await sharingLive(opts.fresh === true))) return null
  return accessOfOthers(project, subject.userId, opts)
}

/** Sharing in force: the switch, then Root's policy (read only with the switch on). */
async function sharingLive(fresh: boolean): Promise<boolean> {
  if (!rbacFlags().sharing) return false
  const policy = await sharingPolicyInForce({ fresh })
  return policy?.enabled === true
}

async function accessOfOthers(project: { id: string; userId: string }, userId: string, opts: ProjectAccessOptions): Promise<ProjectAccess | null> {
  const at = now().getTime()
  const share = await prisma.projectCollaborator.findUnique({
    where: { projectId_userId: { projectId: project.id, userId } },
    select: { access: true, rawData: true, expiresAt: true, user: { select: { status: true } } },
  })
  const shared = share !== null
    && SHARE_ACCESS.has(share.access)
    && (share.expiresAt === null || share.expiresAt.getTime() > at)
    && share.user?.status === 'active'
  if (shared && share.rawData === true) return answer(project, 'read', true, 'share')

  const glass = await prisma.projectBreakGlass.findFirst({
    where: { projectId: project.id, userId, expiresAt: { gt: new Date(at) } },
    select: { expiresAt: true },
  })
  const glassLive = glass !== null && glass.expiresAt.getTime() > at
  if (shared && !glassLive) return answer(project, 'read', false, 'share')

  const capabilities = await capabilitiesOf(userId, opts)
  // Root's break-glass ends with Root's standing, not only at its expiry.
  if (glassLive && capabilities?.has('projects:administer')) return answer(project, 'read', true, 'break_glass')
  if (shared) return answer(project, 'read', false, 'share')
  if (capabilities?.has('projects:oversee')) return answer(project, 'read', false, 'oversight')
  return null
}

/** The subject's own capabilities (never an act-as intersection: the subject is one account). */
async function capabilitiesOf(userId: string, opts: ProjectAccessOptions): Promise<Capabilities | null> {
  const fresh = opts.fresh === true
  const principal = opts.principal && opts.principal.id === userId ? opts.principal : await loadPrincipal(userId, { fresh })
  return principal ? resolveCapabilities(principal, { fresh }) : null
}

/**
 * Whether the access reaches the level a permission needs (§5 legend): the owner every level;
 * `read` reaches `R`, and `R*` with Raw data & files; nothing reaches a write level below the
 * owner until Phase 5. A kind of access without its own row here (or a missing toggle) fails
 * closed.
 */
export function meetsLevel(access: ProjectAccess, needed: ProjectLevel): boolean {
  if (access.level === 'owner') return true
  if (access.level !== 'read') return false
  if (needed === 'R') return true
  return needed === 'R*' && access.toggles?.rawData === true
}

/** What a person is told of their own access to a project: the project GET's `myAccess` and /my-access. */
export interface MyAccess {
  level: ProjectAccessLevel
  toggles: ProjectAccessToggles
  via: ProjectAccessVia
  /** Who shared it, for "Read access, shared by <owner>". */
  owner: { name: string | null; email: string | null }
}

export function myAccessView(access: ProjectAccess, owner: { name?: string | null; email?: string | null } | null | undefined): MyAccess {
  return {
    level: access.level,
    toggles: { rawData: meetsLevel(access, 'R*') },
    via: access.via,
    owner: { name: owner?.name ?? null, email: owner?.email ?? null },
  }
}
