/**
 * The project layer of the policy (feature document §4.2, §6.1): how far a person may go on one
 * project. `can()` asks it for every permission that acts on a project, and the owner helpers of
 * access.ts, triageClient.ts, mcpAuth.ts and the plugin platform delegate to it, so one function
 * decides who sees a project.
 *
 * The answer (step 4.3, step 5.2a; SH-02, SH-03, SH-07, SH-14, SH-16, SH-18, PE-25, D-22):
 *   - the owner: `owner`, every level;
 *   - with sharing in force (RBAC_SHARING_ENABLED and Root's `sharingPolicy.enabled`), anyone else:
 *     a live share (unexpired on the clock, the collaborator's account active) is `read`, with Raw
 *     data & files when the row says so; a row at `write` is `write` (Raw data included, the row's
 *     toggles through `effectiveToggles`, its run toggles only with the owner's consent, step 5.6) only
 *     with write sharing in force (RBAC_SHARING_WRITE_ENABLED and Root's `maxLevel: 'write'`,
 *     `maxShareLevel`) and never for the account an admin acts as,
 *     else it reads as `read`, exactly as in Phase 4; an unexpired break-glass row of someone who
 *     still holds `projects:administer` is `read` with Raw data; holding `projects:oversee` is `read`
 *     without it. The strongest wins, and a share before oversight, which its callers audit (step 4.14);
 *   - otherwise nothing. With sharing not in force no share, break-glass or account row is read
 *     (with the switch off, not the policy either): the answer is the owner's alone, as in Phase 3.
 * Anyone left out, and a project that does not exist, get the same null, so the caller answers 404
 * for both and a stranger cannot tell that a project exists.
 *
 * The person is the effective user: under act-as, the account acted as (`getEffectiveUser`), and the
 * acting admin's own oversight never applies. A project reached through that account's share is
 * `read`, never more (D-22): the caller that knows it is acting says so (`actingAs`, can() does).
 * `project.userId` is the owner: the tenant of every graph, traffic and credential read (T9).
 *
 * Nothing is cached here: a revoked or expired share ends with the next request (expiry is judged on
 * every read; step 4.15's sweep only deletes the rows). The owner's request costs one read by primary
 * key; anyone else's, with sharing in force, the policy (cached), the share by primary key (and the
 * owner's consent when a write share holds a run toggle), and unless the share gives Raw data the
 * break-glass rows and the person's capabilities (cached). A failed read throws, it never reads as
 * access.
 */
import prisma from '@/lib/prisma'
import { rbacFlags } from './flags'
import { now } from './clock'
import { loadPrincipal } from './principal'
import { resolveCapabilities, type Capabilities, type CapabilityPrincipal } from './capabilities'
import { maxShareLevel, sharingPolicyInForce, type SharingPolicy } from './sharingPolicy'
import { holdsSpendToggle, readOwnerConsent } from './ownerConsent'
import { meetsLevel } from './levelTable'

/** Whose data the request touches: the account acted as, else the signed-in account (EffectiveUser). */
export interface ProjectAccessSubject {
  userId: string
}

/**
 * `owner` reaches every level; `write` R, R* and W, and the levels of its toggles; `read` the read
 * levels (`R`, and `R*` with Raw data & files).
 */
export type ProjectAccessLevel = 'owner' | 'write' | 'read'

/** What gave the access. A route that used `oversight` writes its audit row (step 4.14). */
export type ProjectAccessVia = 'owner' | 'share' | 'break_glass' | 'oversight'

/** The toggles of Read + Write (§6.1, §6.2): `W+S`, `W+A`, `W+X` and `M` (co-owner). */
export interface WriteToggles {
  runScans: boolean
  useAgent: boolean
  exploit: boolean
  manage: boolean
}

/**
 * The write toggles are present on a `write` answer only: an owner or read answer carries Raw data
 * alone, exactly as in Phase 4 (DV-30). A missing toggle is off.
 */
export interface ProjectAccessToggles extends Partial<WriteToggles> {
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
  /**
   * The subject is the account an admin acts as (can()'s `actingAs`): a share reaches `read` and
   * never more, whatever its level (D-22, IM-07).
   */
  actingAs?: boolean
}

/** The share kinds that give access; a stored kind outside them (a later release's, a bad write) gives nothing. */
export const SHARE_ACCESS: ReadonlySet<string> = new Set(['read', 'write'])

function answer(project: { id: string; userId: string }, level: ProjectAccessLevel, toggles: ProjectAccessToggles, via: ProjectAccessVia): ProjectAccess {
  return Object.freeze({
    project: Object.freeze({ id: project.id, userId: project.userId }),
    level,
    toggles: Object.freeze(toggles),
    via,
  })
}

/**
 * The toggles a live `write` share gives now: each is the row's (anything but a stored `true` is
 * off), and Run scans, Use AI agent and Exploitation & shells count only while the owner consents to
 * collaborators spending the project's credentials (step 5.6, `ownerConsent.ts`); without it they
 * read false, so a collaborator never spends the owner's keys unasked. Manage needs no consent.
 */
export function effectiveToggles(row: Partial<Record<keyof WriteToggles, unknown>>, ownerConsent = false): WriteToggles {
  const spends = ownerConsent === true
  return {
    runScans: spends && row.runScans === true,
    useAgent: spends && row.useAgent === true,
    exploit: spends && row.exploit === true,
    manage: row.manage === true,
  }
}

/** Phase 4's share read; the toggle columns are read only when a share can be `write`. */
const SHARE_SELECT = { access: true, rawData: true, expiresAt: true, user: { select: { status: true } } } as const
const WRITE_SHARE_SELECT = { ...SHARE_SELECT, runScans: true, useAgent: true, exploit: true, manage: true } as const

interface ShareRow {
  access: string
  rawData: boolean
  expiresAt: Date | null
  user: { status: string } | null
  runScans?: boolean
  useAgent?: boolean
  exploit?: boolean
  manage?: boolean
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
  if (project.userId === subject.userId) return answer(project, 'owner', { rawData: true }, 'owner')
  const policy = await sharingLive(opts.fresh === true)
  if (!policy) return null
  const writeLevel = opts.actingAs !== true && maxShareLevel(policy) === 'write'
  return accessOfOthers(project, subject.userId, writeLevel, opts)
}

/** The policy while sharing is in force (the switch, then Root's policy, read only with the switch on), else null. */
async function sharingLive(fresh: boolean): Promise<Readonly<SharingPolicy> | null> {
  if (!rbacFlags().sharing) return null
  const policy = await sharingPolicyInForce({ fresh })
  return policy?.enabled === true ? policy : null
}

async function accessOfOthers(
  project: { id: string; userId: string },
  userId: string,
  writeLevel: boolean,
  opts: ProjectAccessOptions,
): Promise<ProjectAccess | null> {
  const at = now().getTime()
  const share: ShareRow | null = await prisma.projectCollaborator.findUnique({
    where: { projectId_userId: { projectId: project.id, userId } },
    select: writeLevel ? WRITE_SHARE_SELECT : SHARE_SELECT,
  })
  const shared = share !== null
    && SHARE_ACCESS.has(share.access)
    && (share.expiresAt === null || share.expiresAt.getTime() > at)
    && share.user?.status === 'active'
  // Write includes Raw data & files and is above every read answer: nothing more is needed.
  if (shared && writeLevel && share.access === 'write') {
    // The consent is read only for a row that holds a run toggle: without one there is nothing to open.
    const consent = holdsSpendToggle(share) && (await readOwnerConsent(project.id)) !== null
    return answer(project, 'write', { rawData: true, ...effectiveToggles(share, consent) }, 'share')
  }
  if (shared && share.rawData === true) return answer(project, 'read', { rawData: true }, 'share')

  const glass = await prisma.projectBreakGlass.findFirst({
    where: { projectId: project.id, userId, expiresAt: { gt: new Date(at) } },
    select: { expiresAt: true },
  })
  const glassLive = glass !== null && glass.expiresAt.getTime() > at
  if (shared && !glassLive) return answer(project, 'read', { rawData: false }, 'share')

  const capabilities = await capabilitiesOf(userId, opts)
  // Root's break-glass ends with Root's standing, not only at its expiry.
  if (glassLive && capabilities?.has('projects:administer')) return answer(project, 'read', { rawData: true }, 'break_glass')
  if (shared) return answer(project, 'read', { rawData: false }, 'share')
  if (capabilities?.has('projects:oversee')) return answer(project, 'read', { rawData: false }, 'oversight')
  return null
}

/** The subject's own capabilities (never an act-as intersection: the subject is one account). */
async function capabilitiesOf(userId: string, opts: ProjectAccessOptions): Promise<Capabilities | null> {
  const fresh = opts.fresh === true
  const principal = opts.principal && opts.principal.id === userId ? opts.principal : await loadPrincipal(userId, { fresh })
  return principal ? resolveCapabilities(principal, { fresh }) : null
}

// The table is in levelTable.ts, which reads no database, so the browser can judge settings changes too.
export { meetsLevel }

/** What a person is told of their own access to a project: the project GET's `myAccess` and /my-access. */
export interface MyAccess {
  level: ProjectAccessLevel
  toggles: ProjectAccessToggles
  via: ProjectAccessVia
  /** Who shared it, for "Read access, shared by <owner>" (and "Read + Write"). */
  owner: { name: string | null; email: string | null }
}

/** Each toggle as the level table answers it; the write toggles on a `write` access only (DV-30). */
function togglesOf(access: ProjectAccess): ProjectAccessToggles {
  const rawData = meetsLevel(access, 'R*')
  if (access.level !== 'write') return { rawData }
  return {
    rawData,
    runScans: meetsLevel(access, 'W+S'),
    useAgent: meetsLevel(access, 'W+A'),
    exploit: meetsLevel(access, 'W+X'),
    manage: meetsLevel(access, 'M'),
  }
}

export function myAccessView(access: ProjectAccess, owner: { name?: string | null; email?: string | null } | null | undefined): MyAccess {
  return {
    level: access.level,
    toggles: togglesOf(access),
    via: access.via,
    owner: { name: owner?.name ?? null, email: owner?.email ?? null },
  }
}
