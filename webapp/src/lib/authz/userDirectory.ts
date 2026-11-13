/**
 * The admin users directory and one account's detail (step 6.2; GV-01, ID-27): who is on the
 * instance, with their type, status, permission sets or admin profile, last sign-in and project
 * counts, searched, filtered and paged; and, for each account, the actions the signed-in person may
 * take on it, decided by hierarchy.ts `canManage`, so a row offers what the user routes allow. It
 * only reads: every action goes to its own route, which decides again.
 *
 * Only what the directory lists is read (master plan §9.8): no password hash, no notice, no
 * session version. The real person decides (§4.7), never an account they act as.
 *
 * The `set` filter lists the holders of one set or profile, counted as `listSets` counts them
 * (permissionSetAdmin.ts), so a page showing that count can list the same accounts: a member set
 * by its assignment rows (any account type), an admin profile by the admins' `adminProfileId`, where
 * an admin with none recorded holds Full admin. An account that holds a set only as the default
 * (no assignment) is not listed. The permission sets page (step 6.3) lists a set's holders this way.
 *
 * Shared-project counts and lists read collaborator rows only with sharing in force (the switch and
 * Root's policy); a user's shares are listed only when the policy also lets administrators see every
 * share (`adminsSeeAllShares`), as the Shares section is.
 */
import type { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { projectTargetLabel } from '@/lib/projectSummary'
import type { Session } from '@/lib/session'
import { sessionHolds } from './adminPermission'
import { recentAuditAbout, type AuditRowView } from './auditReader'
import { BUILTIN_SETS, builtinSet, FULL_ADMIN_PROFILE_ID } from './builtinSets'
import { now } from './clock'
import { canManage, MANAGE_ACTIONS, type ManageAction, type Managed, type Manager } from './hierarchy'
import { keptPermissions, managerOf, type SetKind } from './permissionAdmin'
import type { PermissionId } from './permissions'
import { accountTypeOf, loadInstanceRoot, type AccountType, type InstanceRoot } from './root'
import { sharingPolicyInForce } from './sharingPolicy'

export const DIRECTORY_STATUSES = ['active', 'invited', 'disabled'] as const
export type DirectoryStatus = (typeof DIRECTORY_STATUSES)[number]
export const DIRECTORY_TYPES = ['root', 'admin', 'member'] as const satisfies readonly AccountType[]

export const DEFAULT_PAGE_SIZE = 50
export const MAX_PAGE_SIZE = 100
const MAX_QUERY_LENGTH = 200
const MAX_SET_ID_LENGTH = 200
export const RECENT_AUDIT_ROWS = 20

export interface DirectoryFilters {
  q: string | null
  status: DirectoryStatus | null
  type: AccountType | null
  set: string | null
  cursor: DirectoryCursor | null
  limit: number
}

/** Where the previous page ended: the last row's creation time and id (rows run newest first). */
export interface DirectoryCursor {
  createdAt: Date
  id: string
}

export interface FilterProblem {
  error: string
  code: 'invalid_filter'
  field: string
}

const problem = (field: string, error: string): FilterProblem => ({ error, code: 'invalid_filter', field })

export function encodeCursor(c: DirectoryCursor): string {
  return Buffer.from(`${c.createdAt.toISOString()}|${c.id}`, 'utf8').toString('base64url')
}

export function decodeCursor(raw: string): DirectoryCursor | null {
  const text = Buffer.from(raw, 'base64url').toString('utf8')
  const bar = text.indexOf('|')
  if (bar <= 0 || bar === text.length - 1) return null
  const createdAt = new Date(text.slice(0, bar))
  if (Number.isNaN(createdAt.getTime())) return null
  return { createdAt, id: text.slice(bar + 1) }
}

/** The directory's query string, or the first field that is not one it takes. */
export function parseDirectoryQuery(params: URLSearchParams): DirectoryFilters | FilterProblem {
  const text = (name: string) => {
    const v = params.get(name)?.trim()
    return v ? v : null
  }
  const q = text('q')
  if (q && q.length > MAX_QUERY_LENGTH) return problem('q', `q is longer than ${MAX_QUERY_LENGTH} characters`)
  const status = text('status')
  if (status && !(DIRECTORY_STATUSES as readonly string[]).includes(status)) {
    return problem('status', `status is one of ${DIRECTORY_STATUSES.join(', ')}`)
  }
  const type = text('type')
  if (type && !(DIRECTORY_TYPES as readonly string[]).includes(type)) {
    return problem('type', `type is one of ${DIRECTORY_TYPES.join(', ')}`)
  }
  const set = text('set')
  if (set && set.length > MAX_SET_ID_LENGTH) return problem('set', 'set is not a set id')
  const rawCursor = text('cursor')
  const cursor = rawCursor ? decodeCursor(rawCursor) : null
  if (rawCursor && !cursor) return problem('cursor', 'cursor is not one this directory gave')
  const rawLimit = text('limit')
  const limit = rawLimit === null ? DEFAULT_PAGE_SIZE : Number(rawLimit)
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
    return problem('limit', `limit is a whole number from 1 to ${MAX_PAGE_SIZE}`)
  }
  return {
    q, status: status as DirectoryStatus | null, type: type as AccountType | null, set, cursor, limit,
  }
}

export interface WhereContext {
  /** The instance Root's id, or null when there is none. */
  rootId: string | null
  /** What the `set` filter names: a member set or an admin profile. */
  setKind: SetKind
}

/** The accounts the filters select (the cursor is applied apart, so the total ignores it). */
export function directoryWhere(f: DirectoryFilters, ctx: WhereContext): Prisma.UserWhereInput {
  const and: Prisma.UserWhereInput[] = []
  if (f.q) {
    and.push({ OR: [{ name: { contains: f.q, mode: 'insensitive' } }, { email: { contains: f.q, mode: 'insensitive' } }] })
  }
  if (f.status) and.push({ status: f.status })
  if (f.type === 'root') and.push({ id: { in: ctx.rootId ? [ctx.rootId] : [] } })
  if (f.type === 'admin') and.push(ctx.rootId ? { role: 'admin', id: { not: ctx.rootId } } : { role: 'admin' })
  if (f.type === 'member') and.push({ role: { not: 'admin' } })
  if (f.set) {
    if (ctx.setKind === 'member') and.push({ permissionSets: { some: { setId: f.set } } })
    else if (f.set === FULL_ADMIN_PROFILE_ID) and.push({ role: 'admin', OR: [{ adminProfileId: f.set }, { adminProfileId: null }] })
    else and.push({ role: 'admin', adminProfileId: f.set })
  }
  return and.length > 0 ? { AND: and } : {}
}

function afterCursor(c: DirectoryCursor): Prisma.UserWhereInput {
  return { OR: [{ createdAt: { lt: c.createdAt } }, { createdAt: c.createdAt, id: { lt: c.id } }] }
}

/**
 * Which actions a row offers: those `canManage` allows the person on this account, and only in a
 * status where the action exists (an invite is resent or cancelled while invited, an account is
 * disabled while active and enabled while disabled, a reset needs an account that signed up, nobody
 * acts as an account that cannot sign in). Nothing on the person's own account, nor on Root.
 */
const IN_STATUS: Readonly<Record<ManageAction, (status: string) => boolean>> = {
  create: (s) => s === 'invited',
  edit: () => true,
  assign_permissions: () => true,
  disable: (s) => s === 'active',
  enable: (s) => s === 'disabled',
  reset_credentials: (s) => s === 'active' || s === 'disabled',
  revoke_sessions: (s) => s === 'active',
  impersonate: (s) => s === 'active',
  delete: () => true,
}

export function rowActions(manager: Manager, target: Managed, status: string): ManageAction[] {
  return MANAGE_ACTIONS.filter((a) => IN_STATUS[a](status) && canManage(manager, target, a).allowed)
}

export interface SetRef {
  id: string
  /** Null when the set no longer exists (the account then resolves to No access for it). */
  name: string | null
}

export interface DirectoryRow {
  id: string
  name: string
  email: string
  accountType: AccountType
  status: string
  mustChangePassword: boolean
  /** The last sign-in (ISO); null when none is recorded. */
  lastLoginAt: string | null
  createdAt: string
  /** A member's assigned sets ([] = the default set); null for admins and Root. */
  sets: SetRef[] | null
  /** An admin's profile (none recorded = Full admin); null for members and Root. */
  profile: SetRef | null
  /** Shared: live shares with this account; null while sharing is not in force. */
  projects: { owned: number; shared: number | null }
  /** The signed-in person's own account. */
  self: boolean
  actions: ManageAction[]
}

export interface SetOption {
  id: string
  name: string
  kind: SetKind
}

export interface DirectoryPage {
  users: DirectoryRow[]
  nextCursor: string | null
  total: number
  /** Every set and profile, for the set filter. */
  setOptions: SetOption[]
  /** Whether shared-project counts are read (sharing in force). */
  sharing: boolean
}

const liveShare = (): Prisma.ProjectCollaboratorWhereInput => ({ OR: [{ expiresAt: null }, { expiresAt: { gt: now() } }] })

function rowSelect(sharing: boolean) {
  return {
    id: true, name: true, email: true, role: true, status: true, mustChangePassword: true, lastLoginAt: true,
    createdAt: true, adminProfileId: true,
    permissionSets: { select: { setId: true } },
    _count: { select: { projects: true, ...(sharing ? { collaborations: { where: liveShare() } } : {}) } },
  } satisfies Prisma.UserSelect
}

interface AccountRow {
  id: string
  name: string
  email: string
  role: string
  status: string
  mustChangePassword: boolean
  lastLoginAt: Date | null
  createdAt: Date
  adminProfileId: string | null
  permissionSets: { setId: string }[]
  _count: { projects: number; collaborations?: number }
}

interface StoredSet {
  name: string
  kind: string
  permissions: string[]
}

/** The custom sets and profiles the rows name, by id (built-ins need no read). */
async function storedSetsFor(ids: Iterable<string>): Promise<Map<string, StoredSet>> {
  const custom = [...new Set(ids)].filter((id) => !id.startsWith('builtin:'))
  if (custom.length === 0) return new Map()
  const rows = await prisma.permissionSet.findMany({
    where: { id: { in: custom } },
    select: { id: true, name: true, kind: true, permissions: true },
  })
  return new Map(rows.map((r) => [r.id, { name: r.name, kind: r.kind, permissions: r.permissions }]))
}

function setRef(id: string, kind: SetKind, stored: Map<string, StoredSet>): SetRef {
  const builtin = builtinSet(id)
  if (builtin) return { id, name: builtin.kind === kind ? builtin.name : null }
  const row = stored.get(id)
  return { id, name: row && row.kind === kind ? row.name : null }
}

/** An admin profile's permissions as capabilities.ts reads them; a profile that is gone gives none. */
function profilePermissions(id: string, stored: Map<string, StoredSet>): PermissionId[] {
  const builtin = builtinSet(id)
  if (builtin) return builtin.kind === 'admin' ? [...builtin.permissions] : []
  const row = stored.get(id)
  return row && row.kind === 'admin' ? keptPermissions(row.permissions, 'admin') : []
}

function toRow(a: AccountRow, ctx: { root: InstanceRoot | null; manager: Manager; stored: Map<string, StoredSet>; sharing: boolean }): DirectoryRow {
  const accountType = accountTypeOf(a, ctx.root)
  const profileId = accountType === 'admin' ? a.adminProfileId ?? FULL_ADMIN_PROFILE_ID : null
  const managed: Managed = { id: a.id, accountType, profile: profileId ? profilePermissions(profileId, ctx.stored) : [] }
  const status = a.status || 'active'
  return {
    id: a.id,
    name: a.name,
    email: a.email,
    accountType,
    status,
    mustChangePassword: a.mustChangePassword === true,
    lastLoginAt: a.lastLoginAt ? a.lastLoginAt.toISOString() : null,
    createdAt: a.createdAt.toISOString(),
    sets: accountType === 'member' ? a.permissionSets.map((s) => setRef(s.setId, 'member', ctx.stored)) : null,
    profile: profileId ? setRef(profileId, 'admin', ctx.stored) : null,
    projects: { owned: a._count.projects, shared: ctx.sharing ? a._count.collaborations ?? 0 : null },
    self: a.id === ctx.manager.id,
    actions: rowActions(ctx.manager, managed, status),
  }
}

function setIdsOf(rows: readonly AccountRow[], root: InstanceRoot | null): string[] {
  return rows.flatMap((a) => {
    const type = accountTypeOf(a, root)
    if (type === 'admin') return [a.adminProfileId ?? FULL_ADMIN_PROFILE_ID]
    return type === 'member' ? a.permissionSets.map((s) => s.setId) : []
  })
}

/** What the `set` filter names: a built-in's kind, a stored set's kind, else a member set (no holder). */
async function setKindOf(id: string | null): Promise<SetKind> {
  if (!id) return 'member'
  const builtin = builtinSet(id)
  if (builtin) return builtin.kind
  if (id.startsWith('builtin:')) return 'member'
  const row = await prisma.permissionSet.findUnique({ where: { id }, select: { kind: true } })
  return row?.kind === 'admin' ? 'admin' : 'member'
}

async function setOptions(): Promise<SetOption[]> {
  const rows = await prisma.permissionSet.findMany({ select: { id: true, name: true, kind: true } })
  const custom = rows
    .filter((r): r is typeof r & { kind: SetKind } => r.kind === 'member' || r.kind === 'admin')
    .sort((a, b) => a.name.localeCompare(b.name))
  return [
    ...BUILTIN_SETS.map((s) => ({ id: s.id, name: s.name, kind: s.kind })),
    ...custom.map((r) => ({ id: r.id, name: r.name, kind: r.kind })),
  ]
}

/** Whether sharing is in force, and whether Root's policy lets administrators see every share. */
async function sharingView(): Promise<{ inForce: boolean; allShares: boolean }> {
  const policy = await sharingPolicyInForce()
  const inForce = policy?.enabled === true
  return { inForce, allShares: inForce && policy?.adminsSeeAllShares === true }
}

/** One page of the directory for the signed-in person (who holds users:read: the route asked). */
export async function readDirectoryPage(session: Session, f: DirectoryFilters): Promise<DirectoryPage> {
  const [{ manager }, root, setKind, sharing] = await Promise.all([
    managerOf(session), loadInstanceRoot(), setKindOf(f.set), sharingView(),
  ])
  const where = directoryWhere(f, { rootId: root?.userId ?? null, setKind })
  const [found, total, options] = await Promise.all([
    prisma.user.findMany({
      where: f.cursor ? { AND: [where, afterCursor(f.cursor)] } : where,
      select: rowSelect(sharing.inForce),
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: f.limit + 1,
    }) as Promise<AccountRow[]>,
    prisma.user.count({ where }),
    setOptions(),
  ])
  const page = found.slice(0, f.limit)
  const stored = await storedSetsFor(setIdsOf(page, root))
  const last = page[page.length - 1]
  return {
    users: page.map((a) => toRow(a, { root, manager, stored, sharing: sharing.inForce })),
    nextCursor: found.length > f.limit && last ? encodeCursor({ createdAt: last.createdAt, id: last.id }) : null,
    total,
    setOptions: options,
    sharing: sharing.inForce,
  }
}

export interface OwnedProject {
  id: string
  name: string
  createdAt: string
  updatedAt: string
  /** The project's scope, only to a reader who also holds projects:oversee (as GET /api/users/[id]). */
  targetLabel?: string
}

export interface SharedProject {
  id: string
  name: string
  owner: { id: string; name: string; email: string }
  access: string
  expiresAt: string | null
  sharedAt: string
}

export type SharedProjects =
  | { state: 'listed'; projects: SharedProject[] }
  /** Sharing is not in force: nobody shares a project. */
  | { state: 'off' }
  /** Root's policy does not let administrators see others' shares. */
  | { state: 'hidden' }

export type DetailAudit = { rows: AuditRowView[] } | { denied: 'audit:read' }

export interface UserDetail {
  user: DirectoryRow
  owned: OwnedProject[]
  shared: SharedProjects
  /** The latest audit rows where the account is the actor or the target; audit:read's to read. */
  audit: DetailAudit
}

const SCOPE_FIELDS = {
  targetDomain: true, ipMode: true, targetIps: true, subdomainList: true, domainBatchMode: true, domainBatchHosts: true,
} as const

/** One account's detail for the signed-in person (who holds users:read), or null when there is none. */
export async function readUserDetail(session: Session, id: string): Promise<UserDetail | null> {
  const [{ manager }, root, sharing, oversee, auditRead] = await Promise.all([
    managerOf(session), loadInstanceRoot(), sharingView(),
    sessionHolds(session, 'projects:oversee'), sessionHolds(session, 'audit:read'),
  ])
  const account = await prisma.user.findUnique({
    where: { id },
    select: {
      ...rowSelect(sharing.inForce),
      projects: {
        orderBy: { createdAt: 'desc' },
        select: { id: true, name: true, createdAt: true, updatedAt: true, ...(oversee ? SCOPE_FIELDS : {}) },
      },
    },
  }) as (AccountRow & { projects: Array<{ id: string; name: string; createdAt: Date; updatedAt: Date } & Record<string, unknown>> }) | null
  if (!account) return null
  const stored = await storedSetsFor(setIdsOf([account], root))

  const owned: OwnedProject[] = account.projects.map((p) => ({
    id: p.id,
    name: p.name,
    createdAt: p.createdAt.toISOString(),
    updatedAt: p.updatedAt.toISOString(),
    ...(oversee ? { targetLabel: projectTargetLabel(p as Parameters<typeof projectTargetLabel>[0]) } : {}),
  }))

  let shared: SharedProjects = { state: 'off' }
  if (sharing.allShares) {
    const rows = await prisma.projectCollaborator.findMany({
      where: { userId: id, ...liveShare() },
      orderBy: { createdAt: 'desc' },
      select: {
        access: true, expiresAt: true, createdAt: true,
        project: { select: { id: true, name: true, user: { select: { id: true, name: true, email: true } } } },
      },
    })
    shared = {
      state: 'listed',
      projects: rows.map((r) => ({
        id: r.project.id,
        name: r.project.name,
        owner: r.project.user,
        access: r.access,
        expiresAt: r.expiresAt ? r.expiresAt.toISOString() : null,
        sharedAt: r.createdAt.toISOString(),
      })),
    }
  } else if (sharing.inForce) {
    shared = { state: 'hidden' }
  }

  return {
    user: toRow(account, { root, manager, stored, sharing: sharing.inForce }),
    owned,
    shared,
    audit: auditRead ? { rows: await recentAuditAbout(id, RECENT_AUDIT_ROWS) } : { denied: 'audit:read' },
  }
}
