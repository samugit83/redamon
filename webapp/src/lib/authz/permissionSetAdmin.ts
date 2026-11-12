/**
 * Member permission sets (`roles:manage`) and admin profiles (`admin_profiles:manage`, Root's), and
 * the instance's default set for new members (`instance:settings`, Root's): step 3.11; PE-07,
 * PE-11, PE-17, ID-21. The routes check who may call; this module checks what may change.
 *
 *   - Built-in sets and profiles (`builtin:<slug>`) are code: they are cloned, never edited or
 *     deleted. A built-in member set may still become the instance default.
 *   - A member set holds known member permissions; a profile known admin permissions, of the
 *     Root-only ones only `admins:manage` (OQ-02: Root's opt-in). Names are unique ignoring case,
 *     built-ins included.
 *   - An edit adds only permissions the editor holds (PE-11: an admin cannot widen a set it belongs
 *     to), and adding a cross-tenant tool, an exploitation approval, sessions or Kali exec to a set
 *     takes the editor's password (ID-25). A new set holds nobody, so its creation asks for none:
 *     assigning it does (userPermissionAdmin.ts).
 *   - Deleting a set anyone holds, or the instance default, is refused (PE-17): holders of a deleted
 *     set would fall to *No access*, or the default to nothing.
 *   - An edit or a default change that removes a permission raises the session version of every
 *     holder in its transaction and closes their sockets after it (ID-21); the instance default's
 *     holders are the members never assigned a set.
 *
 * Each change commits with its audit row (`permission_set.*`, `admin_profile.*`,
 * `instance.default_member_set_changed`; fail closed) under the permissions lock, then drops the
 * cached sets (capabilities.ts `invalidatePermissionSets`).
 */
import { NextResponse, type NextRequest } from 'next/server'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import type { Session } from '@/lib/session'
import { BUILTIN_SETS, builtinSet } from './builtinSets'
import { invalidatePermissionSets } from './capabilities'
import { stepUpPermissionsIn, unheld, type Manager } from './hierarchy'
import {
  endSessionsOf, keptPermissions, lockPermissions, notHeldResponse, personAuditEntry, setOfKind,
  type SetKind, type Tx,
} from './permissionAdmin'
import { PERMISSIONS, PERMISSION_IDS, isPermissionId, type PermissionId } from './permissions'
import { INSTANCE_SETTINGS_ROW } from './root'
import { requireRootPower } from './rootPowers'
import { requireStepUp } from './stepUp'

const MAX_NAME = 80
const MAX_DESCRIPTION = 500
const ROOT_ONLY_DEFAULT = 'Only Root can choose the default set for new members.'

export interface SetView {
  id: string
  kind: SetKind
  name: string
  description: string | null
  permissions: PermissionId[]
  builtin: boolean
  clonedFrom: string | null
  createdById: string | null
  createdAt: string | null
  updatedAt: string | null
  /** Accounts assigned the set (member) or holding the profile (admin; *Full admin* also counts admins with none). */
  holders: number
  /** Member sets: the instance's default for members never assigned a set. */
  instanceDefault: boolean
}

const WORDS: Record<SetKind, { one: string; audit: string; target: string; permission: PermissionId }> = {
  member: { one: 'permission set', audit: 'permission_set', target: 'permission_set', permission: 'roles:manage' },
  admin: { one: 'admin profile', audit: 'admin_profile', target: 'admin_profile', permission: 'admin_profiles:manage' },
}

const bad = (code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status: 400 })
const conflict = (code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status: 409 })
const notFound = (kind: SetKind) =>
  NextResponse.json({ error: `No ${WORDS[kind].one} has this id.`, code: 'set_not_found' }, { status: 404 })
const builtinReadOnly = (kind: SetKind) =>
  conflict('builtin_read_only', `A built-in ${WORDS[kind].one} cannot be changed or deleted; clone it instead.`)
const nameTaken = () => conflict('name_taken', 'Another set or profile already has this name.')

const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null)

interface StoredRow {
  id: string
  kind: string
  name: string
  description: string | null
  permissions: string[]
  clonedFrom: string | null
  createdById: string
  createdAt: Date
  updatedAt: Date
}

const ROW_SELECT = {
  id: true, kind: true, name: true, description: true, permissions: true, clonedFrom: true,
  createdById: true, createdAt: true, updatedAt: true,
} as const

async function instanceDefaultId(db: Pick<Tx, 'instanceSettings'>): Promise<string | null> {
  const row = await db.instanceSettings.findUnique({ where: { id: INSTANCE_SETTINGS_ROW }, select: { defaultMemberSetId: true } })
  return row?.defaultMemberSetId ?? null
}

/** Every set or profile of `kind`, built-ins first, with its holders. */
export async function listSets(kind: SetKind): Promise<NextResponse> {
  const rows = (await prisma.permissionSet.findMany({ where: { kind }, select: ROW_SELECT }) as StoredRow[])
    .sort((a, b) => a.name.localeCompare(b.name))
  const holders = new Map<string, number>()
  if (kind === 'member') {
    for (const a of await prisma.userPermissionSet.findMany({ select: { setId: true } })) {
      holders.set(a.setId, (holders.get(a.setId) ?? 0) + 1)
    }
  } else {
    for (const u of await prisma.user.findMany({ where: { role: 'admin' }, select: { adminProfileId: true } })) {
      const id = u.adminProfileId ?? 'builtin:full-admin'
      holders.set(id, (holders.get(id) ?? 0) + 1)
    }
  }
  const instanceDefault = kind === 'member' ? await instanceDefaultId(prisma) : null
  const sets: SetView[] = [
    ...BUILTIN_SETS.filter((s) => s.kind === kind).map((s) => ({
      id: s.id, kind, name: s.name, description: s.description, permissions: [...s.permissions], builtin: true,
      clonedFrom: null, createdById: null, createdAt: null, updatedAt: null,
      holders: holders.get(s.id) ?? 0, instanceDefault: s.id === instanceDefault,
    })),
    ...rows.map((r) => view(r, kind, holders.get(r.id) ?? 0, r.id === instanceDefault)),
  ]
  return NextResponse.json({ kind, sets, ...(kind === 'member' ? { instanceDefaultSetId: instanceDefault } : {}) })
}

function view(r: StoredRow, kind: SetKind, holders: number, instanceDefault: boolean): SetView {
  return {
    id: r.id, kind, name: r.name, description: r.description ?? null, permissions: keptPermissions(r.permissions, kind),
    builtin: false, clonedFrom: r.clonedFrom ?? null, createdById: r.createdById, createdAt: iso(r.createdAt),
    updatedAt: iso(r.updatedAt), holders, instanceDefault,
  }
}

function parseName(value: unknown): string | NextResponse {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > MAX_NAME || /[\u0000-\u001f\u007f]/.test(value)) {
    return bad('invalid_name', `name is text of 1 to ${MAX_NAME} characters.`)
  }
  return value.trim()
}

function parseDescription(value: unknown): string | null | NextResponse {
  if (value === undefined || value === null) return null
  if (typeof value !== 'string' || value.length > MAX_DESCRIPTION) return bad('invalid_description', `description is text of at most ${MAX_DESCRIPTION} characters.`)
  return value.trim() || null
}

/** Known ids of the kind, each once, in registry order; or the 400 naming what is wrong. */
function parsePermissions(value: unknown, kind: SetKind): PermissionId[] | NextResponse {
  if (!Array.isArray(value) || value.length > PERMISSION_IDS.length * 2) return bad('invalid_permissions', 'permissions is a list of permission ids.')
  const unknown = value.filter((p) => !isPermissionId(p)).map((p) => String(p).slice(0, 80))
  if (unknown.length) return bad('unknown_permission', 'Some permissions do not exist.', { permissions: unknown })
  const ids = value as PermissionId[]
  const wrong = ids.filter((p) => PERMISSIONS[p].kind !== kind)
  if (wrong.length) {
    return bad('wrong_kind', kind === 'member'
      ? 'A member permission set holds member permissions only; administration and platform rights belong to admin profiles.'
      : 'An admin profile holds administration and platform permissions only; member rights come from the admin\'s member sets.',
    { permissions: wrong })
  }
  const rootOnly = ids.filter((p) => PERMISSIONS[p].rootOnly && p !== 'admins:manage')
  if (rootOnly.length) return bad('root_only_permission', 'These permissions stay Root\'s and go in no profile.', { permissions: rootOnly })
  if (new Set(ids).size !== ids.length) return bad('invalid_permissions', 'A permission is listed twice.')
  const wanted = new Set(ids)
  return PERMISSION_IDS.filter((p) => wanted.has(p))
}

/** Is `name` free, ignoring case, among the built-ins and every stored set but `exceptId`? */
async function nameFree(tx: Tx, name: string, exceptId?: string): Promise<boolean> {
  const key = name.toLowerCase()
  if (BUILTIN_SETS.some((s) => s.name.toLowerCase() === key)) return false
  const rows = await tx.permissionSet.findMany({ select: { id: true, name: true } })
  return !rows.some((r) => r.id !== exceptId && r.name.toLowerCase() === key)
}

/** The accounts holding the set or profile now: they lose what an edit removes. */
async function holdersOf(tx: Tx, kind: SetKind, id: string, isDefault: boolean): Promise<string[]> {
  if (kind === 'admin') {
    return (await tx.user.findMany({ where: { role: 'admin', adminProfileId: id }, select: { id: true } })).map((u) => u.id)
  }
  const assigned = (await tx.userPermissionSet.findMany({ where: { setId: id }, select: { userId: true } })).map((a) => a.userId)
  return isDefault ? [...new Set([...assigned, ...(await neverAssignedMembers(tx))])] : assigned
}

/** Members never assigned a set: the instance default's holders. */
async function neverAssignedMembers(tx: Tx): Promise<string[]> {
  const assigned = new Set((await tx.userPermissionSet.findMany({ select: { userId: true } })).map((a) => a.userId))
  const members = await tx.user.findMany({ where: { role: { not: 'admin' } }, select: { id: true } })
  return members.map((m) => m.id).filter((id) => !assigned.has(id))
}

async function holderCount(kind: SetKind, id: string): Promise<number> {
  return kind === 'member'
    ? prisma.userPermissionSet.count({ where: { setId: id } })
    : prisma.user.count({ where: { role: 'admin', adminProfileId: id } })
}

async function signOut(tx: Tx, ids: readonly string[]): Promise<void> {
  if (ids.length) await tx.user.updateMany({ where: { id: { in: [...ids] } }, data: { sessionVersion: { increment: 1 } } })
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002'
}

/** POST: a new set or profile, or a copy (`cloneFrom`) of one of its kind. */
export async function createSet(
  request: NextRequest, session: Session, manager: Manager, kind: SetKind, body: Record<string, unknown>,
): Promise<NextResponse> {
  const name = parseName(body.name)
  if (name instanceof NextResponse) return name
  const description = parseDescription(body.description)
  if (description instanceof NextResponse) return description
  let clonedFrom: string | null = null
  let permissions: PermissionId[] | NextResponse | null = null
  if (body.cloneFrom !== undefined) {
    const source = typeof body.cloneFrom === 'string' ? await setOfKind(prisma, body.cloneFrom, kind) : null
    if (!source) return bad('unknown_set', `cloneFrom names no ${WORDS[kind].one}.`)
    clonedFrom = source.id
    permissions = source.permissions
  }
  if (body.permissions !== undefined) permissions = parsePermissions(body.permissions, kind)
  if (permissions instanceof NextResponse) return permissions
  if (permissions === null) return bad('invalid_permissions', 'Send permissions, or cloneFrom to copy a set.')
  const missing = unheld(manager, permissions)
  if (missing.length) return notHeldResponse(missing)

  const words = WORDS[kind]
  try {
    const created = await prisma.$transaction(async (tx) => {
      await lockPermissions(tx)
      if (!(await nameFree(tx, name))) return null
      const row = await tx.permissionSet.create({
        data: { kind, name, description, permissions: permissions as PermissionId[], clonedFrom, createdById: session.userId },
        select: ROW_SELECT,
      }) as StoredRow
      await writeAuditTx(tx, await personAuditEntry(request, session, {
        action: `${words.audit}.created`, targetType: words.target, targetId: row.id, permission: words.permission,
        after: { name, kind, description, permissions: row.permissions, clonedFrom },
      }))
      return row
    })
    if (!created) return nameTaken()
    invalidatePermissionSets()
    return NextResponse.json({ set: view(created, kind, 0, false) }, { status: 201 })
  } catch (err) {
    if (isUniqueViolation(err)) return nameTaken()
    throw err
  }
}

const EDITABLE = ['name', 'description', 'permissions'] as const

/**
 * PUT: rename, describe or change the permissions of a stored set or profile, and (member sets,
 * Root) make it the instance default (`instanceDefault: true`) or stop it being one (`false`).
 */
export async function updateSet(
  request: NextRequest, session: Session, manager: Manager, kind: SetKind, id: string, body: Record<string, unknown>,
): Promise<NextResponse> {
  const edits = EDITABLE.filter((k) => k in body)
  const defaultKey = kind === 'member' && 'instanceDefault' in body
  if (!edits.length && !defaultKey) return bad('nothing_to_change', `Send ${EDITABLE.join(', ')}${kind === 'member' ? ' or instanceDefault' : ''}.`)
  if (defaultKey && typeof body.instanceDefault !== 'boolean') return bad('invalid_instance_default', 'instanceDefault is true or false.')
  const builtin = builtinSet(id)
  if (builtin && builtin.kind !== kind) return notFound(kind)
  if (edits.length && (builtin || id.startsWith('builtin:'))) return builtinReadOnly(kind)

  const existing = builtin ? null : await prisma.permissionSet.findUnique({ where: { id }, select: ROW_SELECT }) as StoredRow | null
  if (!builtin && (!existing || existing.kind !== kind)) return notFound(kind)

  const name = 'name' in body ? parseName(body.name) : existing?.name ?? null
  if (name instanceof NextResponse) return name
  const description = 'description' in body ? parseDescription(body.description) : existing?.description ?? null
  if (description instanceof NextResponse) return description
  const before = existing ? keptPermissions(existing.permissions, kind) : [...builtin!.permissions]
  const permissions = 'permissions' in body ? parsePermissions(body.permissions, kind) : before
  if (permissions instanceof NextResponse) return permissions
  const added = permissions.filter((p) => !before.includes(p))
  const removed = before.filter((p) => !permissions.includes(p))

  const missing = unheld(manager, added)
  if (missing.length) return notHeldResponse(missing)
  if (defaultKey) {
    const refusal = await requireRootPower(request, session, body.stepUpPassword, ROOT_ONLY_DEFAULT)
    if (refusal) return refusal
  } else if (kind === 'member' && stepUpPermissionsIn(added).length) {
    const refusal = await requireStepUp(request, body.stepUpPassword)
    if (refusal) return refusal
  }

  const words = WORDS[kind]
  type Outcome =
    | { kind: 'missing' | 'changed' | 'name_taken' | 'no_instance_row' }
    | { kind: 'written'; row: StoredRow | null; signedOut: string[]; instanceDefault: boolean; changed: boolean }
  let outcome: Outcome
  try {
    outcome = await prisma.$transaction(async (tx): Promise<Outcome> => {
      await lockPermissions(tx)
      let row: StoredRow | null = null
      if (existing) {
        row = await tx.permissionSet.findUnique({ where: { id }, select: ROW_SELECT }) as StoredRow | null
        if (!row || row.kind !== kind) return { kind: 'missing' }
        if (row.updatedAt.getTime() !== existing.updatedAt.getTime()) return { kind: 'changed' }
      }
      const currentDefault = kind === 'member' ? await instanceDefaultId(tx) : null
      const wasDefault = currentDefault === id
      const signedOut = new Set<string>()
      let changed = false

      if (existing && edits.length) {
        const renamed = name !== existing.name
        if (renamed && !(await nameFree(tx, name!, id))) return { kind: 'name_taken' }
        const sameDescription = description === (existing.description ?? null)
        if (renamed || !sameDescription || added.length || removed.length) {
          changed = true
          row = await tx.permissionSet.update({
            where: { id },
            data: { name: name!, description, permissions },
            select: ROW_SELECT,
          }) as StoredRow
          if (removed.length) for (const u of await holdersOf(tx, kind, id, wasDefault)) signedOut.add(u)
          await writeAuditTx(tx, await personAuditEntry(request, session, {
            action: `${words.audit}.updated`, targetType: words.target, targetId: id, permission: words.permission,
            before: { name: existing.name, description: existing.description ?? null, permissions: before },
            after: { name, description, permissions, added, removed, holdersSignedOut: signedOut.size },
          }))
        }
      }

      let isDefault = wasDefault
      if (defaultKey && (body.instanceDefault as boolean) !== wasDefault) {
        const settings = await tx.instanceSettings.findUnique({ where: { id: INSTANCE_SETTINGS_ROW }, select: { id: true } })
        if (!settings) return { kind: 'no_instance_row' }
        const next = body.instanceDefault ? id : null
        const fromSet = await setOfKind(tx, currentDefault ?? 'builtin:default-member', 'member')
        const toSet = await setOfKind(tx, next ?? 'builtin:default-member', 'member')
        const lost = (fromSet?.permissions ?? []).filter((p) => !(toSet?.permissions ?? []).includes(p))
        const holders = lost.length ? await neverAssignedMembers(tx) : []
        for (const u of holders) signedOut.add(u)
        await tx.instanceSettings.update({ where: { id: INSTANCE_SETTINGS_ROW }, data: { defaultMemberSetId: next } })
        await writeAuditTx(tx, await personAuditEntry(request, session, {
          action: 'instance.default_member_set_changed', targetType: 'instance', targetId: INSTANCE_SETTINGS_ROW,
          permission: 'instance:settings',
          before: { defaultMemberSetId: currentDefault },
          after: { defaultMemberSetId: next, removed: lost, holdersSignedOut: holders.length },
        }))
        isDefault = next === id
        changed = true
      }
      await signOut(tx, [...signedOut])
      return { kind: 'written', row, signedOut: [...signedOut], instanceDefault: isDefault, changed }
    })
  } catch (err) {
    if (isUniqueViolation(err)) return nameTaken()
    throw err
  }
  switch (outcome.kind) {
    case 'missing': return notFound(kind)
    case 'name_taken': return nameTaken()
    case 'changed': return conflict('set_changed', `The ${WORDS[kind].one} changed while this request ran. Reload it and try again.`)
    case 'no_instance_row': return conflict('instance_settings_missing', 'The instance settings row does not exist yet; restart the webapp to create it.')
  }
  if (outcome.changed) invalidatePermissionSets()
  const agent = outcome.signedOut.length ? await endSessionsOf(outcome.signedOut) : undefined
  const holders = await holderCount(kind, id)
  const setView: SetView = outcome.row
    ? view(outcome.row, kind, holders, outcome.instanceDefault)
    : {
        id, kind, name: builtin!.name, description: builtin!.description, permissions: [...builtin!.permissions], builtin: true,
        clonedFrom: null, createdById: null, createdAt: null, updatedAt: null, holders, instanceDefault: outcome.instanceDefault,
      }
  return NextResponse.json({
    set: setView, changed: outcome.changed, added, removed,
    signedOut: outcome.signedOut.length, ...(agent ? { agent } : {}),
  })
}

/** DELETE: a stored set or profile nobody holds and that is not the instance default. */
export async function deleteSet(request: NextRequest, session: Session, kind: SetKind, id: string): Promise<NextResponse> {
  const builtin = builtinSet(id)
  if (builtin && builtin.kind === kind) return builtinReadOnly(kind)
  if (id.startsWith('builtin:')) return notFound(kind)
  const words = WORDS[kind]
  type Outcome = { kind: 'missing' | 'default' } | { kind: 'in_use'; holders: number } | { kind: 'deleted' }
  const outcome = await prisma.$transaction(async (tx): Promise<Outcome> => {
    await lockPermissions(tx)
    const row = await tx.permissionSet.findUnique({ where: { id }, select: ROW_SELECT }) as StoredRow | null
    if (!row || row.kind !== kind) return { kind: 'missing' }
    const holders = kind === 'member'
      ? await tx.userPermissionSet.count({ where: { setId: id } })
      : await tx.user.count({ where: { adminProfileId: id } })
    if (holders > 0) return { kind: 'in_use', holders }
    if (kind === 'member' && (await instanceDefaultId(tx)) === id) return { kind: 'default' }
    await tx.permissionSet.delete({ where: { id } })
    await writeAuditTx(tx, await personAuditEntry(request, session, {
      action: `${words.audit}.deleted`, targetType: words.target, targetId: id, permission: words.permission,
      before: { name: row.name, description: row.description ?? null, permissions: keptPermissions(row.permissions, kind), clonedFrom: row.clonedFrom ?? null },
    }))
    return { kind: 'deleted' }
  })
  switch (outcome.kind) {
    case 'missing': return notFound(kind)
    case 'in_use':
      return conflict(kind === 'member' ? 'set_in_use' : 'profile_in_use',
        `${outcome.holders} account(s) hold this ${words.one}: give them another first.`, { holders: outcome.holders })
    case 'default':
      return conflict('set_is_default', 'This set is the default for new members: choose another default first.')
  }
  invalidatePermissionSets()
  return NextResponse.json({ id, deleted: true })
}
