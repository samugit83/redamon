import type { PermissionId } from '@/lib/authz/permissions'
import type { SetKind } from './setModel'

/** What the two pages call things, and where each kind's Phase 3 API lives (step 3.11). */
export interface SetWords {
  title: string
  one: string
  short: string
  listUrl: string
  itemUrl: (id: string) => string
  /** Who may write (the routes ask the same): roles:manage, or the confirmed Root's admin_profiles:manage. */
  writePermission: PermissionId
  newLabel: string
  builtinLabel: string
  customLabel: string
  lead: string
  pickHint: string
  emptyCustom: string
}

const item = (base: string) => (id: string) => `${base}/${encodeURIComponent(id)}`

export const SET_WORDS: Readonly<Record<SetKind, SetWords>> = Object.freeze({
  member: {
    title: 'Permission sets',
    one: 'permission set',
    short: 'set',
    listUrl: '/api/admin/permission-sets',
    itemUrl: item('/api/admin/permission-sets'),
    writePermission: 'roles:manage',
    newLabel: 'New set',
    builtinLabel: 'Built-in sets',
    customLabel: 'Custom sets',
    lead: 'A member holds every set assigned to them, together; a member with none holds the default set for new members. '
      + 'Built-in sets are read-only: clone one to change it. A set holds only permissions you hold yourself.',
    pickHint: 'Member permissions only. You can add only permissions you hold yourself; the others are listed disabled.',
    emptyCustom: 'No custom set yet. Clone a built-in set, or create one with New set.',
  },
  admin: {
    title: 'Admin profiles',
    one: 'admin profile',
    short: 'profile',
    listUrl: '/api/admin/admin-profiles',
    itemUrl: item('/api/admin/admin-profiles'),
    writePermission: 'admin_profiles:manage',
    newLabel: 'New profile',
    builtinLabel: 'Built-in profiles',
    customLabel: 'Custom profiles',
    lead: 'Each admin holds one profile; an admin with none recorded holds Full admin. Built-in profiles are read-only: '
      + 'clone one to change it. Every change is Root\'s and takes your password.',
    pickHint: 'Administration and platform permissions. Of Root\'s own, only admins:manage can go in a profile.',
    emptyCustom: 'No custom profile yet. Clone a built-in profile, or create one with New profile.',
  },
})
