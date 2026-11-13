import { PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'

/**
 * The admin console's sections (step 6.1, UI-10, OQ-44) and the permissions that open each. The
 * left navigation, the header's "Admin" link and each section's denied state read this list, so a
 * section is listed exactly where its page would let the person in. The screens only hide; every
 * route behind a section still asks its own permission.
 */

export type ConsoleSectionId =
  | 'users' | 'permission-sets' | 'admin-profiles' | 'projects' | 'shares' | 'operations' | 'audit' | 'instance'

export interface ConsoleSection {
  id: ConsoleSectionId
  label: string
  href: string
  description: string
  /** Any one of these opens the section. */
  anyOf: readonly PermissionId[]
  /**
   * Shares: also needs sharing in force and Root's sharing policy letting admins see every share
   * (`sharingPolicy.adminsSeeAllShares`); the console reads the policy once.
   */
  needsAllSharesView?: true
}

const PLATFORM: readonly PermissionId[] = PERMISSION_IDS.filter((p) => p.startsWith('platform:'))

// instance:settings is the confirmed Root's (rootOnly); instance:quotas is how a Full admin reaches
// the quotas section of the same page.
export const CONSOLE_SECTIONS: readonly ConsoleSection[] = Object.freeze([
  { id: 'users', label: 'Users', href: '/admin/users', anyOf: ['users:read'],
    description: 'Accounts, invitations, status, permission sets and sign-ins.' },
  { id: 'permission-sets', label: 'Permission sets', href: '/admin/permission-sets', anyOf: ['roles:manage'],
    description: 'The sets members hold, their holders and the default for new members.' },
  { id: 'admin-profiles', label: 'Admin profiles', href: '/admin/admin-profiles', anyOf: ['admin_profiles:manage'],
    description: 'What each kind of administrator may do. Root only.' },
  { id: 'projects', label: 'Projects', href: '/admin/projects', anyOf: ['projects:oversee'],
    description: 'Every project on the instance, with its owner and its shares.' },
  { id: 'shares', label: 'Shares', href: '/admin/shares', anyOf: ['users:read'], needsAllSharesView: true,
    description: 'Every share between accounts, with its level and expiry.' },
  { id: 'operations', label: 'Operations', href: '/admin/operations', anyOf: ['platform:operations'],
    description: 'Agent runs, scans and triage runs running or queued now.' },
  { id: 'audit', label: 'Audit', href: '/admin/audit', anyOf: ['audit:read'],
    description: 'Who did what and when, with filters, export and retention.' },
  { id: 'instance', label: 'Instance', href: '/admin/instance', anyOf: ['instance:settings', 'instance:quotas', ...PLATFORM],
    description: 'Instance-wide settings: security and sharing policy, quotas, tunnels, TrafficMind, Nuclei templates.' },
] satisfies ConsoleSection[])

export const CONSOLE_PERMISSIONS: readonly PermissionId[] = Object.freeze([...new Set(CONSOLE_SECTIONS.flatMap((s) => s.anyOf))])

export type Holds = (permission: PermissionId) => boolean

/** Whether the Shares section's second key is known: `pending` while the policy is read. */
export type AllSharesView = 'yes' | 'no' | 'pending'

export type SectionAccess =
  | { state: 'open' }
  | { state: 'pending' }
  /** None of the section's permissions is held: `missing` lists what would open it. */
  | { state: 'denied'; missing: readonly PermissionId[] }
  /** The permission is held, but sharing is not in force or the policy hides others' shares. */
  | { state: 'policy' }

export function holdsConsolePermission(holds: Holds): boolean {
  return CONSOLE_PERMISSIONS.some(holds)
}

export function sectionAccess(section: ConsoleSection, holds: Holds, allShares: AllSharesView): SectionAccess {
  if (!section.anyOf.some(holds)) return { state: 'denied', missing: section.anyOf }
  if (!section.needsAllSharesView || allShares === 'yes') return { state: 'open' }
  return allShares === 'pending' ? { state: 'pending' } : { state: 'policy' }
}

export function openSections(holds: Holds, allShares: AllSharesView): ConsoleSection[] {
  return CONSOLE_SECTIONS.filter((s) => sectionAccess(s, holds, allShares).state === 'open')
}

/** The section a console path belongs to; null for the overview and for a path no section owns. */
export function sectionForPath(pathname: string): ConsoleSection | null {
  return CONSOLE_SECTIONS.find((s) => pathname === s.href || pathname.startsWith(`${s.href}/`)) ?? null
}
