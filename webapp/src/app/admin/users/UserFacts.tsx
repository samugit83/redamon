'use client'

import { ACCOUNT_TYPE_LABEL } from '@/components/auth/IdentityLabel'
import type { DirectoryRow, SetRef } from '@/lib/authz/userDirectory'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './users.module.css'

/** The words and cells the directory and the detail both show for an account (step 6.2). */

const TYPE_TONE: Record<DirectoryRow['accountType'], string> = {
  root: pageStyles.badgeRoot,
  admin: pageStyles.badgeAdmin,
  member: pageStyles.badgeStandard,
}

export function TypeBadge({ type }: { type: DirectoryRow['accountType'] }) {
  return <span className={`${pageStyles.badge} ${TYPE_TONE[type]}`}>{ACCOUNT_TYPE_LABEL[type]}</span>
}

export const STATUS_LABEL: Record<string, string> = { active: 'Active', invited: 'Invited', disabled: 'Disabled' }
const STATUS_TONE: Record<string, string> = {
  active: pageStyles.badgeYes,
  invited: pageStyles.badgeStandard,
  disabled: pageStyles.badgeWarn,
}

export function StatusCell({ status, mustChange }: { status: string; mustChange: boolean }) {
  return (
    <span className={pageStyles.cellStack}>
      <span className={`${pageStyles.badge} ${STATUS_TONE[status] ?? pageStyles.badgeStandard}`}>{STATUS_LABEL[status] ?? status}</span>
      {mustChange && <span className={`${pageStyles.badge} ${pageStyles.badgeWarn}`}>Must change password</span>}
    </span>
  )
}

/**
 * The last sign-in (ID-27). Sign-ins are recorded from the identity schema on (step 2.2), so an
 * account without one may have signed in before that: "Not recorded", never "Never".
 */
export function LastLogin({ at }: { at: string | null }) {
  const when = at ? new Date(at) : null
  if (!when || Number.isNaN(when.getTime())) {
    return <span className={pageStyles.badgeNo} title="No sign-in recorded since this version">Not recorded</span>
  }
  return (
    <time dateTime={when.toISOString()} title={when.toLocaleString()}>
      {when.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
    </time>
  )
}

function setName(s: SetRef): string {
  return s.name ?? 'Deleted set'
}

/** A member's sets, an admin's profile, or Root's every permission. */
export function SetsCell({ row }: { row: Pick<DirectoryRow, 'accountType' | 'sets' | 'profile'> }) {
  if (row.accountType === 'root') return <span className={styles.muted}>Every permission</span>
  if (row.profile) return <span title="Admin profile">{setName(row.profile)}</span>
  if (!row.sets || row.sets.length === 0) {
    return <span className={styles.muted} title="No set assigned: the account holds the default set for members">Default set</span>
  }
  return (
    <ul className={styles.setList} aria-label="Permission sets">
      {row.sets.map((s) => <li key={s.id} className={s.name ? undefined : styles.muted}>{setName(s)}</li>)}
    </ul>
  )
}
