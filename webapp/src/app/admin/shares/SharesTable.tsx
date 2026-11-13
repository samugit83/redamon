'use client'

import Link from 'next/link'
import type { AdminShareRow } from '@/lib/authz/adminShares'
import { ForcedAction } from '../projects/ForcedAction'
import { shareLevelLabel, whenLabel } from './shareWords'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from '../projects/overview.module.css'

interface SharesTableProps {
  shares: AdminShareRow[]
  /** The confirmed Root's force-revoke (the server says whether it is offered). */
  canRevoke: boolean
  /** Links to the account pages (the Users section is open to the viewer). */
  linkUsers: boolean
  /** Hidden inside one project's row, where the project is already named. */
  showProject?: boolean
  caption: string
  onRevoked: (share: AdminShareRow, socketsClosed: boolean) => void
}

function Person({ person, link }: { person: { id: string; name: string; email: string }; link: boolean }) {
  return (
    <span className={pageStyles.cellStack}>
      {link ? <Link href={`/admin/users/${encodeURIComponent(person.id)}`} className={styles.nameLink}>{person.name}</Link> : <span>{person.name}</span>}
      <span className={pageStyles.email}>{person.email}</span>
    </span>
  )
}

/**
 * The shares as a table (step 6.4; GV-05): project, owner, the person it is shared with, level and
 * toggles, expiry, when it was granted, and Root's Revoke. Used by the Shares page and by a project's
 * row on the Projects page.
 */
export function SharesTable({ shares, canRevoke, linkUsers, showProject = true, caption, onRevoked }: SharesTableProps) {
  return (
    <div className={styles.tableWrap}>
      <table className={pageStyles.table} aria-label={caption}>
        <thead>
          <tr>
            {showProject && <th scope="col" className={pageStyles.th}>Project</th>}
            {showProject && <th scope="col" className={pageStyles.th}>Owner</th>}
            <th scope="col" className={pageStyles.th}>Shared with</th>
            <th scope="col" className={pageStyles.th}>Level</th>
            <th scope="col" className={pageStyles.th}>Expires</th>
            <th scope="col" className={pageStyles.th}>Shared on</th>
            {canRevoke && <th scope="col" className={pageStyles.th}>Actions</th>}
          </tr>
        </thead>
        <tbody>
          {shares.map((s) => (
            <tr key={`${s.project.id}:${s.collaborator.id}`} className={pageStyles.tr}>
              {showProject && <td className={pageStyles.td}>{s.project.name}</td>}
              {showProject && <td className={pageStyles.td}><Person person={s.owner} link={linkUsers} /></td>}
              <td className={pageStyles.td}>
                <Person person={s.collaborator} link={linkUsers} />
                {s.collaborator.status !== 'active' && <span className={styles.muted}> ({s.collaborator.status})</span>}
              </td>
              <td className={pageStyles.td}>{shareLevelLabel(s.access, s.toggles)}</td>
              <td className={pageStyles.td}>
                {s.expiresAt ? <time dateTime={s.expiresAt}>{whenLabel(s.expiresAt, 'Never')}</time> : 'Never'}
                {s.expired && <span className={pageStyles.badgeWarn}> Expired</span>}
              </td>
              <td className={pageStyles.td}><time dateTime={s.createdAt}>{whenLabel(s.createdAt, '')}</time></td>
              {canRevoke && (
                <td className={pageStyles.td}>
                  <ForcedAction
                    label="Revoke"
                    ariaLabel={`Revoke ${s.collaborator.name}'s share of ${s.project.name}`}
                    confirmTitle="Revoke this share"
                    confirmMessage={`${s.collaborator.name} (${s.collaborator.email}) loses access to ${s.project.name}, owned by ${s.owner.name}, now. Their open sessions on the project close. The owner can share it again.`}
                    stepUpMessage="Enter your password to revoke the share. The revoke is recorded in the audit log and in the project's activity."
                    confirmLabel="Revoke the share"
                    url={`/api/admin/shares/${encodeURIComponent(s.project.id)}/${encodeURIComponent(s.collaborator.id)}`}
                    failure="Could not revoke the share"
                    onDone={(answer) => onRevoked(s, answer.socketsClosed !== false)}
                  />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
