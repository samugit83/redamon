'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { AccountStatusActions } from '@/components/admin/AccountStatusActions'
import { InviteRowActions } from '@/components/admin/InviteUserModal'
import { ResetCredentialsModal } from '@/components/admin/ResetCredentialsModal'
import { useProject } from '@/providers/ProjectProvider'
import { fetchOk, toApiError } from '@/lib/apiError'
import type { DirectoryRow } from '@/lib/authz/userDirectory'
import type { PasswordPolicyView } from '@/hooks/usePasswordPolicy'
import { EditAccountModal } from './EditAccountModal'
import pageStyles from '@/app/settings/users/page.module.css'

interface Props {
  row: DirectoryRow
  /** The password policy in force, for a temporary password. */
  policy: PasswordPolicyView | null
  /** The directory links to the detail's permissions; the detail shows them itself. */
  permissionsLink: boolean
  /** The account changed: read it again. */
  onChanged: () => void
  /** The account is gone. */
  onDeleted: () => void
}

/**
 * An account's actions in the admin console (step 6.2): exactly those the server listed for the
 * signed-in person on this account (`row.actions`, hierarchy.ts), and on the person's own row
 * "Sign out everywhere". Each action is its existing route's, which decides again; every
 * confirmation goes through the app's dialog, and an action on another admin asks for the person's
 * own password, as the server does.
 */
export function UserRowActions({ row, policy, permissionsLink, onChanged, onDeleted }: Props) {
  const alerts = useAlertModal()
  const { setUserId } = useProject()
  const [editing, setEditing] = useState(false)
  const [resetting, setResetting] = useState(false)
  const [deletingAdmin, setDeletingAdmin] = useState(false)
  const can = new Set(row.actions)
  const admin = row.accountType === 'admin'
  const url = `/api/users/${encodeURIComponent(row.id)}`

  async function actAs() {
    const refusal = await setUserId(row.id, {
      target: { id: row.id, name: row.name, email: row.email, accountType: row.accountType },
    })
    if (refusal) void alerts.alertError(refusal.message, `Act as ${row.name}`)
  }

  async function removeMember() {
    const ok = await alerts.dangerConfirm(
      `Delete ${row.name} (${row.email})? Their projects, conversations and settings are deleted too. This cannot be undone.`,
      'Delete account',
      { confirmLabel: 'Delete' },
    )
    if (!ok) return
    try {
      await fetchOk(url, { method: 'DELETE' }, 'Could not delete the account')
      onDeleted()
    } catch (err) {
      void alerts.alertError(toApiError(err, 'Could not delete the account').message, row.name)
    }
  }

  const label = (verb: string) => `${verb} ${row.name}`

  return (
    <div className={pageStyles.actions}>
      {can.has('create') && (
        <InviteRowActions
          user={row}
          buttonClassName={pageStyles.actionButton}
          dangerClassName={pageStyles.deleteButton}
          onChanged={onChanged}
        />
      )}
      {can.has('edit') && (
        <button type="button" className={pageStyles.actionButton} aria-label={label('Edit')} onClick={() => setEditing(true)}>
          Edit
        </button>
      )}
      {permissionsLink && can.has('assign_permissions') && (
        <Link
          href={`/admin/users/${encodeURIComponent(row.id)}#permissions`}
          className={pageStyles.actionButton}
          aria-label={`Permissions of ${row.name}`}
        >
          Permissions
        </Link>
      )}
      {can.has('reset_credentials') && (
        <button type="button" className={pageStyles.actionButton} aria-label={`Reset the credentials of ${row.name}`} onClick={() => setResetting(true)}>
          Reset credentials
        </button>
      )}
      {can.has('impersonate') && (
        <button type="button" className={pageStyles.actionButton} aria-label={label('Act as')} onClick={() => void actAs()}>
          Act as
        </button>
      )}
      {(row.self || can.has('disable') || can.has('enable') || can.has('revoke_sessions')) && (
        <AccountStatusActions
          user={{ id: row.id, name: row.name, role: admin ? 'admin' : 'standard', status: row.status }}
          selfId={row.self ? row.id : undefined}
          identity
          manageAdmins={admin && !row.self}
          allowed={{ disable: can.has('disable'), enable: can.has('enable'), revoke: row.self || can.has('revoke_sessions') }}
          buttonClassName={pageStyles.actionButton}
          dangerClassName={pageStyles.deleteButton}
          onChanged={onChanged}
        />
      )}
      {can.has('delete') && (
        <button
          type="button"
          className={`${pageStyles.actionButton} ${pageStyles.deleteButton}`}
          aria-label={label('Delete')}
          onClick={() => (admin ? setDeletingAdmin(true) : void removeMember())}
        >
          Delete
        </button>
      )}

      {editing && <EditAccountModal isOpen row={row} onClose={() => setEditing(false)} onSaved={onChanged} />}
      {resetting && (
        <ResetCredentialsModal
          isOpen
          user={{ id: row.id, name: row.name, email: row.email }}
          targetIsAdmin={admin}
          policy={policy}
          onClose={() => setResetting(false)}
          onDone={onChanged}
        />
      )}
      {admin && (
        <StepUpModal
          isOpen={deletingAdmin}
          title="Delete an admin"
          message={`Delete ${row.name} (${row.email}), an admin account? Their projects, conversations and settings are deleted too. Confirm with your own password.`}
          confirmLabel="Delete"
          onConfirm={async (stepUpPassword) => {
            await fetchOk(url, {
              method: 'DELETE',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ stepUpPassword }),
            }, 'Could not delete the account')
            onDeleted()
          }}
          onClose={() => setDeletingAdmin(false)}
        />
      )}
    </div>
  )
}
