'use client'

import { useState } from 'react'
import { useOptionalAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { fetchJson, toApiError } from '@/lib/apiError'

export interface RoleRowUser {
  id: string
  name: string
  role: string
}

interface Props {
  user: RoleRowUser
  /** RBAC_IDENTITY_ENABLED is on: only the confirmed Root is shown this control, and every change takes its password. */
  identity: boolean
  className: string
  /** The list must be read again: a role changed. */
  onChanged: () => void
}

type Role = 'admin' | 'standard'

const FAILED = 'Could not change the role'

/**
 * The Member / Admin control of a Users page row (step 2.6, PE-08, ID-25). The page shows it
 * only where the viewer may change the role: with the identity switch off any admin on another
 * row (Phase 1), with it on the confirmed Root. Demoting another admin always takes the acting
 * admin's own password (step-up), and with the switch on every change does, because a role change
 * is Root's power and signs the account out (its session version is raised). A promotion with the
 * switch off is confirmed through the app's dialog; outside the app shell nothing is sent. The
 * server decides: a refusal is shown with its code.
 */
export function RoleControl({ user, identity, className, onChanged }: Props) {
  const alerts = useOptionalAlertModal()
  const [stepUpTo, setStepUpTo] = useState<Role | null>(null)
  const [busy, setBusy] = useState(false)
  const current: Role = user.role === 'admin' ? 'admin' : 'standard'

  async function send(role: Role, stepUpPassword?: string): Promise<void> {
    await fetchJson(`/api/users/${encodeURIComponent(user.id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stepUpPassword ? { role, stepUpPassword } : { role }),
    }, FAILED)
  }

  function describe(role: Role): string {
    const what = role === 'admin'
      ? `Make ${user.name} an admin? Admins manage members, the shared settings and every member's projects.`
      : `Make ${user.name} a member? They lose the admin role.`
    return identity ? `${what} They sign in again.` : what
  }

  async function choose(role: Role) {
    if (role === current) return
    if (identity || current === 'admin') {
      setStepUpTo(role)
      return
    }
    if (!(await alerts?.confirm(describe(role), 'Change the role', { confirmLabel: 'Make admin' }))) return
    setBusy(true)
    try {
      await send(role)
    } catch (err) {
      void alerts?.alertError(toApiError(err, FAILED).message, user.name)
    } finally {
      onChanged()
      setBusy(false)
    }
  }

  return (
    <>
      <select
        className={className}
        aria-label={`Role of ${user.name}`}
        value={current}
        disabled={busy}
        onChange={(e) => void choose(e.target.value as Role)}
      >
        <option value="standard">Member</option>
        <option value="admin">Admin</option>
      </select>
      <StepUpModal
        isOpen={stepUpTo !== null}
        title={stepUpTo === 'admin' ? 'Make an admin' : 'Remove the admin role'}
        message={stepUpTo ? `${describe(stepUpTo)} Confirm with your own password.` : ''}
        confirmLabel={stepUpTo === 'admin' ? 'Make admin' : 'Make member'}
        onConfirm={async (pw) => {
          if (!stepUpTo) return
          await send(stepUpTo, pw)
          onChanged()
        }}
        onClose={() => setStepUpTo(null)}
      />
    </>
  )
}
