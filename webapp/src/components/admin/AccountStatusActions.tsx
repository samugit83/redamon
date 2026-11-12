'use client'

import { useState } from 'react'
import { useOptionalAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { fetchJson, toApiError } from '@/lib/apiError'

export interface StatusRowUser {
  id: string
  name: string
  role: string
  /** active | invited | disabled; a row from an older server has none and reads as active. */
  status?: string
}

interface AgentPart { stopped?: number; closed?: number; error?: string }
interface StatusAnswer {
  changed?: boolean
  agent?: { runs?: AgentPart; sockets?: AgentPart }
}

interface Props {
  user: StatusRowUser
  selfId: string | undefined
  /** RBAC_IDENTITY_ENABLED is on (`rbac.identity` of /api/auth/me): disable and sign-out exist. */
  identity: boolean
  buttonClassName: string
  dangerClassName: string
  /** The list must be read again: a status changed. */
  onChanged: () => void
}

type Action = 'disable' | 'enable' | 'revoke' | 'revoke-all'

const ENDPOINT: Record<Action, (id: string) => string> = {
  disable: (id) => `/api/users/${encodeURIComponent(id)}/disable`,
  enable: (id) => `/api/users/${encodeURIComponent(id)}/enable`,
  revoke: (id) => `/api/users/${encodeURIComponent(id)}/revoke-sessions`,
  'revoke-all': () => '/api/auth/sessions/revoke-all',
}

const FAILED: Record<Action, string> = {
  disable: 'Could not disable the account',
  enable: 'Could not enable the account',
  revoke: 'Could not sign the account out',
  'revoke-all': 'Could not sign out everywhere',
}

/** The agent parts that did not answer, in words, or null when everything it held was ended. */
function agentUnconfirmed(answer: StatusAnswer): string | null {
  const parts = [answer.agent?.runs?.error, answer.agent?.sockets?.error].filter(Boolean)
  return parts.length ? [...new Set(parts)].join(', ') : null
}

/**
 * Disable, Enable and "Sign out everywhere" on a Users page row (step 2.3, ID-13, ID-21).
 * What is offered follows the server's rules, which still decide: admins act on members;
 * another admin's status and sessions are Root's (step 2.6), so no button is shown for them;
 * the own row offers "Sign out everywhere" for this account. Enable is offered on a disabled
 * row whatever the identity switch; with the switch off, enabling another admin asks for
 * the admin's own password (step-up). Every action is confirmed first; outside the app
 * shell there is no dialog to ask with, and nothing is done.
 */
export function AccountStatusActions({ user, selfId, identity, buttonClassName, dangerClassName, onChanged }: Props) {
  const alerts = useOptionalAlertModal()
  const [busy, setBusy] = useState(false)
  const [stepUp, setStepUp] = useState(false)
  const status = user.status ?? 'active'
  const self = user.id === selfId
  const admin = user.role === 'admin'

  async function send(action: Action, body: Record<string, unknown> = {}): Promise<StatusAnswer> {
    return fetchJson<StatusAnswer>(ENDPOINT[action](user.id), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }, FAILED[action])
  }

  async function run(action: Action, confirm: { title: string; message: string; label: string; danger?: boolean }) {
    const ask = confirm.danger ? alerts?.dangerConfirm : alerts?.confirm
    if (!(await ask?.(confirm.message, confirm.title, { confirmLabel: confirm.label }))) return
    setBusy(true)
    try {
      const answer = await send(action)
      if (action === 'revoke-all') {
        // This browser's cookie is gone too.
        window.location.replace('/login')
        return
      }
      const unconfirmed = agentUnconfirmed(answer)
      if (unconfirmed) {
        void alerts?.alertWarning(
          `${user.name} is signed out, but the agent did not confirm that their open sessions and runs were ended `
          + `(${unconfirmed}). No new session can be opened.`,
          'Agent sessions not confirmed',
        )
      }
    } catch (err) {
      void alerts?.alertError(toApiError(err, FAILED[action]).message, user.name)
    } finally {
      onChanged()
      setBusy(false)
    }
  }

  const disable = () => run('disable', {
    title: 'Disable account',
    message: `Disable ${user.name}? They are signed out everywhere, their MCP tokens are revoked and their agent runs `
      + 'stop. Their projects are kept, and their schedules and queued scans do not start while the account is disabled.',
    label: 'Disable',
    danger: true,
  })
  const enable = () => run('enable', {
    title: 'Enable account',
    message: `Enable ${user.name}? They can sign in again with their previous password. MCP tokens revoked at the disable stay revoked.`,
    label: 'Enable',
  })
  const revoke = () => run(self ? 'revoke-all' : 'revoke', {
    title: 'Sign out everywhere',
    message: self
      ? 'Sign your account out on every browser and device, this one included? Your MCP tokens are revoked too.'
      : `Sign ${user.name} out on every browser and device? Their MCP tokens are revoked and their open agent sessions close. The account stays active.`,
    label: 'Sign out everywhere',
    danger: true,
  })

  const showEnable = status === 'disabled' && !self && !(identity && admin)
  const showRevoke = identity && status === 'active' && (self || !admin)
  const showDisable = identity && status === 'active' && !self && !admin
  const enableNeedsStepUp = !identity && admin

  return (
    <>
      {showEnable && (
        <button
          type="button"
          className={buttonClassName}
          disabled={busy}
          aria-label={`Enable ${user.name}`}
          onClick={() => (enableNeedsStepUp ? setStepUp(true) : void enable())}
        >
          Enable
        </button>
      )}
      {showRevoke && (
        <button type="button" className={buttonClassName} disabled={busy} aria-label={`Sign ${self ? 'your account' : user.name} out everywhere`} onClick={() => void revoke()}>
          Sign out everywhere
        </button>
      )}
      {showDisable && (
        <button type="button" className={`${buttonClassName} ${dangerClassName}`} disabled={busy} aria-label={`Disable ${user.name}`} onClick={() => void disable()}>
          Disable
        </button>
      )}
      {enableNeedsStepUp && (
        <StepUpModal
          isOpen={stepUp}
          title="Enable an admin"
          message={`Enable ${user.name}, an admin account? Confirm with your own password.`}
          confirmLabel="Enable"
          onConfirm={async (pw) => {
            try {
              await send('enable', { stepUpPassword: pw })
            } finally {
              onChanged()
            }
          }}
          onClose={() => setStepUp(false)}
        />
      )}
    </>
  )
}

/** The status badge of a Users page row; nothing for an active account. */
export function AccountStatusBadge({ status, className }: { status?: string; className: string }) {
  if (!status || status === 'active') return null
  return <span className={className}>{status === 'disabled' ? 'Disabled' : status}</span>
}
