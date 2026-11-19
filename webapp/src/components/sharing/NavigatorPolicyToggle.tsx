/**
 * "AI Navigator for collaborators" in the share dialog (plan §5.4, §9.12). AI Navigator runs on each
 * collaborator's own model, so turning it on sends this project's data to the provider they chose:
 * only the owner may do it, with their password; anyone else sees its state. Hidden when the policy
 * route answers 404 (sharing not in force, or Root turned AI Navigator off).
 */
'use client'

import { useCallback, useEffect, useState } from 'react'
import { Toggle } from '@/components/ui'
import { errorMessage, fetchJson } from '@/lib/apiError'
import styles from './ShareDialog.module.css'

type State = { kind: 'loading' } | { kind: 'hidden' } | { kind: 'ready'; allowed: boolean } | { kind: 'error'; message: string }

const HELP = "Collaborators can ask AI Navigator about this project. It runs on each collaborator's own AI model, " +
  'so your project data is sent to the AI provider they chose. Off by default.'

export function NavigatorPolicyToggle({ projectId, canChange, askPassword }: {
  projectId: string
  canChange: boolean
  /** The dialog's password prompt; true once `run` succeeded with the password. */
  askPassword: (text: { title: string; message: string; confirmLabel: string }, run: (password: string) => Promise<void>) => Promise<boolean>
}) {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [saving, setSaving] = useState(false)
  const url = `/api/navigator/projects/${encodeURIComponent(projectId)}/policy`

  const load = useCallback(async () => {
    const res = await fetch(url, { cache: 'no-store' }).catch(() => null)
    if (!res || res.status === 404 || res.status === 403) return setState({ kind: 'hidden' })
    const body = await res.json().catch(() => null) as { collaboratorsAllowed?: boolean } | null
    if (!res.ok || !body) return setState({ kind: 'error', message: `Could not read the AI Navigator setting (HTTP ${res.status}).` })
    setState({ kind: 'ready', allowed: body.collaboratorsAllowed === true })
  }, [url])

  useEffect(() => { void load() }, [load])

  const send = async (value: boolean, password?: string) => {
    const body = await fetchJson<{ collaboratorsAllowed: boolean }>(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ collaboratorsAllowed: value, ...(password ? { stepUpPassword: password } : {}) }),
    }, 'Could not change the AI Navigator setting')
    setState({ kind: 'ready', allowed: body.collaboratorsAllowed })
  }

  const change = async (value: boolean) => {
    setSaving(true)
    try {
      if (value) {
        await askPassword({
          title: 'Let collaborators use AI Navigator',
          message: `${HELP} Confirm with your password.`,
          confirmLabel: 'Turn on',
        }, (password) => send(true, password))
      } else {
        await send(false)
      }
    } catch (err) {
      setState({ kind: 'error', message: errorMessage(err, 'Could not change the AI Navigator setting') })
    } finally {
      setSaving(false)
    }
  }

  if (state.kind === 'hidden' || state.kind === 'loading') return null
  return (
    <div className={styles.callout} role="group" aria-label="AI Navigator for collaborators" data-testid="navigator-policy">
      {state.kind === 'error' ? (
        <span>{state.message}</span>
      ) : (
        <>
          <strong>AI Navigator for collaborators</strong>
          <Toggle
            checked={state.allowed}
            onChange={(v: boolean) => void change(v)}
            disabled={!canChange || saving}
            aria-label="AI Navigator for collaborators"
          />
          <span className={styles.hint}>{HELP}</span>
        </>
      )}
    </div>
  )
}
