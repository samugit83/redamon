'use client'

import { useState, type ReactNode } from 'react'
import { useAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { fetchJson } from '@/lib/apiError'
import pageStyles from '@/app/settings/users/page.module.css'

interface ForcedActionProps {
  /** The button's text, and its accessible name with the target (`aria-label`). */
  label: string
  ariaLabel: string
  /** The first, plain confirmation: what will happen and to whom. */
  confirmTitle: string
  confirmMessage: ReactNode
  /** The password dialog that follows it (the routes take Root's own password). */
  stepUpMessage: ReactNode
  confirmLabel: string
  url: string
  failure: string
  onDone: (answer: Record<string, unknown>) => void
}

/**
 * One of Root's forced actions on another person's project (step 6.4, projects:administer): a
 * destructive confirmation through the app's alert, then Root's password, then the DELETE with
 * `{stepUpPassword}`. A refusal (a wrong password, root_only) shows in the password dialog, which
 * stays open; the password goes with that one request and is never kept.
 */
export function ForcedAction({
  label, ariaLabel, confirmTitle, confirmMessage, stepUpMessage, confirmLabel, url, failure, onDone,
}: ForcedActionProps) {
  const alerts = useAlertModal()
  const [asking, setAsking] = useState(false)

  async function start() {
    if (await alerts.dangerConfirm(confirmMessage, confirmTitle, { confirmLabel: 'Continue' })) setAsking(true)
  }

  async function run(password: string) {
    const answer = await fetchJson<Record<string, unknown>>(url, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ stepUpPassword: password }),
    }, failure)
    onDone(answer)
  }

  return (
    <>
      <button type="button" className={`${pageStyles.actionButton} ${pageStyles.deleteButton}`} aria-label={ariaLabel} onClick={() => void start()}>
        {label}
      </button>
      <StepUpModal
        isOpen={asking}
        title={confirmTitle}
        message={stepUpMessage}
        confirmLabel={confirmLabel}
        onConfirm={run}
        onClose={() => setAsking(false)}
      />
    </>
  )
}
