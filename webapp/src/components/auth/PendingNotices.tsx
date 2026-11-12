'use client'

import { useCallback } from 'react'
import { useOptionalAlertModal } from '@/components/ui'

/** A notice as the sign-in answers it (lib/authz/accountNotices.ts NoticeView). */
export interface AccountNoticeView {
  id: string
  type: 'credentials_reset'
  at: string
  by: { name: string; email: string }
  reason: string | null
  mode: 'link' | 'temporary'
}

type Alerts = ReturnType<typeof useOptionalAlertModal>

const TITLE = 'Your password was reset'

function isView(v: unknown): v is AccountNoticeView {
  if (!v || typeof v !== 'object') return false
  const n = v as Record<string, unknown>
  const by = n.by as Record<string, unknown> | null | undefined
  return n.type === 'credentials_reset' && typeof n.id === 'string' && typeof n.at === 'string'
    && (n.mode === 'link' || n.mode === 'temporary') && (n.reason === null || typeof n.reason === 'string')
    && !!by && typeof by === 'object' && typeof by.name === 'string' && typeof by.email === 'string'
}

/** The notices a sign-in answer carries; anything else in it is ignored. */
export function readNoticeViews(value: unknown): AccountNoticeView[] {
  return Array.isArray(value) ? value.filter(isView) : []
}

/**
 * What the person reads. Whoever resets a password can sign in with it first, so the notice
 * names who did it and when, and says what to do if it was not expected (feature document §7.1).
 */
export function noticeMessage(n: AccountNoticeView): string {
  const how = n.mode === 'link' ? 'with a reset link' : 'with a temporary password'
  const why = n.reason ? `Reason: ${n.reason}.` : 'No reason was given.'
  return `${n.by.name} (${n.by.email}) reset your password ${how} on ${new Date(n.at).toLocaleString()}. ${why} `
    + 'If you did not ask for this, tell your administrator: whoever resets a password can sign in with it before you do.'
}

/**
 * Shows each notice once, in the app's dialog, one after the other; resolves when the person
 * has closed them all. Outside the dialog provider it resolves at once: a notice never blocks a
 * sign-in (the account's activity list keeps it).
 */
export async function showPendingNotices(alerts: Alerts, value: unknown): Promise<void> {
  if (!alerts) return
  for (const n of readNoticeViews(value)) await alerts.alertWarning(noticeMessage(n), TITLE)
}

/** `showPendingNotices` bound to the app's dialog: for the pages that sign a person in (step 2.10). */
export function usePendingNotices(): (value: unknown) => Promise<void> {
  const alerts = useOptionalAlertModal()
  return useCallback((value: unknown) => showPendingNotices(alerts, value), [alerts])
}
