'use client'

import { useCallback } from 'react'
import { useOptionalAlertModal } from '@/components/ui'

/** A notice as the sign-in answers it (lib/authz/accountNotices.ts NoticeView). */
export type AccountNoticeView =
  | {
    id: string
    type: 'credentials_reset'
    at: string
    by: { name: string; email: string }
    reason: string | null
    mode: 'link' | 'temporary'
  }
  | {
    id: string
    type: 'email_changed'
    at: string
    by: { name: string; email: string }
    from: string
    to: string
    /** The account changed it itself. */
    self: boolean
  }
  | {
    id: string
    type: 'acted_as'
    at: string
    by: { name: string; email: string }
    reason: string | null
    /** The time limit the admin chose (step 3.14). */
    durationMinutes: number
  }
  | {
    id: string
    type: 'break_glass'
    at: string
    by: { name: string; email: string }
    reason: string
    durationMinutes: number
    /** The person's project Root opened (step 4.14). */
    project: { id: string; name: string }
  }

type Alerts = ReturnType<typeof useOptionalAlertModal>

const TITLES: Record<AccountNoticeView['type'], string> = {
  credentials_reset: 'Your password was reset',
  email_changed: 'Your sign-in email was changed',
  acted_as: 'An administrator acted as you',
  break_glass: 'Root opened break-glass access to your project',
}

function isView(v: unknown): v is AccountNoticeView {
  if (!v || typeof v !== 'object') return false
  const n = v as Record<string, unknown>
  const by = n.by as Record<string, unknown> | null | undefined
  const common = typeof n.id === 'string' && typeof n.at === 'string'
    && !!by && typeof by === 'object' && typeof by.name === 'string' && typeof by.email === 'string'
  if (!common) return false
  if (n.type === 'credentials_reset') {
    return (n.mode === 'link' || n.mode === 'temporary') && (n.reason === null || typeof n.reason === 'string')
  }
  if (n.type === 'acted_as') {
    return (n.reason === null || typeof n.reason === 'string') && Number.isSafeInteger(n.durationMinutes) && (n.durationMinutes as number) >= 1
  }
  if (n.type === 'break_glass') {
    const project = n.project as Record<string, unknown> | null | undefined
    return typeof n.reason === 'string' && Number.isSafeInteger(n.durationMinutes) && (n.durationMinutes as number) >= 1
      && !!project && typeof project === 'object' && typeof project.id === 'string' && typeof project.name === 'string'
  }
  return n.type === 'email_changed' && typeof n.from === 'string' && typeof n.to === 'string' && typeof n.self === 'boolean'
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
  const when = new Date(n.at).toLocaleString()
  if (n.type === 'email_changed') {
    // Whoever changes the sign-in email can then have a reset link or password sent their way.
    const who = n.self ? 'You changed your sign-in email' : `${n.by.name} (${n.by.email}) changed your sign-in email`
    return `${who} from ${n.from} to ${n.to} on ${when}. `
      + 'If you did not ask for this, tell your administrator: you now sign in with the new address.'
  }
  if (n.type === 'acted_as') {
    // Acting as someone is taking over their account for a while (feature document §4.7): say who, when, why.
    const why = n.reason ? `Reason: ${n.reason}.` : 'No reason was given.'
    return `${n.by.name} (${n.by.email}) acted as you on ${when}, for up to ${n.durationMinutes} min, using your account and API keys. ${why} `
      + 'If you did not expect this, tell your administrator. My account lists when it started and ended.'
  }
  if (n.type === 'break_glass') {
    // Break-glass reads everything a project holds, raw data included (feature document §4.5): say who, when, why.
    return `${n.by.name} (${n.by.email}), the instance's Root, opened break-glass access to your project "${n.project.name}" on ${when}, `
      + `for up to ${n.durationMinutes} min: read access to everything in it, raw data and files included. Reason: ${n.reason}. `
      + "The project's Activity page lists it."
  }
  const how = n.mode === 'link' ? 'with a reset link' : 'with a temporary password'
  const why = n.reason ? `Reason: ${n.reason}.` : 'No reason was given.'
  return `${n.by.name} (${n.by.email}) reset your password ${how} on ${when}. ${why} `
    + 'If you did not ask for this, tell your administrator: whoever resets a password can sign in with it before you do.'
}

/**
 * Shows each notice once, in the app's dialog, one after the other; resolves when the person
 * has closed them all. Outside the dialog provider it resolves at once: a notice never blocks a
 * sign-in (the account's activity list keeps it).
 */
export async function showPendingNotices(alerts: Alerts, value: unknown): Promise<void> {
  if (!alerts) return
  for (const n of readNoticeViews(value)) await alerts.alertWarning(noticeMessage(n), TITLES[n.type])
}

/** `showPendingNotices` bound to the app's dialog: for the pages that sign a person in (step 2.10). */
export function usePendingNotices(): (value: unknown) => Promise<void> {
  const alerts = useOptionalAlertModal()
  return useCallback((value: unknown) => showPendingNotices(alerts, value), [alerts])
}
