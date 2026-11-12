import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { rbacFlags } from '@/lib/authz/flags'
import { InviteAcceptForm } from './InviteAcceptForm'

export const metadata: Metadata = {
  title: 'RedAmon',
  referrer: 'no-referrer',
}

/**
 * `/invite` (step 2.9): where an invite or reset link lands once its token became a cookie.
 * Public while RBAC_IDENTITY_ENABLED is on; with it off the page does not exist.
 */
export default function InvitePage() {
  if (!rbacFlags().identity) notFound()
  return <InviteAcceptForm />
}
