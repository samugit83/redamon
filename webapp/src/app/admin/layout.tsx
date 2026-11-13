import type { ReactNode } from 'react'
import { notFound } from 'next/navigation'
import { rbacFlags } from '@/lib/authz/flags'
import { AdminConsole } from './AdminConsole'

/**
 * /admin (step 6.1, OQ-44): the admin console. With RBAC_GOVERNANCE_ENABLED off it does not exist,
 * as before Phase 6: Next's 404, decided here on the server before anything renders or is read, and
 * the Users page of Phases 2-3 stays where it was.
 */
export default function AdminLayout({ children }: { children: ReactNode }) {
  if (!rbacFlags().governance) notFound()
  return <AdminConsole>{children}</AdminConsole>
}
