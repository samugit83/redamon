'use client'

import { useEffect, useState, type ReactNode } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { holdsConsolePermission } from '@/app/admin/consoleSections'
import styles from './page.module.css'

/**
 * With RBAC_GOVERNANCE_ENABLED on the user directory lives in the admin console (step 6.1, OQ-44):
 * a users:read holder is sent to /admin/users, a holder of another console permission to /admin,
 * the query string and the anchor kept. A member stays, and so does whoever came for the
 * change-password dialog: the user menu opens `?changePassword=true` and the page strips the query
 * once the dialog is open, so the first sight of it holds for as long as the page stays mounted.
 * With the switch off nothing moves. A layout, so the page itself is unchanged.
 */
export default function UsersLayout({ children }: { children: ReactNode }) {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { user, isLoading, capabilities } = useAuth()
  const cameForPassword = searchParams.get('changePassword') === 'true'
  const [stay, setStay] = useState(cameForPassword)
  useEffect(() => {
    if (cameForPassword) setStay(true)
  }, [cameForPassword])

  const target = !isLoading && user?.flags?.governance === true && !stay && !cameForPassword
    && holdsConsolePermission((p) => capabilities.has(p))
    ? (capabilities.has('users:read') ? '/admin/users' : '/admin')
    : null

  const query = searchParams.toString()
  useEffect(() => {
    if (!target) return
    router.replace(`${target}${query ? `?${query}` : ''}${window.location.hash}`)
  }, [target, query, router])

  if (target) return <div className={styles.page}><p className={styles.empty} role="status">Opening the admin console…</p></div>
  return <>{children}</>
}
