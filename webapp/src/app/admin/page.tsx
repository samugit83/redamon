'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useConsoleSections } from './AdminConsole'
import styles from './admin.module.css'

/**
 * /admin, where the header's Admin link lands: it opens the first section the person may open, the
 * navigation already lists the rest. With none, the console shows its no-permission notice instead
 * of rendering this page.
 */
export default function AdminIndexPage() {
  const sections = useConsoleSections()
  const router = useRouter()
  const first = sections[0]?.href
  useEffect(() => {
    if (first) router.replace(first)
  }, [first, router])
  return <p className={styles.state} role="status">Opening the admin console…</p>
}
