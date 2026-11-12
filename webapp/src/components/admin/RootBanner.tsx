'use client'

import { Crown } from 'lucide-react'
import type { RootNotice } from '@/providers/AuthProvider'
import styles from './AdminNotices.module.css'

/**
 * The header's Root banner (step 2.5, ID-10, master plan §14.4): admins only, identity switch
 * on. While the boot's automatic choice waits for the host it names Root and how to change
 * it; an unconfirmed Root is protected but has no Root-only powers (it cannot transfer Root
 * yet), so the wording says when it can. With no Root, the Root-only actions wait for the
 * host. `undefined` (switch off, or the Root could not be read) and a confirmed Root show nothing.
 */
export function RootBanner({ root }: { root: RootNotice | null | undefined }) {
  if (root === undefined || (root && root.confirmed)) return null
  if (root === null) {
    return (
      <div role="status" aria-label="This instance has no Root" className={`${styles.banner} ${styles.rootNotice}`}>
        <Crown size={14} className={styles.icon} aria-hidden />
        <span>
          <strong>This instance has no Root.</strong> Admins keep their powers; the Root-only actions wait until the
          host names one: <code>./redamon.sh set-root &lt;email&gt;</code>.
        </span>
      </div>
    )
  }
  // The date as recorded (UTC), unambiguous in every locale.
  const on = root.chosenAt ? ` on ${root.chosenAt.slice(0, 10)}` : ''
  return (
    <div role="status" aria-label="Root was chosen automatically" className={`${styles.banner} ${styles.rootNotice}`}>
      <Crown size={14} className={styles.icon} aria-hidden />
      <span>
        Root is <strong>{root.email}</strong>, chosen automatically{on}. Root can transfer it once the host confirms
        it; the host can run <code>./redamon.sh set-root &lt;email&gt;</code>.
      </span>
    </div>
  )
}
