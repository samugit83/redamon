'use client'

import { useEffect, useState } from 'react'
import { ShieldAlert, KeyRound } from 'lucide-react'
import { GuardedLink as Link } from '@/components/GuardedLink'
import type { AdminNotices } from '@/providers/AuthProvider'
import { LEGACY_GRANTS_CHANGED_EVENT, LEGACY_REVIEW_ANCHOR, plural } from './updateNotes'
import { RootBanner } from './RootBanner'
import styles from './AdminNotices.module.css'

/** Red while the escape hatch is on (HD-30): it reopens shared tools, so admins must not forget it. */
export function CompatBanner() {
  return (
    <div role="status" aria-label="Compatibility mode is on" className={`${styles.banner} ${styles.compat}`}>
      <ShieldAlert size={14} className={styles.icon} aria-hidden />
      <span>
        <strong>Compatibility mode is on.</strong> REDAMON_SHARED_TOOLS_COMPAT gives every account created before the
        upgrade the shared tools without a grant; every use is audited. Turn it off in .env once nobody needs it.
      </span>
    </div>
  )
}

export function LegacyReviewBanner({ pending }: { pending: number }) {
  return (
    <div role="status" aria-label="Legacy access waits for review" className={`${styles.banner} ${styles.review}`}>
      <KeyRound size={14} className={styles.icon} aria-hidden />
      <span>
        {plural(pending, 'legacy grant from the previous version waits', 'legacy grants from the previous version wait')}{' '}
        for your review.{' '}
        <Link href={`/settings/users#${LEGACY_REVIEW_ANCHOR}`} className={styles.bannerLink}>Review on the Users page</Link>
      </span>
    </div>
  )
}

interface AdminBannersProps {
  isAdmin: boolean
  rbac: AdminNotices | undefined
  pathname: string
}

/**
 * The header's banner slot: admins only, from /api/auth/me's `rbac` block. No banner blocks
 * anything; the Root one (step 2.5) shows while Root is unconfirmed or missing. A decision on the Users page fires LEGACY_GRANTS_CHANGED_EVENT, and the
 * count is read again then.
 */
export function AdminBanners({ isAdmin, rbac, pathname }: AdminBannersProps) {
  const [notices, setNotices] = useState<AdminNotices | undefined>(rbac)
  useEffect(() => { setNotices(rbac) }, [rbac])

  useEffect(() => {
    if (!isAdmin) return
    let live = true
    const refresh = () => {
      fetch('/api/auth/me', { cache: 'no-store' })
        .then(res => (res.ok ? res.json() : null))
        .then((body: { rbac?: AdminNotices } | null) => { if (live && body?.rbac) setNotices(body.rbac) })
        // The banner keeps what it showed: a failed refresh is not worth a message here.
        .catch(() => {})
    }
    window.addEventListener(LEGACY_GRANTS_CHANGED_EVENT, refresh)
    return () => {
      live = false
      window.removeEventListener(LEGACY_GRANTS_CHANGED_EVENT, refresh)
    }
  }, [isAdmin])

  if (!isAdmin || !notices) return null
  const pending = notices.legacyGrantsPending ?? 0
  const showReview = pending > 0 && pathname !== '/settings/users'
  const showRoot = notices.root === null || (notices.root !== undefined && !notices.root.confirmed)
  if (!notices.compat && !showReview && !showRoot) return null
  return (
    <div className={styles.slot}>
      {notices.compat && <CompatBanner />}
      {showRoot && <RootBanner root={notices.root} />}
      {showReview && <LegacyReviewBanner pending={pending} />}
    </div>
  )
}
