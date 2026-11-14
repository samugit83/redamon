'use client'

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { GuardedLink } from '@/components/GuardedLink'
import { ForbiddenNotice } from '@/components/auth/ForbiddenNotice'
import noticeStyles from '@/components/auth/ForbiddenNotice.module.css'
import { useAuth } from '@/providers/AuthProvider'
import { PERMISSIONS, type PermissionId } from '@/lib/authz/permissions'
import {
  openSections, sectionAccess, sectionForPath, type AllSharesView, type ConsoleSection, type Holds,
} from './consoleSections'
import { SECTION_ICONS } from './consoleIcons'
import styles from './admin.module.css'

const SectionsContext = createContext<readonly ConsoleSection[]>([])

/** The sections the signed-in person may open, for the pages inside the console. */
export function useConsoleSections(): readonly ConsoleSection[] {
  return useContext(SectionsContext)
}

/**
 * Whether Root's sharing policy lets admins see every share, read once from the instance settings
 * (admins read the policy there while sharing is in force). Not asked when it cannot matter; a
 * failed read hides the Shares section, as the policy being off would.
 */
function useAllSharesView(ask: boolean): AllSharesView {
  const [answer, setAnswer] = useState<AllSharesView>('pending')
  useEffect(() => {
    if (!ask) return
    let live = true
    fetch('/api/admin/instance-settings', { cache: 'no-store' })
      .then(async (res) => (res.ok ? res.json() : null))
      .then((body) => { if (live) setAnswer(body?.sharingPolicy?.adminsSeeAllShares === true ? 'yes' : 'no') })
      .catch(() => { if (live) setAnswer('no') })
    return () => { live = false }
  }, [ask])
  return ask ? answer : 'no'
}

function MissingPermissions({ missing }: { missing: readonly PermissionId[] }) {
  if (missing.length === 1) return <ForbiddenNotice permission={missing[0]} />
  return (
    <div role="alert" className={noticeStyles.notice}>
      <p className={noticeStyles.title}>You do not have the permission this needs.</p>
      <p className={noticeStyles.body}>Any one of these opens this section:</p>
      <ul className={styles.missingList}>
        {missing.map((p) => (
          <li key={p}><code className={noticeStyles.id}>{p}</code>: {PERMISSIONS[p].description}</li>
        ))}
      </ul>
      <p className={noticeStyles.body}>Ask an administrator to grant one to you.</p>
    </div>
  )
}

function Frame({ children }: { children: ReactNode }) {
  return <div className={styles.frame}>{children}</div>
}

/**
 * The admin console around every /admin page (step 6.1, UI-10): a left navigation of the sections
 * the person's permissions open, and in place of a section's page the denied state when they may
 * not open it. The layout renders it only with RBAC_GOVERNANCE_ENABLED on.
 */
export function AdminConsole({ children }: { children: ReactNode }) {
  const pathname = usePathname()
  const { user, isLoading, capabilities, sessionError } = useAuth()
  const holds: Holds = (p) => capabilities.has(p)
  const allShares = useAllSharesView(user?.sharing?.enabled === true && capabilities.has('users:read'))

  if (isLoading) {
    return <Frame><p className={styles.state} role="status">Loading the admin console…</p></Frame>
  }
  if (!user) {
    return (
      <Frame>
        {sessionError ? (
          <>
            <div className={styles.error} role="alert">{sessionError.message}</div>
            <div>
              <button type="button" className="primaryButton" onClick={() => window.location.reload()}>Retry</button>
            </div>
          </>
        ) : (
          <p className={styles.state}>You are signed out. <Link href="/login">Sign in</Link> to open the admin console.</p>
        )}
      </Frame>
    )
  }

  const sections = openSections(holds, allShares)
  const current = sectionForPath(pathname)
  if (sections.length === 0 && !current) {
    return (
      <Frame>
        <div role="alert" className={noticeStyles.notice}>
          <p className={noticeStyles.title}>The admin console needs an administration permission.</p>
          <p className={noticeStyles.body}>
            You hold none of the permissions that open its sections (for example <code className={noticeStyles.id}>users:read</code> or{' '}
            <code className={noticeStyles.id}>audit:read</code>). Ask an administrator to grant one to you.
          </p>
        </div>
      </Frame>
    )
  }

  const access = current ? sectionAccess(current, holds, allShares) : { state: 'open' as const }
  let body: ReactNode = children
  if (access.state === 'pending') {
    body = <p className={styles.state} role="status">Checking the sharing policy…</p>
  } else if (access.state === 'denied') {
    body = <MissingPermissions missing={access.missing} />
  } else if (access.state === 'policy') {
    body = (
      <div role="alert" className={noticeStyles.notice}>
        <p className={noticeStyles.title}>Shares are not listed here now.</p>
        <p className={noticeStyles.body}>
          This section lists every share only while sharing is in force and Root&apos;s sharing policy lets
          administrators see every share.
        </p>
      </div>
    )
  }

  const navItem = (href: string, label: string, isCurrent: boolean, Icon: LucideIcon) => (
    <li key={href}>
      <GuardedLink
        href={href}
        className={`${styles.navLink} ${isCurrent ? styles.navLinkActive : ''}`}
        aria-current={isCurrent ? 'page' : undefined}
      >
        <Icon size={16} strokeWidth={1.75} aria-hidden="true" />
        {label}
      </GuardedLink>
    </li>
  )

  return (
    <SectionsContext.Provider value={sections}>
      <div className={styles.console}>
        {sections.length > 0 && (
          <nav className={styles.nav} aria-label="Admin console">
            <p className={styles.navTitle} aria-hidden="true">Admin console</p>
            <ul className={styles.navList}>
              {sections.map((s) => navItem(s.href, s.label, current?.id === s.id, SECTION_ICONS[s.id]))}
            </ul>
          </nav>
        )}
        <div className={styles.content}>{body}</div>
      </div>
    </SectionsContext.Provider>
  )
}
