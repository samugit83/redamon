'use client'

import type { ReactNode } from 'react'
import Image from 'next/image'
// Guarded drop-in for next/link: consults the unsaved-changes guard before
// navigating, so header links prompt when a dirty form would lose edits.
import { GuardedLink as Link } from '@/components/GuardedLink'
import { usePathname } from 'next/navigation'
import { Crosshair, FolderOpen, Shield, BookOpen, TrendingUp, FileText, Settings, Users, GitBranch, Network, Puzzle } from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import { ProjectSelector } from './ProjectSelector'
import { UserSelector } from './UserSelector'
import { AdminBanners } from '@/components/admin/CompatBanner'
import { ActAsBannerSlot } from '@/components/auth/ActAsBanner'
import { useAuth } from '@/providers/AuthProvider'
import { useCan } from '@/hooks/useCan'
import { useProject } from '@/providers/ProjectProvider'
import styles from './GlobalHeader.module.css'

export function GlobalHeader() {
  const pathname = usePathname()
  const { user } = useAuth()
  const canReadUsers = useCan('users:read')
  const { projectId } = useProject()

  const coreNav: Array<{ label: string; href: string; icon: ReactNode; isNew?: boolean }> = [
    { label: 'Red Zone', href: '/graph', icon: <Crosshair size={14} /> },
    ...(projectId
      ? [{ label: 'Recon Pipeline', href: `/projects/${projectId}/settings`, icon: <GitBranch size={14} /> }]
      : []),
    { label: 'CypherFix', href: '/cypherfix', icon: <Shield size={14} /> },
    { label: 'Insights', href: '/insights', icon: <TrendingUp size={14} /> },
    // TrafficMind table view is visible to everyone (view captured traffic for
    // their project). Only the TrafficMind *settings* (egress guard, master
    // switch) need platform:traffic_capture, gated on the /traffic page.
    { label: 'TrafficMind', href: '/traffic', icon: <Network size={14} /> },
    { label: 'Plugins', href: '/plugins', icon: <Puzzle size={14} /> },
    { label: 'Reports', href: '/reports', icon: <FileText size={14} /> },
  ]

  return (
    <>
    <header className={styles.header}>
      <Link href="/graph" className={styles.logo}>
        <Image src="/logo.png" alt="RedAmon" width={28} height={28} className={styles.logoImg} />
        <span className={styles.logoText}>
          <span className={styles.logoAccent}>Red</span>Amon
        </span>
      </Link>

      <div className={styles.spacer} />

      <div className={styles.actions}>
        <nav className={styles.coreNav}>
          {coreNav.map(item => {
            const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`${styles.coreNavItem} ${isActive ? styles.coreNavItemActive : ''}`}
              >
                {item.icon}
                <span>{item.label}</span>
                {'isNew' in item && item.isNew && <span className={styles.newBadge}>New!</span>}
              </Link>
            )
          })}
        </nav>

        <Link
          href="/projects"
          className={`${styles.navItem} ${pathname === '/projects' || pathname.startsWith('/projects/') ? styles.navItemActive : ''}`}
        >
          <FolderOpen size={14} />
          <span>Projects</span>
        </Link>

        {canReadUsers && (
          <Link
            href="/settings/users"
            className={`${styles.navItem} ${pathname === '/settings/users' ? styles.navItemActive : ''}`}
          >
            <Users size={14} />
            <span>Users</span>
          </Link>
        )}

        <div className={styles.divider} />

        <ProjectSelector />

        <div className={styles.divider} />

        <ThemeToggle />

        <div className={styles.divider} />

        <a
          href="https://github.com/samugit83/redamon/wiki"
          target="_blank"
          rel="noopener noreferrer"
          className={styles.helpLink}
          title="Wiki Documentation"
        >
          <BookOpen size={17} />
        </a>

        <div className={styles.divider} />

        <UserSelector />

        <div className={styles.divider} />

        <Link
          href="/settings"
          className={`${styles.helpLink} ${pathname === '/settings' ? styles.navItemActive : ''}`}
          title="Global Settings"
        >
          <Settings size={17} />
        </Link>
      </div>
    </header>
    {/* While an admin acts as someone (permissions switch on, step 3.14): on every page. */}
    <ActAsBannerSlot />
    {/* /api/auth/me sends `rbac` to administrator accounts only. */}
    <AdminBanners adminAccount={user?.rbac !== undefined} rbac={user?.rbac} pathname={pathname} />
    </>
  )
}
