'use client'

import { useCallback, useEffect, useId, useState } from 'react'
import Link from 'next/link'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { DirectoryPage } from '@/lib/authz/userDirectory'
import { STATUS_LABEL, TypeBadge } from '../users/UserFacts'
import type { SetKind, SetRow } from './setModel'
import { SET_WORDS } from './setWords'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './sets.module.css'

/** The directory's largest page (userDirectory.ts MAX_PAGE_SIZE); past it the panel links to the directory. */
const HOLDERS_SHOWN = 100

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; page: DirectoryPage }

interface SetHoldersProps {
  kind: SetKind
  set: SetRow
  /** A refused delete's reason (the 409 carries a count, not names). */
  refusal?: string
  onClose: () => void
}

/**
 * Who holds a set or profile (step 6.3), read from the users directory's `?set=` filter (step 6.2),
 * which lists the holders exactly as the set list and a refused delete count them. Reading it takes
 * users:read; without it the panel says so. More than one page links to the directory filtered.
 */
export function SetHolders({ kind, set, refusal, onClose }: SetHoldersProps) {
  const headingId = useId()
  const [view, setView] = useState<View>({ kind: 'loading' })
  const words = SET_WORDS[kind]
  const directoryHref = `/admin/users?set=${encodeURIComponent(set.id)}`

  const load = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const page = await fetchJson<DirectoryPage>(
        `/api/admin/users?set=${encodeURIComponent(set.id)}&limit=${HOLDERS_SHOWN}`,
        { cache: 'no-store' },
        `Could not list who holds the ${words.one}`,
      )
      setView({ kind: 'ready', page })
    } catch (err) {
      const error = toApiError(err, `Could not list who holds the ${words.one}`)
      const permission = forbiddenPermission(error)
      setView(permission ? { kind: 'denied', permission } : { kind: 'error', message: error.message })
    }
  }, [set.id, words.one])

  useEffect(() => { void load() }, [load])

  return (
    <section className={styles.holders} aria-labelledby={headingId}>
      <div className={styles.holdersHead}>
        <h2 id={headingId} className={styles.sectionTitle}>Who holds {set.name}</h2>
        <button type="button" className={pageStyles.actionButton} onClick={onClose}>Close</button>
      </div>
      {refusal && <div className={pageStyles.error} role="alert">{refusal}</div>}
      {view.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the holders…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'error' && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={() => void load()}>Retry</button>
        </div>
      )}
      {view.kind === 'ready' && (view.page.users.length === 0 ? (
        <p className={consoleStyles.state}>Nobody holds this {words.short} now.</p>
      ) : (
        <>
          <ul className={styles.holderList} aria-label={`Holders of ${set.name}`}>
            {view.page.users.map((u) => (
              <li key={u.id} className={styles.holder}>
                <Link href={`/admin/users/${encodeURIComponent(u.id)}`} className={styles.link}>{u.name}</Link>
                <span className={pageStyles.email}>{u.email}</span>
                <TypeBadge type={u.accountType} />
                {u.status !== 'active' && <span className={styles.muted}>{STATUS_LABEL[u.status] ?? u.status}</span>}
              </li>
            ))}
          </ul>
          {view.page.total > view.page.users.length && (
            <p className={styles.muted}>Showing {view.page.users.length} of {view.page.total}.</p>
          )}
          <Link href={directoryHref} className={styles.directoryLink}>
            {view.page.total > view.page.users.length ? `See all ${view.page.total} in the users directory` : 'Open in the users directory'}
          </Link>
        </>
      ))}
    </section>
  )
}
