'use client'

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import noticeStyles from '@/components/auth/ForbiddenNotice.module.css'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { AdminShareRow, SharesOverview } from '@/lib/authz/adminShares'
import { useConsoleSections } from '../AdminConsole'
import { SharesTable } from './SharesTable'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from '../projects/overview.module.css'

interface Filters {
  q: string
  project: string
  user: string
}

const FILTER_KEYS = ['q', 'project', 'user'] as const

function filtersFrom(params: URLSearchParams | null): Filters {
  return { q: params?.get('q') ?? '', project: params?.get('project') ?? '', user: params?.get('user') ?? '' }
}

function queryOf(f: Filters, cursor?: string): string {
  const qs = new URLSearchParams()
  for (const k of FILTER_KEYS) if (f[k].trim()) qs.set(k, f[k].trim())
  if (cursor) qs.set('cursor', cursor)
  return qs.toString()
}

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  /** Sharing went out of force, or Root's policy now hides others' shares, after the console read it. */
  | { kind: 'hidden' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; page: SharesOverview; more: 'idle' | 'loading' | string }

/**
 * The admin console's Shares section (step 6.4; GV-05, GV-20): every share between accounts with its
 * project, owner, level, toggles and expiry, searched and paged (`/admin/shares?project=<id>` or
 * `?user=<id>` narrows it), and Root's force-revoke. The console opens it only for users:read while
 * sharing is in force and Root's policy lets administrators see every share; the route checks the
 * same, so a policy changed meanwhile shows here as the hidden state.
 */
export default function AdminSharesPage() {
  const uid = useId()
  const router = useRouter()
  const searchParams = useSearchParams()
  const usersOpen = useConsoleSections().some((s) => s.id === 'users')
  const [filters, setFilters] = useState<Filters>(() => filtersFrom(searchParams))
  const [search, setSearch] = useState(filters.q)
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [notice, setNotice] = useState('')
  const generation = useRef(0)

  const load = useCallback(async (f: Filters) => {
    const mine = ++generation.current
    setView({ kind: 'loading' })
    try {
      const page = await fetchJson<SharesOverview>(`/api/admin/shares?${queryOf(f)}`, { cache: 'no-store' }, 'Could not list the shares')
      if (mine !== generation.current) return
      setView({ kind: 'ready', page, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      const error = toApiError(err, 'Could not list the shares')
      const permission = forbiddenPermission(error)
      if (permission) setView({ kind: 'denied', permission })
      else if (error.code === 'shares_hidden' || error.status === 404) setView({ kind: 'hidden' })
      else setView({ kind: 'error', message: error.message })
    }
  }, [])

  useEffect(() => { void load(filters) }, [load, filters])

  function apply(next: Filters) {
    setFilters(next)
    const qs = queryOf(next)
    router.replace(qs ? `/admin/shares?${qs}` : '/admin/shares', { scroll: false })
  }

  function submitSearch(e: FormEvent) {
    e.preventDefault()
    if (search.trim() !== filters.q.trim()) apply({ ...filters, q: search })
  }

  async function loadMore() {
    if (view.kind !== 'ready' || !view.page.nextCursor) return
    const { page } = view
    const mine = generation.current
    setView({ ...view, more: 'loading' })
    try {
      const next = await fetchJson<SharesOverview>(`/api/admin/shares?${queryOf(filters, page.nextCursor!)}`, { cache: 'no-store' }, 'Could not list more shares')
      if (mine !== generation.current) return
      setView({ kind: 'ready', page: { ...next, shares: [...page.shares, ...next.shares] }, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      setView({ kind: 'ready', page, more: toApiError(err, 'Could not list more shares').message })
    }
  }

  const reload = () => void load(filters)
  const filtered = FILTER_KEYS.some((k) => filters[k].trim() !== '')
  const narrowed = filters.project || filters.user

  function revoked(s: AdminShareRow, socketsClosed: boolean) {
    setNotice(`Revoked ${s.collaborator.name}'s share of ${s.project.name}.${socketsClosed ? '' : ' The agent did not confirm closing their open sessions on it.'}`)
    reload()
  }

  return (
    <div className={consoleStyles.page}>
      <div className={styles.headline}>
        <h1 className={consoleStyles.title}>Shares</h1>
      </div>
      <p className={styles.intro}>Every share between accounts on this instance. Expired shares give nothing and are removed by the next sweep.</p>

      <form className={styles.filters} onSubmit={submitSearch} role="search" aria-label="Find shares">
        <div className={styles.filter}>
          <label className={pageStyles.label} htmlFor={`${uid}-q`}>Project, owner or person</label>
          <input id={`${uid}-q`} type="search" className={pageStyles.input} value={search} onChange={(e) => setSearch(e.target.value)} maxLength={200} />
        </div>
        <button type="submit" className={pageStyles.actionButton}>Search</button>
        {filtered && (
          <button type="button" className={pageStyles.actionButton} onClick={() => { setSearch(''); apply({ q: '', project: '', user: '' }) }}>
            Clear filters
          </button>
        )}
      </form>
      {narrowed && <p className={styles.filterTag}>{filters.project ? "Showing one project's shares only." : "Showing one account's shares only."}</p>}
      {notice && <p className={styles.notice} role="status">{notice}</p>}

      {view.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the shares…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'hidden' && (
        <div role="alert" className={noticeStyles.notice}>
          <p className={noticeStyles.title}>Shares are not listed here now.</p>
          <p className={noticeStyles.body}>
            This section lists every share only while sharing is in force and Root&apos;s sharing policy lets administrators see every share.
          </p>
        </div>
      )}
      {view.kind === 'error' && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={reload}>Retry</button>
        </div>
      )}
      {view.kind === 'ready' && (
        view.page.shares.length === 0 ? (
          <p className={consoleStyles.state}>{filtered ? 'No share matches these filters.' : 'No project is shared yet.'}</p>
        ) : (
          <>
            <p className={styles.count} aria-live="polite">
              Showing {view.page.shares.length} of {view.page.total} share{view.page.total === 1 ? '' : 's'}
            </p>
            <SharesTable shares={view.page.shares} canRevoke={view.page.actions.revoke} linkUsers={usersOpen} caption="Shares" onRevoked={revoked} />
            {view.page.nextCursor && (
              <div className={styles.more}>
                <button type="button" className={pageStyles.actionButton} onClick={() => void loadMore()} disabled={view.more === 'loading'}>
                  {view.more === 'loading' ? 'Loading…' : 'Load more'}
                </button>
              </div>
            )}
            {view.more !== 'idle' && view.more !== 'loading' && <div className={pageStyles.error} role="alert">{view.more}</div>}
          </>
        )
      )}
    </div>
  )
}
