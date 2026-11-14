'use client'

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { useCan } from '@/hooks/useCan'
import { usePasswordPolicy } from '@/hooks/usePasswordPolicy'
import { useUsers } from '@/hooks/useUsers'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { LegacyAccessCard } from '@/components/admin/LegacyAccessCard'
import { WhatChangedCard } from '@/components/admin/WhatChangedCard'
import { InviteUserModal } from '@/components/admin/InviteUserModal'
import { RootTransferAction } from '@/components/admin/RootTransferAction'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { DirectoryPage, DirectoryRow, SetOption } from '@/lib/authz/userDirectory'
import { LastLogin, SetsCell, StatusCell, TypeBadge } from './UserFacts'
import { UserRowActions } from './UserRowActions'
import { ConsoleHeader } from '../ConsoleHeader'
import { SECTION_ICONS } from '../consoleIcons'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './users.module.css'

interface Filters {
  q: string
  status: string
  type: string
  set: string
}

const FILTER_KEYS = ['q', 'status', 'type', 'set'] as const

function filtersFrom(params: URLSearchParams | null): Filters {
  return { q: params?.get('q') ?? '', status: params?.get('status') ?? '', type: params?.get('type') ?? '', set: params?.get('set') ?? '' }
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
  | { kind: 'error'; message: string }
  | { kind: 'ready'; page: DirectoryPage; more: 'idle' | 'loading' | string }

/**
 * The admin console's users directory (step 6.2; GV-01, ID-27): every account with its type,
 * status, permission sets or admin profile, last sign-in and project counts, searched and filtered
 * (the filters live in the address, so `/admin/users?set=<id>` lists a set's holders), a page at a
 * time. Each row offers what the server says the signed-in person may do on that account. The
 * legacy access review and the update notes stay at the top, as on the Users page; the console
 * shows the denied state to anyone without users:read before this page renders.
 */
export default function AdminUsersPage() {
  const uid = useId()
  const router = useRouter()
  const searchParams = useSearchParams()
  const { user: me } = useAuth()
  const canInvite = useCan('users:create')
  const policy = usePasswordPolicy(true)
  const [filters, setFilters] = useState<Filters>(() => filtersFrom(searchParams))
  const [search, setSearch] = useState(filters.q)
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [inviting, setInviting] = useState(false)
  // Kept while a new page loads, so the set filter keeps its options.
  const [setOptions, setSetOptions] = useState<SetOption[]>([])
  const generation = useRef(0)

  const load = useCallback(async (f: Filters) => {
    const mine = ++generation.current
    setView({ kind: 'loading' })
    try {
      const page = await fetchJson<DirectoryPage>(`/api/admin/users?${queryOf(f)}`, { cache: 'no-store' }, 'Could not list the accounts')
      if (mine !== generation.current) return
      setSetOptions(page.setOptions)
      setView({ kind: 'ready', page, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      const error = toApiError(err, 'Could not list the accounts')
      const permission = forbiddenPermission(error)
      setView(permission ? { kind: 'denied', permission } : { kind: 'error', message: error.message })
    }
  }, [])

  useEffect(() => { void load(filters) }, [load, filters])

  function apply(next: Filters) {
    setFilters(next)
    const qs = queryOf(next)
    router.replace(qs ? `/admin/users?${qs}` : '/admin/users', { scroll: false })
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
      const next = await fetchJson<DirectoryPage>(`/api/admin/users?${queryOf(filters, page.nextCursor!)}`, { cache: 'no-store' }, 'Could not list more accounts')
      if (mine !== generation.current) return
      setView({ kind: 'ready', page: { ...next, users: [...page.users, ...next.users] }, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      setView({ kind: 'ready', page, more: toApiError(err, 'Could not list more accounts').message })
    }
  }

  const reload = () => void load(filters)
  const filtered = FILTER_KEYS.some((k) => filters[k].trim() !== '')
  const confirmedRoot = me?.accountType === 'root' && me?.rbac?.root?.confirmed === true

  return (
    <div className={consoleStyles.page}>
      <ConsoleHeader
        icon={SECTION_ICONS.users}
        title="Users"
        lead="Every account on this instance: invitations, status, permission sets and sign-ins."
        actions={(confirmedRoot && me) || canInvite ? (
          <>
            {confirmedRoot && me && <RootTransfer selfId={me.id} />}
            {canInvite && (
              <button type="button" className="primaryButton" onClick={() => setInviting(true)}>Invite user</button>
            )}
          </>
        ) : undefined}
      />

      <WhatChangedCard />
      <LegacyAccessCard />

      <form className={styles.filters} onSubmit={submitSearch} role="search" aria-label="Find accounts">
        <div className={`${styles.filter} ${styles.search}`}>
          <label className={pageStyles.label} htmlFor={`${uid}-q`}>Name or email</label>
          <input
            id={`${uid}-q`}
            type="search"
            className={pageStyles.input}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            maxLength={200}
          />
        </div>
        <div className={styles.filter}>
          <label className={pageStyles.label} htmlFor={`${uid}-status`}>Status</label>
          <select id={`${uid}-status`} className={pageStyles.select} value={filters.status} onChange={(e) => apply({ ...filters, status: e.target.value })}>
            <option value="">Any status</option>
            <option value="active">Active</option>
            <option value="invited">Invited</option>
            <option value="disabled">Disabled</option>
          </select>
        </div>
        <div className={styles.filter}>
          <label className={pageStyles.label} htmlFor={`${uid}-type`}>Type</label>
          <select id={`${uid}-type`} className={pageStyles.select} value={filters.type} onChange={(e) => apply({ ...filters, type: e.target.value })}>
            <option value="">Any type</option>
            <option value="root">Root</option>
            <option value="admin">Admin</option>
            <option value="member">Member</option>
          </select>
        </div>
        <div className={styles.filter}>
          <label className={pageStyles.label} htmlFor={`${uid}-set`}>Set or profile</label>
          <select id={`${uid}-set`} className={pageStyles.select} value={filters.set} onChange={(e) => apply({ ...filters, set: e.target.value })}>
            <option value="">Any set</option>
            {filters.set && !setOptions.some((s) => s.id === filters.set) && <option value={filters.set}>{filters.set}</option>}
            <optgroup label="Member sets">
              {setOptions.filter((s) => s.kind === 'member').map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </optgroup>
            <optgroup label="Admin profiles">
              {setOptions.filter((s) => s.kind === 'admin').map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </optgroup>
          </select>
        </div>
        <button type="submit" className={pageStyles.actionButton}>Search</button>
        {filtered && (
          <button type="button" className={pageStyles.actionButton} onClick={() => { setSearch(''); apply({ q: '', status: '', type: '', set: '' }) }}>
            Clear filters
          </button>
        )}
      </form>

      {view.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the accounts…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'error' && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={reload}>Retry</button>
        </div>
      )}
      {view.kind === 'ready' && (
        view.page.users.length === 0 ? (
          <p className={consoleStyles.state}>{filtered ? 'No account matches these filters.' : 'No accounts yet.'}</p>
        ) : (
          <>
            <p className={styles.count} aria-live="polite">
              Showing {view.page.users.length} of {view.page.total} account{view.page.total === 1 ? '' : 's'}
            </p>
            <div className={styles.tableWrap}>
              <table className={pageStyles.table} aria-label="Accounts">
                <thead>
                  <tr>
                    <th scope="col" className={pageStyles.th}>Account</th>
                    <th scope="col" className={pageStyles.th}>Type</th>
                    <th scope="col" className={pageStyles.th}>Status</th>
                    <th scope="col" className={pageStyles.th}>Sets or profile</th>
                    <th scope="col" className={pageStyles.th}>Last sign-in</th>
                    <th scope="col" className={pageStyles.th}>Projects</th>
                    <th scope="col" className={pageStyles.th}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {view.page.users.map((row) => (
                    <DirectoryRowView key={row.id} row={row} sharing={view.page.sharing} policy={policy} onChanged={reload} />
                  ))}
                </tbody>
              </table>
            </div>
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

      <InviteUserModal isOpen={inviting} onClose={() => setInviting(false)} onInvited={reload} selfId={me?.id} />
    </div>
  )
}

function DirectoryRowView({ row, sharing, policy, onChanged }: {
  row: DirectoryRow
  sharing: boolean
  policy: ReturnType<typeof usePasswordPolicy>
  onChanged: () => void
}) {
  return (
    <tr className={pageStyles.tr}>
      <td className={pageStyles.td}>
        <span className={pageStyles.cellStack}>
          <Link href={`/admin/users/${encodeURIComponent(row.id)}`} className={styles.nameLink}>
            {row.name}
          </Link>
          <span className={pageStyles.email}>
            {row.email}
            {row.self && <span className={pageStyles.selfLabel}>(you)</span>}
          </span>
        </span>
      </td>
      <td className={pageStyles.td}><TypeBadge type={row.accountType} /></td>
      <td className={pageStyles.td}><StatusCell status={row.status} mustChange={row.mustChangePassword} /></td>
      <td className={pageStyles.td}><SetsCell row={row} /></td>
      <td className={pageStyles.td}><LastLogin at={row.lastLoginAt} /></td>
      <td className={pageStyles.td}>
        <span title="Projects owned">{row.projects.owned}</span>
        {sharing && <span className={styles.muted}> · {row.projects.shared ?? 0} shared</span>}
      </td>
      <td className={pageStyles.td}>
        <UserRowActions row={row} policy={policy} permissionsLink onChanged={onChanged} onDeleted={onChanged} />
      </td>
    </tr>
  )
}

/**
 * "Transfer Root" for the confirmed Root (step 2.6), which the Users page offered on its own row:
 * its candidates are the admins who can sign in, read from the Users page's list.
 */
function RootTransfer({ selfId }: { selfId: string }) {
  const { data: users } = useUsers()
  if (!users) return null
  return <RootTransferAction selfId={selfId} users={users} className={pageStyles.actionButton} />
}

