'use client'

import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { useAuth } from '@/providers/AuthProvider'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { BreakGlassDialog, type BreakGlassInput, type BreakGlassTarget } from '@/components/auth/BreakGlassDialog'
import { fetchJson, toApiError } from '@/lib/apiError'
import type { AdminProjectRow, ProjectsOverview } from '@/lib/authz/adminProjects'
import type { AdminShareRow, SharesOverview } from '@/lib/authz/adminShares'
import { useConsoleSections } from '../AdminConsole'
import { SharesTable } from '../shares/SharesTable'
import { whenLabel } from '../shares/shareWords'
import { ForcedAction } from './ForcedAction'
import { ConsoleHeader } from '../ConsoleHeader'
import { SECTION_ICONS } from '../consoleIcons'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import styles from './overview.module.css'

interface Filters {
  q: string
  owner: string
}

function filtersFrom(params: URLSearchParams | null): Filters {
  return { q: params?.get('q') ?? '', owner: params?.get('owner') ?? '' }
}

function queryOf(f: Filters, cursor?: string): string {
  const qs = new URLSearchParams()
  if (f.q.trim()) qs.set('q', f.q.trim())
  if (f.owner.trim()) qs.set('owner', f.owner.trim())
  if (cursor) qs.set('cursor', cursor)
  return qs.toString()
}

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; page: ProjectsOverview; more: 'idle' | 'loading' | string }

/**
 * The admin console's Projects section (step 6.4; GV-04, SH-18): every project on the instance with
 * its owner, scope, live shares and last activity, searched and paged (`/admin/projects?owner=<id>`
 * lists one account's). A row opens the project read-only by oversight when sharing is in force and
 * the person is not acting as someone; lists the project's shares when they may be listed; and
 * offers the confirmed Root break-glass (step 4.14's dialog and route; closing one early stays on the
 * projects page's oversight list), the forced delete and the force-revoke of a share. What a row offers is
 * the server's answer (`actions`); every action's route decides again. The console shows the denied
 * state to anyone without projects:oversee before this page renders.
 */
export default function AdminProjectsPage() {
  const uid = useId()
  const router = useRouter()
  const searchParams = useSearchParams()
  const { user: me } = useAuth()
  const sections = useConsoleSections()
  const sharesOpen = sections.some((s) => s.id === 'shares')
  const usersOpen = sections.some((s) => s.id === 'users')
  const [filters, setFilters] = useState<Filters>(() => filtersFrom(searchParams))
  const [search, setSearch] = useState(filters.q)
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [expanded, setExpanded] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const [glassTarget, setGlassTarget] = useState<BreakGlassTarget | null>(null)
  const generation = useRef(0)

  const load = useCallback(async (f: Filters) => {
    const mine = ++generation.current
    setView({ kind: 'loading' })
    try {
      const page = await fetchJson<ProjectsOverview>(`/api/admin/projects?${queryOf(f)}`, { cache: 'no-store' }, 'Could not list the projects')
      if (mine !== generation.current) return
      setView({ kind: 'ready', page, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      const error = toApiError(err, 'Could not list the projects')
      const permission = forbiddenPermission(error)
      setView(permission ? { kind: 'denied', permission } : { kind: 'error', message: error.message })
    }
  }, [])

  useEffect(() => { void load(filters) }, [load, filters])

  function apply(next: Filters) {
    setFilters(next)
    const qs = queryOf(next)
    router.replace(qs ? `/admin/projects?${qs}` : '/admin/projects', { scroll: false })
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
      const next = await fetchJson<ProjectsOverview>(`/api/admin/projects?${queryOf(filters, page.nextCursor!)}`, { cache: 'no-store' }, 'Could not list more projects')
      if (mine !== generation.current) return
      setView({ kind: 'ready', page: { ...next, projects: [...page.projects, ...next.projects] }, more: 'idle' })
    } catch (err) {
      if (mine !== generation.current) return
      setView({ kind: 'ready', page, more: toApiError(err, 'Could not list more projects').message })
    }
  }

  const reload = () => void load(filters)
  const filtered = filters.q.trim() !== '' || filters.owner.trim() !== ''

  function deleted(p: AdminProjectRow) {
    setNotice(`Deleted ${p.name} (owned by ${p.owner.name}).`)
    if (expanded === p.id) setExpanded(null)
    reload()
  }

  // Step 4.14's break-glass, through its own route: the row, its audit row and the owner's notice.
  async function openBreakGlass(input: BreakGlassInput) {
    if (!glassTarget) return
    const { breakGlass } = await fetchJson<Record<'breakGlass', { expiresAt: string }>>(
      `/api/projects/${encodeURIComponent(glassTarget.id)}/breakglass`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: input.reason, durationMinutes: input.durationMinutes, stepUpPassword: input.password }),
      },
      'Break-glass was refused',
    )
    setNotice(`Break-glass open on ${glassTarget.name} until ${whenLabel(breakGlass.expiresAt, 'its expiry')}: opening it now reads everything, raw data included.`)
  }

  function revoked(s: AdminShareRow, socketsClosed: boolean) {
    setNotice(`Revoked ${s.collaborator.name}'s share of ${s.project.name}.${socketsClosed ? '' : ' The agent did not confirm closing their open sessions on it.'}`)
    reload()
  }

  return (
    <div className={consoleStyles.page}>
      <ConsoleHeader
        icon={SECTION_ICONS.projects}
        title="Projects"
        lead={<>Every project on this instance. Opening one you do not own is an oversight read: its owner sees it in the project&apos;s activity.</>}
      />

      <form className={styles.filters} onSubmit={submitSearch} role="search" aria-label="Find projects">
        <div className={styles.filter}>
          <label className={pageStyles.label} htmlFor={`${uid}-q`}>Project or owner</label>
          <input id={`${uid}-q`} type="search" className={pageStyles.input} value={search} onChange={(e) => setSearch(e.target.value)} maxLength={200} />
        </div>
        <button type="submit" className={pageStyles.actionButton}>Search</button>
        {filtered && (
          <button type="button" className={pageStyles.actionButton} onClick={() => { setSearch(''); apply({ q: '', owner: '' }) }}>
            Clear filters
          </button>
        )}
      </form>
      {filters.owner && <p className={styles.filterTag}>Showing one account&apos;s projects only.</p>}
      {notice && <p className={styles.notice} role="status">{notice}</p>}

      {view.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the projects…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'error' && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={reload}>Retry</button>
        </div>
      )}
      {view.kind === 'ready' && (
        view.page.projects.length === 0 ? (
          <p className={consoleStyles.state}>{filtered ? 'No project matches these filters.' : 'No projects yet.'}</p>
        ) : (
          <>
            {!view.page.sharing.inForce && (
              <p className={styles.muted}>Sharing is not in force: projects cannot be opened read-only and no share is listed.</p>
            )}
            <p className={styles.count} aria-live="polite">
              Showing {view.page.projects.length} of {view.page.total} project{view.page.total === 1 ? '' : 's'}
            </p>
            <div className={styles.tableWrap}>
              <table className={pageStyles.table} aria-label="Projects">
                <thead>
                  <tr>
                    <th scope="col" className={pageStyles.th}>Project</th>
                    <th scope="col" className={pageStyles.th}>Owner</th>
                    <th scope="col" className={pageStyles.th}>Shares</th>
                    <th scope="col" className={pageStyles.th}>Last activity</th>
                    <th scope="col" className={pageStyles.th}>Created</th>
                    <th scope="col" className={pageStyles.th}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {view.page.projects.map((p) => (
                    <ProjectRows
                      key={p.id}
                      project={p}
                      page={view.page}
                      own={p.owner.id === me?.id}
                      linkUsers={usersOpen}
                      listShares={sharesOpen && view.page.sharing.allShares}
                      expanded={expanded === p.id}
                      onToggle={() => setExpanded(expanded === p.id ? null : p.id)}
                      onDeleted={() => deleted(p)}
                      onBreakGlass={() => setGlassTarget({ id: p.id, name: p.name, owner: `${p.owner.name} (${p.owner.email})` })}
                      onRevoked={revoked}
                    />
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

      <BreakGlassDialog isOpen={glassTarget !== null} target={glassTarget} onConfirm={openBreakGlass} onClose={() => setGlassTarget(null)} />
    </div>
  )
}

function ProjectRows({ project: p, page, own, linkUsers, listShares, expanded, onToggle, onDeleted, onBreakGlass, onRevoked }: {
  project: AdminProjectRow
  page: ProjectsOverview
  own: boolean
  linkUsers: boolean
  listShares: boolean
  expanded: boolean
  onToggle: () => void
  onDeleted: () => void
  onBreakGlass: () => void
  onRevoked: (s: AdminShareRow, socketsClosed: boolean) => void
}) {
  const panelId = `shares-${p.id}`
  return (
    <>
      <tr className={pageStyles.tr}>
        <td className={pageStyles.td}>
          <span className={pageStyles.cellStack}>
            <span>{p.name}</span>
            {p.targetLabel && <span className={pageStyles.email}>{p.targetLabel}</span>}
          </span>
        </td>
        <td className={pageStyles.td}>
          <span className={pageStyles.cellStack}>
            {linkUsers
              ? <Link href={`/admin/users/${encodeURIComponent(p.owner.id)}`} className={styles.nameLink}>{p.owner.name}</Link>
              : <span>{p.owner.name}</span>}
            <span className={pageStyles.email}>
              {p.owner.email}
              {p.owner.status !== 'active' && <span className={styles.muted}> ({p.owner.status})</span>}
            </span>
          </span>
        </td>
        <td className={pageStyles.td}>
          {p.collaborators === null ? (
            <span className={styles.muted} title="Sharing is not in force">Not in force</span>
          ) : listShares && p.collaborators > 0 ? (
            <button type="button" className={pageStyles.actionButton} aria-expanded={expanded} aria-controls={panelId} onClick={onToggle}>
              {expanded ? 'Hide' : 'Show'} {p.collaborators} share{p.collaborators === 1 ? '' : 's'}
            </button>
          ) : (
            <span>{p.collaborators}</span>
          )}
        </td>
        <td className={pageStyles.td}><time dateTime={p.lastActivityAt}>{whenLabel(p.lastActivityAt, '')}</time></td>
        <td className={pageStyles.td}><time dateTime={p.createdAt}>{whenLabel(p.createdAt, '')}</time></td>
        <td className={pageStyles.td}>
          <span className={styles.rowActions}>
            {page.actions.openReadOnly && (
              <Link href={`/graph?project=${encodeURIComponent(p.id)}`} className={pageStyles.actionButton} aria-label={`Open ${p.name}${own ? '' : ' read-only'}`}>
                {own ? 'Open' : 'Open read-only'}
              </Link>
            )}
            {page.actions.breakGlass && !own && (
              <button type="button" className={pageStyles.actionButton} aria-label={`Open break-glass on ${p.name}`} onClick={onBreakGlass}>
                Break-glass
              </button>
            )}
            {page.actions.delete && (
              <ForcedAction
                label="Delete"
                ariaLabel={`Delete ${p.name}`}
                confirmTitle={`Delete ${p.name}`}
                confirmMessage={`${p.name}, owned by ${p.owner.name} (${p.owner.email}), is deleted with its graph, scans, files and conversations, and its shares end. This cannot be undone.`}
                stepUpMessage="Enter your password to delete the project. The deletion is recorded in the audit log."
                confirmLabel="Delete the project"
                url={`/api/admin/projects/${encodeURIComponent(p.id)}`}
                failure="Could not delete the project"
                onDone={onDeleted}
              />
            )}
          </span>
        </td>
      </tr>
      {expanded && (
        <tr className={styles.sharesRow}>
          <td colSpan={6} id={panelId}>
            <ProjectShares project={p} canRevoke={page.actions.revokeShares} linkUsers={linkUsers} onRevoked={onRevoked} />
          </td>
        </tr>
      )}
    </>
  )
}

type SharesView =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; answer: SharesOverview }

/** One project's shares, read from the shares overview when its row is opened. */
function ProjectShares({ project, canRevoke, linkUsers, onRevoked }: {
  project: AdminProjectRow
  canRevoke: boolean
  linkUsers: boolean
  onRevoked: (s: AdminShareRow, socketsClosed: boolean) => void
}) {
  const [view, setView] = useState<SharesView>({ kind: 'loading' })
  const read = useCallback(async () => {
    setView({ kind: 'loading' })
    try {
      const answer = await fetchJson<SharesOverview>(
        `/api/admin/shares?project=${encodeURIComponent(project.id)}&limit=100`, { cache: 'no-store' }, 'Could not list the shares',
      )
      setView({ kind: 'ready', answer })
    } catch (err) {
      setView({ kind: 'error', message: toApiError(err, 'Could not list the shares').message })
    }
  }, [project.id])
  useEffect(() => { void read() }, [read])

  if (view.kind === 'loading') return <p className={consoleStyles.state} role="status">Loading the shares…</p>
  if (view.kind === 'error') {
    return (
      <div className={pageStyles.errorState}>
        <div className={pageStyles.error} role="alert">{view.message}</div>
        <button type="button" className={pageStyles.actionButton} onClick={() => void read()}>Retry</button>
      </div>
    )
  }
  if (view.answer.shares.length === 0) return <p className={consoleStyles.state}>{project.name} is not shared with anyone.</p>
  return (
    <>
      <SharesTable
        shares={view.answer.shares}
        canRevoke={canRevoke && view.answer.actions.revoke}
        linkUsers={linkUsers}
        showProject={false}
        caption={`Shares of ${project.name}`}
        onRevoked={onRevoked}
      />
      {view.answer.nextCursor && (
        <Link href={`/admin/shares?project=${encodeURIComponent(project.id)}`} className={styles.nameLink}>
          See all {view.answer.total} shares of {project.name}
        </Link>
      )}
    </>
  )
}
