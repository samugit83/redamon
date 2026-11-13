'use client'

import Link from 'next/link'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useAlertModal } from '@/components/ui'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { readApiError, toApiError } from '@/lib/apiError'
import { AUDIT_GROUPS, AUDIT_GROUP_IDS, type AuditGroup } from '@/lib/authz/auditLabels'
import type { ActivityEvent, ActivityPage, ActivityPerson } from '@/lib/authz/projectActivity'
import styles from './ActivityFeed.module.css'

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'denied' }
  | { kind: 'unavailable' }
  | { kind: 'ready'; page: ActivityPage }

const FALLBACK = "Could not read the project's activity"

function Person({ person }: { person: ActivityPerson }) {
  if (person.deleted || !person.email) {
    return <span className={styles.deleted}>{person.email ? `a deleted account (${person.email})` : 'a deleted account'}</span>
  }
  return <IdentityLabel name={person.name} email={person.email} accountType={person.accountType ?? undefined} />
}

function Actor({ event }: { event: ActivityEvent }) {
  if (event.actor) return <Person person={event.actor} />
  return <span className={styles.system}>{event.source === 'system' ? 'RedAmon, automatically' : 'no recorded account'}</span>
}

function Row({ event }: { event: ActivityEvent }) {
  return (
    <li className={styles.item}>
      <time className={styles.when} dateTime={event.at}>{new Date(event.at).toLocaleString()}</time>
      <div className={styles.body}>
        <span className={styles.label}>{event.label}</span>
        <span className={styles.people}>
          <span className={styles.by}>by</span> <Actor event={event} />
          {event.onBehalfOf && (
            <>
              {' '}<span className={styles.by}>acting as</span> <Person person={event.onBehalfOf} />
            </>
          )}
          {event.target && (
            <>
              {' '}<span className={styles.by}>with</span> <Person person={event.target} />
            </>
          )}
          {event.source === 'mcp' && <span className={styles.tag}>through MCP</span>}
        </span>
      </div>
    </li>
  )
}

/**
 * The project activity feed (step 4.13; UI-08, AU-07, AU-09): the owner's (and an overseer's) view of
 * who did what on the project, newest first, a page at a time, filtered by group. A refusal is told
 * on the page (who may see it); a failed next page in the app's dialog, keeping the rows shown.
 */
export function ActivityFeed({ projectId }: { projectId: string }) {
  const { alertError } = useAlertModal()
  const [group, setGroup] = useState<AuditGroup | ''>('')
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [loadingMore, setLoadingMore] = useState(false)
  // A slow answer for a group the person has since left must not replace the newer one.
  const generation = useRef(0)

  const url = useCallback((cursor?: string) => {
    const params = new URLSearchParams()
    if (group) params.set('group', group)
    if (cursor) params.set('cursor', cursor)
    const query = params.toString()
    return `/api/projects/${encodeURIComponent(projectId)}/activity${query ? `?${query}` : ''}`
  }, [projectId, group])

  const load = useCallback(async () => {
    const mine = ++generation.current
    setState({ kind: 'loading' })
    try {
      const res = await fetch(url())
      if (mine !== generation.current) return
      if (res.status === 403) return setState({ kind: 'denied' })
      if (res.status === 404) return setState({ kind: 'unavailable' })
      if (!res.ok) return setState({ kind: 'error', message: (await readApiError(res, FALLBACK)).message })
      const page = await res.json() as ActivityPage
      if (mine === generation.current) setState({ kind: 'ready', page })
    } catch (err) {
      if (mine === generation.current) setState({ kind: 'error', message: toApiError(err, FALLBACK).message })
    }
  }, [url])

  useEffect(() => {
    void load()
  }, [load])

  const loadMore = async () => {
    if (state.kind !== 'ready' || !state.page.nextCursor) return
    const mine = generation.current
    setLoadingMore(true)
    try {
      const res = await fetch(url(state.page.nextCursor))
      if (!res.ok) throw await readApiError(res, FALLBACK)
      const next = await res.json() as ActivityPage
      setLoadingMore(false)
      if (mine !== generation.current) return
      setState(prev => (prev.kind === 'ready'
        ? { kind: 'ready', page: { ...next, events: [...prev.page.events, ...next.events] } }
        : prev))
    } catch (err) {
      // The button is usable again while the dialog is open: the dialog waits to be dismissed.
      setLoadingMore(false)
      await alertError(toApiError(err, FALLBACK).message, 'Could not load more activity')
    }
  }

  const projectName = state.kind === 'ready' ? state.page.project?.name : null

  return (
    <section className={styles.feed} aria-labelledby="project-activity-title">
      <header className={styles.header}>
        <h1 id="project-activity-title" className={styles.title}>{projectName ? `Activity: ${projectName}` : 'Project activity'}</h1>
        <div className={styles.filter}>
          <label htmlFor="project-activity-group" className={styles.filterLabel}>Show</label>
          <select
            id="project-activity-group"
            className={styles.select}
            value={group}
            onChange={e => setGroup(e.target.value as AuditGroup | '')}
          >
            <option value="">All activity</option>
            {AUDIT_GROUP_IDS.map(id => <option key={id} value={id}>{AUDIT_GROUPS[id]}</option>)}
          </select>
        </div>
      </header>

      {state.kind === 'loading' && <p className={styles.state} role="status">Loading the project activity…</p>}
      {state.kind === 'error' && (
        <>
          <div className={styles.error} role="alert">{state.message}</div>
          <div className={styles.actions}>
            <button type="button" className="secondaryButton" onClick={() => void load()}>Retry</button>
          </div>
        </>
      )}
      {state.kind === 'denied' && (
        <div className={styles.error} role="alert">
          Only the project&apos;s owner, and admins reading it by oversight, can see its activity.
        </div>
      )}
      {state.kind === 'unavailable' && (
        <div className={styles.state}>
          <p>
            The activity of this project is not available: the project does not exist, you cannot see it, or
            project sharing is off on this instance.
          </p>
          <Link href="/projects">Back to projects</Link>
        </div>
      )}
      {state.kind === 'ready' && (
        <>
          {state.page.sharesHidden && (
            <p className={styles.notice}>Share changes are hidden from admins by the instance sharing policy.</p>
          )}
          {state.page.events.length === 0 ? (
            <p className={styles.state}>Nothing has been recorded on this project yet.</p>
          ) : (
            <ol className={styles.list} aria-label="Project activity, newest first">
              {state.page.events.map(e => <Row key={e.id} event={e} />)}
            </ol>
          )}
          {state.page.nextCursor && (
            <div className={styles.actions}>
              <button type="button" className="secondaryButton" onClick={() => void loadMore()} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load more'}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

export default ActivityFeed
