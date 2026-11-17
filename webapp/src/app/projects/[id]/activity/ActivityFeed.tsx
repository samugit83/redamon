'use client'

import Link from 'next/link'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Bot, Bug, Cog, Eye, FolderOpen, History, Inbox, KeyRound, ListFilter, Loader2, Lock, Plug, Radar, Server,
  Share2, SlidersHorizontal, UserCog, EyeOff, type LucideIcon,
} from 'lucide-react'
import { useAlertModal } from '@/components/ui'
import { IdentityLabel } from '@/components/auth/IdentityLabel'
import { ConsoleHeader } from '@/app/admin/ConsoleHeader'
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

type Tone = 'neutral' | 'info' | 'warning' | 'success' | 'danger' | 'violet' | 'cyan'

/** Admin access and acting-as are the rows an owner most needs to spot, so they carry the warning tone. */
const GROUP_LOOK: Record<AuditGroup, { icon: LucideIcon; tone: Tone }> = {
  sharing: { icon: Share2, tone: 'info' },
  oversight: { icon: Eye, tone: 'warning' },
  acting: { icon: UserCog, tone: 'warning' },
  project: { icon: SlidersHorizontal, tone: 'neutral' },
  scans: { icon: Radar, tone: 'success' },
  findings: { icon: Bug, tone: 'danger' },
  agent: { icon: Bot, tone: 'violet' },
  mcp: { icon: Plug, tone: 'cyan' },
  accounts: { icon: KeyRound, tone: 'neutral' },
  platform: { icon: Server, tone: 'neutral' },
  system: { icon: Cog, tone: 'neutral' },
}
const UNKNOWN_LOOK = { icon: History, tone: 'neutral' as Tone }

const TONE_CLASS: Record<Tone, string> = {
  neutral: styles.toneNeutral, info: styles.toneInfo, warning: styles.toneWarning, success: styles.toneSuccess,
  danger: styles.toneDanger, violet: styles.toneViolet, cyan: styles.toneCyan,
}

/** The local calendar day, so rows group by the day the reader lives in, not by UTC. */
function dayKey(d: Date): string {
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}

function dayLabel(d: Date, now: Date): string {
  if (dayKey(d) === dayKey(now)) return 'Today'
  const yesterday = new Date(now)
  yesterday.setDate(now.getDate() - 1)
  if (dayKey(d) === dayKey(yesterday)) return 'Yesterday'
  return d.toLocaleDateString(undefined, {
    weekday: 'long', month: 'long', day: 'numeric', ...(d.getFullYear() === now.getFullYear() ? {} : { year: 'numeric' }),
  })
}

function byDay(events: ActivityEvent[]): { key: string; label: string; events: ActivityEvent[] }[] {
  const now = new Date()
  const days: { key: string; label: string; events: ActivityEvent[] }[] = []
  for (const event of events) {
    const at = new Date(event.at)
    const key = dayKey(at)
    const last = days[days.length - 1]
    if (last && last.key === key) last.events.push(event)
    else days.push({ key, label: dayLabel(at, now), events: [event] })
  }
  return days
}

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
  const look = event.group ? GROUP_LOOK[event.group] : UNKNOWN_LOOK
  const Icon = look.icon
  const at = new Date(event.at)
  return (
    <li className={`${styles.item} ${TONE_CLASS[look.tone]}`}>
      <span className={styles.marker} aria-hidden="true"><Icon size={15} strokeWidth={1.9} /></span>
      <div className={styles.body}>
        <div className={styles.headline}>
          <span className={styles.label}>{event.label}</span>
          {event.group && <span className={styles.group}>{AUDIT_GROUPS[event.group]}</span>}
          {event.source === 'mcp' && <span className={styles.tag}><Plug size={11} aria-hidden="true" />through MCP</span>}
        </div>
        <div className={styles.people}>
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
        </div>
      </div>
      <time className={styles.when} dateTime={event.at} title={at.toLocaleString()}>
        {at.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })}
      </time>
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
  const events = state.kind === 'ready' ? state.page.events : null
  const days = useMemo(() => (events ? byDay(events) : []), [events])

  return (
    <section className={styles.feed} aria-labelledby="project-activity-title">
      <ConsoleHeader
        icon={History}
        title={(
          <span id="project-activity-title" className={styles.title}>
            Activity
            {projectName && (
              <>
                {' '}
                <span className={styles.project}><FolderOpen size={14} aria-hidden="true" />{projectName}</span>
              </>
            )}
          </span>
        )}
        lead="Who did what on this project, newest first."
        actions={(
          <div className={styles.filter}>
            <label htmlFor="project-activity-group" className={styles.filterLabel}>
              <ListFilter size={14} aria-hidden="true" />Show
            </label>
            <select
              id="project-activity-group"
              className={`select ${styles.select}`}
              value={group}
              onChange={e => setGroup(e.target.value as AuditGroup | '')}
            >
              <option value="">All activity</option>
              {AUDIT_GROUP_IDS.map(id => <option key={id} value={id}>{AUDIT_GROUPS[id]}</option>)}
            </select>
          </div>
        )}
      />

      <div className={styles.card}>
        {state.kind === 'loading' && (
          <p className={styles.state} role="status">
            <Loader2 size={16} className={styles.spin} aria-hidden="true" />Loading the project activity…
          </p>
        )}
        {state.kind === 'error' && (
          <div className={styles.callout}>
            <div className={styles.error} role="alert">{state.message}</div>
            <button type="button" className="secondaryButton" onClick={() => void load()}>Retry</button>
          </div>
        )}
        {state.kind === 'denied' && (
          <div className={styles.empty}>
            <span className={styles.emptyIcon} aria-hidden="true"><Lock size={20} /></span>
            <p className={styles.emptyTitle} role="alert">
              Only the project&apos;s owner, and admins reading it by oversight, can see its activity.
            </p>
          </div>
        )}
        {state.kind === 'unavailable' && (
          <div className={styles.empty}>
            <span className={styles.emptyIcon} aria-hidden="true"><Inbox size={20} /></span>
            <p className={styles.emptyText}>
              The activity of this project is not available: the project does not exist, you cannot see it, or
              project sharing is off on this instance.
            </p>
            <Link className={styles.emptyLink} href="/projects">Back to projects</Link>
          </div>
        )}
        {state.kind === 'ready' && (
          <>
            {state.page.sharesHidden && (
              <div className={styles.notice}>
                <EyeOff size={15} aria-hidden="true" />
                <p>Share changes are hidden from admins by the instance sharing policy.</p>
              </div>
            )}
            {state.page.events.length === 0 ? (
              <div className={styles.empty}>
                <span className={styles.emptyIcon} aria-hidden="true"><Inbox size={20} /></span>
                <p className={styles.emptyTitle}>Nothing has been recorded on this project yet.</p>
                <p className={styles.emptyText}>Changes, scans, sharing and admin access will be listed here as they happen.</p>
              </div>
            ) : (
              days.map(day => (
                <section key={day.key} className={styles.day} aria-labelledby={`activity-day-${day.key}`}>
                  <h2 id={`activity-day-${day.key}`} className={styles.dayHeading}>
                    <span>{day.label}</span>
                    <span className={styles.dayCount}>{day.events.length} {day.events.length === 1 ? 'event' : 'events'}</span>
                  </h2>
                  <ol className={styles.list}>
                    {day.events.map(e => <Row key={e.id} event={e} />)}
                  </ol>
                </section>
              ))
            )}
            {state.page.events.length > 0 && (
              <div className={styles.footer}>
                <span className={styles.footerCount}>
                  {state.page.nextCursor ? 'Showing' : 'Showing all'} {state.page.events.length} {state.page.events.length === 1 ? 'event' : 'events'}
                </span>
                {state.page.nextCursor && (
                  <button type="button" className="secondaryButton" onClick={() => void loadMore()} disabled={loadingMore}>
                    {loadingMore ? 'Loading…' : 'Load more'}
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </section>
  )
}

export default ActivityFeed
