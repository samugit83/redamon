'use client'

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import Link from 'next/link'
import { useAlertModal } from '@/components/ui'
import { ForbiddenNotice, forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import { fetchJson, toApiError } from '@/lib/apiError'
import { scanKindText } from '@/components/settings/api-usage/format'
import type {
  OperationsView, OpsAgentRun, OpsPerson, OpsProject, OpsScan, OpsShell, OpsTriageRun, SourceState,
} from '@/lib/authz/adminOperations'
import { useConsoleSections } from '../AdminConsole'
import { whenLabel } from '../shares/shareWords'
import { ConsoleHeader } from '../ConsoleHeader'
import { SECTION_ICONS } from '../consoleIcons'
import consoleStyles from '../admin.module.css'
import pageStyles from '@/app/settings/users/page.module.css'
import overviewStyles from '../projects/overview.module.css'
import styles from './operations.module.css'

/** How often the view reads the instance again (the spec's 10 s, within the API rate zone). */
const REFRESH_MS = 10_000

type View =
  | { kind: 'loading' }
  | { kind: 'denied'; permission: string }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; data: OperationsView }

const SOURCE_WORDS: Record<string, string> = {
  agent_unreachable: 'the agent did not answer',
  agent_timeout: 'the agent did not answer in time',
  agent_not_ready: 'the agent is still starting, or its INTERNAL_API_KEY is not configured',
  agent_refused: "the agent refused the webapp's internal key",
  agent_route_missing: 'the running agent is older than this view and does not list its sessions; rebuild the agent',
  agent_error: 'the agent answered with an error',
  orchestrator_unreachable: 'the recon orchestrator did not answer',
  orchestrator_timeout: 'the recon orchestrator did not answer in time',
  orchestrator_error: 'the recon orchestrator answered with an error',
}

function SourceDown({ state, what }: { state: SourceState; what: string }) {
  if (state.ok) return null
  return (
    <p className={styles.sourceDown} role="status">
      {what}: {SOURCE_WORDS[state.code] ?? 'the service did not answer'} (<code>{state.code}</code>).
    </p>
  )
}

function Person({ person, linkUsers, fallback = '-' }: { person: OpsPerson | null; linkUsers: boolean; fallback?: string }) {
  if (!person) return <span className={overviewStyles.muted}>{fallback}</span>
  const label = person.name || `Account ${person.id}`
  return linkUsers
    ? <Link href={`/admin/users/${encodeURIComponent(person.id)}`} className={overviewStyles.nameLink}>{label}</Link>
    : <span>{label}</span>
}

function projectName(project: OpsProject | null): string {
  if (!project) return 'No project known'
  return project.name ?? `Deleted project (${project.id})`
}

function ProjectCells({ project, linkUsers }: { project: OpsProject | null; linkUsers: boolean }) {
  return (
    <>
      <td className={pageStyles.td}>{project?.name ?? <span className={overviewStyles.muted}>{projectName(project)}</span>}</td>
      <td className={pageStyles.td}><Person person={project?.owner ?? null} linkUsers={linkUsers} /></td>
    </>
  )
}

/** The person a row acts as, and the administrator behind it when one acted as them. */
function ActorCell({ actor, realActor, linkUsers, fallback }: {
  actor: OpsPerson | null; realActor?: OpsPerson | null; linkUsers: boolean; fallback?: string
}) {
  return (
    <td className={pageStyles.td}>
      <span className={pageStyles.cellStack}>
        <Person person={actor} linkUsers={linkUsers} fallback={fallback} />
        {realActor && <span className={pageStyles.email}>started by <Person person={realActor} linkUsers={linkUsers} /> acting as them</span>}
      </span>
    </td>
  )
}

function When({ iso }: { iso: string | null }) {
  return iso ? <time dateTime={iso}>{whenLabel(iso, '-')}</time> : <span className={overviewStyles.muted}>-</span>
}

function Section({ id, title, count, children }: { id: string; title: string; count?: number; children: ReactNode }) {
  return (
    <section className={styles.section} aria-labelledby={id}>
      <h2 id={id} className={styles.sectionTitle}>
        {title}{count !== undefined && <span className={styles.count}> ({count})</span>}
      </h2>
      <div className={styles.sectionBody}>{children}</div>
    </section>
  )
}

function Table({ label, head, children }: { label: string; head: string[]; children: ReactNode }) {
  return (
    <div className={overviewStyles.tableWrap}>
      <table className={pageStyles.table} aria-label={label}>
        <thead>
          <tr>{head.map((h) => <th key={h} scope="col" className={pageStyles.th}>{h}</th>)}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

function scanKind(s: OpsScan): string {
  return s.detail ? `${scanKindText(s.kind)} · ${s.detail}` : scanKindText(s.kind)
}

/**
 * The admin console's Operations section (step 6.5; GV-06, GV-18): the agent runs, scans, queued scans,
 * triage runs and shell sessions of every user, each with its project's owner and its actor, read again
 * every 10 seconds. Whoever may stop runs (platform:emergency_stop, the server's `actions.stopRuns`)
 * gets the global emergency stop and a stop per running agent run, each behind the app's danger
 * confirmation; their routes decide again. A source that does not answer is named and the rest still
 * show; a failed refresh keeps the last data with a notice. The console shows the denied state to
 * anyone without platform:operations before this page renders.
 */
export default function AdminOperationsPage() {
  const alerts = useAlertModal()
  const sections = useConsoleSections()
  const linkUsers = sections.some((s) => s.id === 'users')
  const [view, setView] = useState<View>({ kind: 'loading' })
  const [refreshError, setRefreshError] = useState('')
  const [refreshing, setRefreshing] = useState(false)
  const [notice, setNotice] = useState('')
  const [stopping, setStopping] = useState<string | null>(null)
  const inFlight = useRef(false)
  const hasData = useRef(false)

  const load = useCallback(async () => {
    if (inFlight.current) return
    inFlight.current = true
    setRefreshing(true)
    try {
      const data = await fetchJson<OperationsView>('/api/admin/operations', { cache: 'no-store' }, 'Could not load the operations view')
      hasData.current = true
      setView({ kind: 'ready', data })
      setRefreshError('')
    } catch (err) {
      const error = toApiError(err, 'Could not load the operations view')
      const permission = forbiddenPermission(error)
      if (permission) {
        hasData.current = false
        setView({ kind: 'denied', permission })
      } else if (hasData.current) {
        setRefreshError(error.message)
      } else {
        setView({ kind: 'error', message: error.message })
      }
    } finally {
      inFlight.current = false
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const timer = setInterval(() => { void load() }, REFRESH_MS)
    return () => clearInterval(timer)
  }, [load])

  async function stopAll() {
    const confirmed = await alerts.dangerConfirm(
      'Every running agent run of every user stops now, with the tool calls it has in flight. Scans and triage runs are not touched.',
      'Stop every agent run',
      { confirmLabel: 'Stop every run' },
    )
    if (!confirmed) return
    setStopping('all')
    try {
      const { scope, stopped } = await fetchJson<{ scope: 'all' | 'own'; stopped: number }>(
        '/api/agent/emergency-stop-all', { method: 'POST' }, 'The emergency stop failed')
      const runs = `${stopped} agent run${stopped === 1 ? '' : 's'}`
      setNotice(scope === 'all'
        ? `Emergency stop: stopped ${runs}.`
        : `You may no longer stop other people's runs: stopped ${runs} of your own.`)
    } catch (err) {
      await alerts.alertError(toApiError(err, 'The emergency stop failed').message, 'Emergency stop failed')
    } finally {
      setStopping(null)
      void load()
    }
  }

  async function stopRun(run: OpsAgentRun) {
    const who = run.actor.name || `account ${run.actor.id}`
    const where = projectName(run.project)
    const confirmed = await alerts.dangerConfirm(
      `${who}'s agent run in ${where} stops now, with the tool calls it has in flight. The conversation is kept.`,
      'Stop this agent run',
      { confirmLabel: 'Stop the run' },
    )
    if (!confirmed) return
    setStopping(run.key)
    try {
      const { stopped } = await fetchJson<{ stopped: boolean }>('/api/admin/operations/agent-runs/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: run.actor.id, projectId: run.project.id, sessionId: run.sessionId }),
      }, 'Could not stop the agent run')
      setNotice(stopped ? `Stopped ${who}'s agent run in ${where}.` : `${who}'s run in ${where} had already ended.`)
    } catch (err) {
      await alerts.alertError(toApiError(err, 'Could not stop the agent run').message, 'Could not stop the run')
    } finally {
      setStopping(null)
      void load()
    }
  }

  const data = view.kind === 'ready' ? view.data : null

  return (
    <div className={consoleStyles.page}>
      <ConsoleHeader
        icon={SECTION_ICONS.operations}
        title="Operations"
        lead={<>What runs on this instance now, whoever started it. The view reads it again every 10 seconds; it shows names only, never a project&apos;s content.</>}
        actions={
          <>
            {data && (
              <p className={styles.updated} aria-live="polite">Updated <time dateTime={data.generatedAt}>{whenLabel(data.generatedAt, '')}</time></p>
            )}
            {data?.actions.stopRuns && (
              <button
                type="button"
                className={`${pageStyles.actionButton} ${pageStyles.deleteButton}`}
                onClick={() => void stopAll()}
                disabled={stopping !== null}
              >
                {stopping === 'all' ? 'Stopping…' : 'Stop every agent run'}
              </button>
            )}
            <button type="button" className={pageStyles.actionButton} onClick={() => void load()} disabled={refreshing}>
              {refreshing ? 'Refreshing…' : 'Refresh now'}
            </button>
          </>
        }
      />
      {refreshError && (
        <p className={styles.refreshError} role="alert">Could not refresh: {refreshError}. The lists below are from the last successful read.</p>
      )}
      {notice && <p className={overviewStyles.notice} role="status">{notice}</p>}

      {view.kind === 'loading' && <p className={consoleStyles.state} role="status">Loading the operations view…</p>}
      {view.kind === 'denied' && <ForbiddenNotice permission={view.permission} />}
      {view.kind === 'error' && (
        <div className={pageStyles.errorState}>
          <div className={pageStyles.error} role="alert">{view.message}</div>
          <button type="button" className={pageStyles.actionButton} onClick={() => void load()}>Retry</button>
        </div>
      )}

      {data && (
        <>
          <Section id="ops-agent-runs" title="Agent runs" count={data.agentRuns.runs.filter((r) => r.running).length}>
            <SourceDown state={data.agentRuns.state} what="Agent runs cannot be listed now" />
            {data.agentRuns.state.ok && (data.agentRuns.runs.length === 0 ? (
              <p className={consoleStyles.state}>No agent session is open and no agent run is in progress.</p>
            ) : (
              <Table label="Agent runs" head={['Project', 'Owner', 'Run by', 'State', 'Actions']}>
                {data.agentRuns.runs.map((run) => (
                  <tr key={run.key} className={pageStyles.tr}>
                    <ProjectCells project={run.project} linkUsers={linkUsers} />
                    <ActorCell actor={run.actor} realActor={run.realActor} linkUsers={linkUsers} />
                    <td className={pageStyles.td}>
                      <span className={pageStyles.cellStack}>
                        <span>{run.running ? 'Running' : 'Idle'}</span>
                        <span className={pageStyles.email}>{run.connected ? 'a tab is open' : 'no tab open'}</span>
                      </span>
                    </td>
                    <td className={pageStyles.td}>
                      {data.actions.stopRuns && run.running && (
                        <button
                          type="button"
                          className={`${pageStyles.actionButton} ${pageStyles.deleteButton}`}
                          aria-label={`Stop ${run.actor.name || run.actor.id}'s agent run in ${projectName(run.project)}`}
                          onClick={() => void stopRun(run)}
                          disabled={stopping !== null}
                        >
                          {stopping === run.key ? 'Stopping…' : 'Stop'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </Table>
            ))}
          </Section>

          <Section id="ops-scans" title="Scans running" count={data.scans.running.length}>
            <SourceDown state={data.scans.orchestrator} what="Only the scans the database records are listed" />
            {data.scans.running.length === 0 ? (
              <p className={consoleStyles.state}>No scan is running.</p>
            ) : (
              <Table label="Scans running" head={['Scan', 'Project', 'Owner', 'Run as', 'Status', 'Started']}>
                {data.scans.running.map((s) => (
                  <tr key={s.key} className={pageStyles.tr}>
                    <td className={pageStyles.td}>{scanKind(s)}</td>
                    <ProjectCells project={s.project} linkUsers={linkUsers} />
                    <ActorCell actor={s.actor} linkUsers={linkUsers} fallback="No person (a schedule or the system)" />
                    <td className={pageStyles.td}>{s.status}</td>
                    <td className={pageStyles.td}><When iso={s.startedAt} /></td>
                  </tr>
                ))}
              </Table>
            )}
          </Section>

          <Section id="ops-queued" title="Queued scans" count={data.scans.queuedTotal}>
            {data.scans.queued.length === 0 ? (
              <p className={consoleStyles.state}>No scan is waiting in the queue.</p>
            ) : (
              <>
                {data.scans.queuedTotal > data.scans.queued.length && (
                  <p className={overviewStyles.count}>Showing the first {data.scans.queued.length} of {data.scans.queuedTotal}, in the order they will start.</p>
                )}
                <Table label="Queued scans" head={['Scan', 'Project', 'Owner', 'Run as', 'Status', 'Queued']}>
                  {data.scans.queued.map((s) => (
                    <tr key={s.key} className={pageStyles.tr}>
                      <td className={pageStyles.td}>{scanKind(s)}</td>
                      <ProjectCells project={s.project} linkUsers={linkUsers} />
                      <ActorCell actor={s.actor} linkUsers={linkUsers} fallback="No person (a schedule or the system)" />
                      <td className={pageStyles.td}>
                        <span className={pageStyles.cellStack}>
                          <span>{s.status === 'needs_review' ? 'Needs review' : 'Queued'}</span>
                          {s.blockedReason && <span className={pageStyles.email}>{s.blockedReason}</span>}
                        </span>
                      </td>
                      <td className={pageStyles.td}><When iso={s.enqueuedAt} /></td>
                    </tr>
                  ))}
                </Table>
              </>
            )}
          </Section>

          <Section id="ops-triage" title="Triage runs" count={data.triageRuns.length}>
            {data.triageRuns.length === 0 ? (
              <p className={consoleStyles.state}>No triage run is in progress.</p>
            ) : (
              <Table label="Triage runs" head={['Project', 'Owner', 'Run by', 'Started from', 'Progress', 'Started']}>
                {data.triageRuns.map((r: OpsTriageRun) => (
                  <tr key={r.id} className={pageStyles.tr}>
                    <ProjectCells project={r.project} linkUsers={linkUsers} />
                    <ActorCell actor={r.actor} realActor={r.realActor} linkUsers={linkUsers} />
                    <td className={pageStyles.td}>{r.trigger === 'mcp' ? 'An MCP client' : 'The app'}</td>
                    <td className={pageStyles.td}>{r.status === 'publishing' ? 'Publishing' : `${r.phase || 'Running'} · ${r.progress}%`}</td>
                    <td className={pageStyles.td}><When iso={r.startedAt} /></td>
                  </tr>
                ))}
              </Table>
            )}
          </Section>

          <Section id="ops-shells" title="Shell sessions" count={data.shells.sessions.length}>
            <SourceDown state={data.shells.state} what="Shell sessions cannot be listed now" />
            {data.shells.state.ok && (data.shells.sessions.length === 0 ? (
              <p className={consoleStyles.state}>No shell session or listener is open.</p>
            ) : (
              <Table label="Shell sessions" head={['Session', 'Project', 'Owner', 'Opened from the chat of']}>
                {data.shells.sessions.map((s: OpsShell) => (
                  <tr key={s.key} className={pageStyles.tr}>
                    <td className={pageStyles.td}>{s.kind === 'listener' ? 'Listener' : 'Session'} {s.id} · {s.type}</td>
                    <ProjectCells project={s.project} linkUsers={linkUsers} />
                    <td className={pageStyles.td}><Person person={s.person} linkUsers={linkUsers} /></td>
                  </tr>
                ))}
              </Table>
            ))}
            {data.shells.state.ok && data.shells.jobs > 0 && (
              <p className={overviewStyles.count}>{data.shells.jobs} background job{data.shells.jobs === 1 ? '' : 's'} (handlers) running in the shared Metasploit console.</p>
            )}
          </Section>
        </>
      )}
    </div>
  )
}
