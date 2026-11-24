'use client'

import { useCallback, useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Loader2, RotateCw } from 'lucide-react'
import { Modal } from '@/components/ui/Modal/Modal'
import { formatApiError, readApiError, toApiError } from '@/lib/apiError'
import type { ActionContext } from './host/actionClient'
import styles from './SessionSkillPicker.module.css'

/** One row of GET /api/plugins/[pluginId]/session-skills. */
export interface PickerSkill {
  ref: string
  kind: 'builtin' | 'user'
  name: string | null
  turns: number
  exists: boolean
  selectable: boolean
  reason?: 'deleted' | 'credentials' | 'quarantined'
  revision?: number
}

/** What the person picked; the server re-derives everything else from `ref`. */
export interface SessionPick {
  kind: 'session.skill'
  ref: string
  name: string | null
  skillKind: 'builtin' | 'user'
}

const PLUGIN_GONE = new Set(['plugin_not_found', 'plugin_unavailable', 'plugin_updating'])

const REASON: Record<NonNullable<PickerSkill['reason']>, string> = {
  deleted: 'deleted',
  credentials: 'holds a key or token',
  quarantined: 'quarantined',
}

/** Why the agent could not say whether it is running here (the route's `agentCheck`). */
interface AgentCheck {
  code?: string
  upstreamStatus?: number
  cause?: string
}

type Load =
  | { state: 'loading' }
  | { state: 'failed'; message: string }
  | { state: 'unavailable' }
  | { state: 'ready'; running: boolean | 'unverified'; agentCheck?: AgentCheck; skills: PickerSkill[]; suggested: string | null }

const READ_FAILED = 'The skills of this session could not be read'

/** "agent_unreachable · ECONNREFUSED", "agent_error · agent HTTP 500": what to check, in a few words. */
function agentCheckText(check: AgentCheck | undefined): string {
  if (!check) return ''
  const parts = [check.code, check.cause, check.upstreamStatus ? `agent HTTP ${check.upstreamStatus}` : undefined]
    .filter((p): p is string => typeof p === 'string' && /^[\w .:-]{1,64}$/.test(p))
  return parts.length ? ` (${parts.join(' · ')})` : ''
}

/**
 * The core's skill picker (platform 1.1.0), opened by a chat action whose manifest item says
 * `pick: "session.skill"`, before the model gate and the start: the skills the agent used in
 * this session that the plugin may work on, built-in and the person's own. A row that
 * cannot be picked says why. Plugin text is shown React-escaped.
 */
export function SessionSkillPicker({
  pluginId,
  pluginName,
  context,
  onCancel,
  onStart,
}: {
  pluginId: string
  pluginName: string
  context: ActionContext
  onCancel: () => void
  onStart: (pick: SessionPick) => void
}) {
  const queryClient = useQueryClient()
  const [load, setLoad] = useState<Load>({ state: 'loading' })
  const [chosen, setChosen] = useState<string | null>(null)
  const [generation, setGeneration] = useState(0)

  const retry = useCallback(() => setGeneration((g) => g + 1), [])

  useEffect(() => {
    let cancelled = false
    // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch in an effect: each read, and each Retry through generation, starts from the loading state
    setLoad({ state: 'loading' })
    const qs = new URLSearchParams()
    if (context.sessionId) qs.set('sessionId', context.sessionId)
    if (context.projectId) qs.set('projectId', context.projectId)
    fetch(`/api/plugins/${encodeURIComponent(pluginId)}/session-skills?${qs}`)
      .then(async (res) => {
        if (!res.ok) {
          const err = await readApiError(res, READ_FAILED)
          if (cancelled) return
          if (PLUGIN_GONE.has(err.code ?? '')) {
            // The gear menu's list is cached; this plugin should leave it now.
            void queryClient.invalidateQueries({ queryKey: ['plugins', 'contributions'] })
            setLoad({ state: 'unavailable' })
            return
          }
          if (res.status === 404) {
            setLoad({ state: 'failed', message: 'This session was not found. Send the agent a message first, then try again.' })
            return
          }
          setLoad({ state: 'failed', message: err.message })
          return
        }
        const body = await res.json().catch(() => null)
        if (cancelled) return
        if (PLUGIN_GONE.has(body?.code)) {
          // The gear menu's list is cached; this plugin should leave it now.
          void queryClient.invalidateQueries({ queryKey: ['plugins', 'contributions'] })
          setLoad({ state: 'unavailable' })
          return
        }
        if (res.status === 404) {
          setLoad({ state: 'failed', message: 'This session was not found. Send the agent a message first, then try again.' })
          return
        }
        if (!body || !Array.isArray(body.skills)) {
          setLoad({ state: 'failed', message: formatApiError({ reason: READ_FAILED, code: 'invalid_answer', status: res.status }) })
          return
        }
        const skills = body.skills as PickerSkill[]
        const suggested = typeof body.suggested === 'string' ? body.suggested : null
        setLoad({ state: 'ready', running: body.running, agentCheck: body.agentCheck ?? undefined, skills, suggested })
        setChosen(suggested)
      })
      .catch((e) => {
        if (!cancelled) setLoad({ state: 'failed', message: toApiError(e, READ_FAILED).message })
      })
    return () => { cancelled = true }
  }, [pluginId, context.sessionId, context.projectId, generation, queryClient])

  const ready = load.state === 'ready' ? load : null
  // 'unverified': a run is marked but the agent could not be asked, so its end is not known either.
  const running = ready?.running === true
  const unverified = ready?.running === 'unverified'
  const pick = ready?.skills.find((s) => s.ref === chosen && s.selectable) ?? null

  return (
    <Modal
      isOpen
      onClose={onCancel}
      title="Choose a skill"
      className={styles.sheet}
      footer={
        <div className={styles.footer}>
          <button type="button" className="secondaryButton" onClick={onCancel}>Cancel</button>
          <button
            type="button"
            className="primaryButton"
            disabled={!pick || running || unverified}
            onClick={() => pick && onStart({ kind: 'session.skill', ref: pick.ref, name: pick.name, skillKind: pick.kind })}
          >
            Start
          </button>
        </div>
      }
    >
      <p className={styles.intro}>{pluginName} works on one skill the agent used in this session.</p>
      {load.state === 'loading' && (
        <div className={styles.state} role="status"><Loader2 size={14} className={styles.spin} /> Reading the session…</div>
      )}
      {load.state === 'failed' && (
        <div className={styles.state} role="alert">
          {load.message}
          <button type="button" className="secondaryButton" onClick={retry}><RotateCw size={13} /> Retry</button>
        </div>
      )}
      {load.state === 'unavailable' && (
        <div className={styles.state} role="alert">{pluginName} is not available right now.</div>
      )}
      {ready && ready.skills.length === 0 && (
        <div className={styles.state}>This session used no skill {pluginName} can work on.</div>
      )}
      {ready && ready.skills.length > 0 && (
        <>
          {running && (
            <div className={styles.notice} role="status">The agent is still working in this session. Wait until it stops, then start.</div>
          )}
          {unverified && (
            <div className={styles.notice} role="status">
              RedAmon could not confirm that the agent has stopped in this session{agentCheckText(ready.agentCheck)}.
              <button type="button" className="secondaryButton" onClick={retry}><RotateCw size={13} /> Check again</button>
            </div>
          )}
          <div className={styles.list} role="radiogroup" aria-label="Skills used in this session">
            {ready.skills.map((s) => (
              <label key={s.ref} className={`${styles.row} ${s.selectable ? '' : styles.disabled}`} data-testid={`pick-${s.ref}`}>
                <input
                  type="radio"
                  name="session-skill"
                  value={s.ref}
                  checked={chosen === s.ref}
                  disabled={!s.selectable}
                  onChange={() => setChosen(s.ref)}
                />
                <span className={styles.name}>{s.name ?? 'A deleted skill'}</span>
                <span className={styles.meta}>
                  <span className={s.kind === 'builtin' ? styles.badgeBuiltin : styles.badgeUser}>
                    {s.kind === 'builtin' ? 'Built-in' : 'Your skill'}
                  </span>
                  {` · ${s.turns} turn${s.turns === 1 ? '' : 's'}`}
                  {s.kind === 'builtin' && s.revision ? ` · v${s.revision}` : ''}
                  {s.reason ? ` · ${REASON[s.reason]}` : ''}
                </span>
              </label>
            ))}
          </div>
        </>
      )}
    </Modal>
  )
}
