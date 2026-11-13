'use client'

import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Modal, useAlertModal } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { errorMessage, readApiError, toApiError } from '@/lib/apiError'
import type { RbacFlags } from '@/lib/authz/flags'
import type { DeletionPerson, DeletionPlan, SharedProjectPlan } from '@/lib/authz/userDeletion'
import styles from './DeleteUserWizard.module.css'

/** The wizard replaces the plain delete confirmation only with write sharing switched on (DV-30). */
export function deletionWizardInForce(flags: Readonly<RbacFlags> | null): boolean {
  return flags?.sharingWrite === true
}

type Mode = 'offer' | 'force' | 'delete'
type Choice = { mode: Mode | null; toUserId: string }
type Pending =
  | { kind: 'offer' | 'force'; project: SharedProjectPlan; toUserId: string }
  | { kind: 'cancel'; project: SharedProjectPlan }
  | { kind: 'delete' }

interface Props {
  isOpen: boolean
  userId: string
  userName: string
  /** Another admin's account: its deletion and the actions on its projects take the deleter's own password. */
  targetIsAdmin: boolean
  onClose: () => void
  onDeleted: () => void
}

const who = (p: DeletionPerson | null | undefined) => (p ? p.name || p.email || p.id : 'someone')
const day = (iso: string) => new Date(iso).toLocaleDateString()
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

/**
 * Deleting an account (step 5.13; SH-16, SH-17): the deletion plan says what the deletion does, and each
 * project the account shares with other people is resolved first: offered to a collaborator (they accept
 * or decline), given now by Root without the acceptance, or deleted anyway. The delete stays disabled
 * until every shared project is resolved; the server refuses it too (409 deletion_plan_unresolved).
 */
export function DeleteUserWizard({ isOpen, userId, userName, targetIsAdmin, onClose, onDeleted }: Props) {
  const { confirm, dangerConfirm } = useAlertModal()
  const [plan, setPlan] = useState<DeletionPlan | null>(null)
  const [state, setState] = useState<'loading' | 'ready' | 'error' | 'denied'>('loading')
  const [loadError, setLoadError] = useState('')
  const [choices, setChoices] = useState<Record<string, Choice>>({})
  const [actionError, setActionError] = useState('')
  const [status, setStatus] = useState('')
  const [pending, setPending] = useState<Pending | null>(null)
  const [deleting, setDeleting] = useState(false)

  const load = useCallback(async () => {
    setState((s) => (s === 'ready' ? s : 'loading'))
    try {
      const res = await fetch(`/api/users/${encodeURIComponent(userId)}/deletion-plan`, { cache: 'no-store' })
      if (!res.ok) {
        const err = await readApiError(res, 'Could not read what this deletion does')
        setLoadError(err.message)
        setState(res.status === 403 ? 'denied' : 'error')
        return
      }
      const body = await res.json() as { plan: DeletionPlan }
      setPlan(body.plan)
      setState('ready')
    } catch (err) {
      setLoadError(errorMessage(err, 'Could not read what this deletion does'))
      setState('error')
    }
  }, [userId])

  useEffect(() => {
    if (!isOpen) return
    setPlan(null)
    setChoices({})
    setActionError('')
    setStatus('')
    setState('loading')
    void load()
  }, [isOpen, load])

  const choiceOf = (projectId: string): Choice => choices[projectId] ?? { mode: null, toUserId: '' }
  const choose = (projectId: string, change: Partial<Choice>) =>
    setChoices((all) => ({ ...all, [projectId]: { ...choiceOf(projectId), ...change } }))

  const shared = plan?.sharedProjects ?? []
  const deleteAnyway = shared.filter((p) => !p.offer && choiceOf(p.id).mode === 'delete')
  const resolved = shared.every((p) => !p.offer && choiceOf(p.id).mode === 'delete')

  async function act(body: Record<string, unknown>): Promise<void> {
    const res = await fetch(`/api/users/${encodeURIComponent(userId)}/deletion-plan`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    })
    if (!res.ok) throw await readApiError(res, 'The deletion plan could not be changed')
  }

  async function runPending(password?: string): Promise<void> {
    if (!pending) return
    if (pending.kind === 'delete') {
      await runDelete(password)
      return
    }
    const { project } = pending
    const recipient = pending.kind === 'cancel' ? null : project.collaborators.find((c) => c.id === pending.toUserId)
    await act({
      action: pending.kind, projectId: project.id,
      ...(pending.kind === 'cancel' ? {} : { toUserId: pending.toUserId }),
      ...(password ? { stepUpPassword: password } : {}),
    })
    setStatus(pending.kind === 'offer'
      ? `${project.name} was offered to ${who(recipient)}. The account can be deleted once they accept, or once you choose otherwise.`
      : pending.kind === 'force'
        ? `${project.name} now belongs to ${who(recipient)}.`
        : `The offer of ${project.name} was withdrawn.`)
    setActionError('')
    await load()
  }

  async function withdraw(project: SharedProjectPlan) {
    if (targetIsAdmin) {
      setPending({ kind: 'cancel', project })
      return
    }
    const ok = await confirm(`Withdraw the offer of ${project.name} to ${who(project.offer?.to)}?`, 'Withdraw the offer', { confirmLabel: 'Withdraw' })
    if (!ok) return
    try {
      await act({ action: 'cancel', projectId: project.id })
      setStatus(`The offer of ${project.name} was withdrawn.`)
      setActionError('')
      await load()
    } catch (err) {
      setActionError(errorMessage(err, 'The offer could not be withdrawn'))
    }
  }

  async function runDelete(password?: string): Promise<void> {
    setDeleting(true)
    try {
      const res = await fetch(`/api/users/${encodeURIComponent(userId)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ deleteAnyway: deleteAnyway.map((p) => p.id), ...(password ? { stepUpPassword: password } : {}) }),
      })
      if (!res.ok) {
        const err = await readApiError(res, 'Could not delete the user')
        // Shared since the plan was read, or an offer accepted meanwhile: show the plan as it is now.
        if (err.code === 'deletion_plan_unresolved') await load()
        throw err
      }
      onDeleted()
    } finally {
      setDeleting(false)
    }
  }

  async function startDelete() {
    if (deleteAnyway.length > 0) {
      const ok = await dangerConfirm(
        <div>
          <p>These projects are shared, and their collaborators lose them with everything they hold:</p>
          <ul>{deleteAnyway.map((p) => <li key={p.id}>{p.name}</li>)}</ul>
        </div>,
        'Delete shared projects anyway?',
        { confirmLabel: 'Delete them with the account' },
      )
      if (!ok) return
    }
    if (targetIsAdmin) {
      setPending({ kind: 'delete' })
      return
    }
    try {
      await runDelete()
    } catch (err) {
      setActionError(toApiError(err, 'Could not delete the user').message)
    }
  }

  // `pending` is set only for an action that takes the admin's own password.
  const stepUp = pending
  const stepUpText: Record<Pending['kind'], { title: string; message: ReactNode; confirm: string }> = {
    offer: { title: 'Offer the project', message: 'Confirm the offer with your own password.', confirm: 'Send the offer' },
    force: {
      title: 'Transfer without acceptance',
      message: 'The project goes to the collaborator now, without their acceptance. Confirm with your own (Root) password.',
      confirm: 'Transfer now',
    },
    cancel: { title: 'Withdraw the offer', message: 'Confirm with your own password.', confirm: 'Withdraw' },
    delete: { title: 'Delete an admin', message: `Delete ${userName}, an admin account? Confirm with your own password.`, confirm: 'Delete the account' },
  }

  return (
    <>
      <Modal isOpen={isOpen && !stepUp} onClose={deleting ? () => {} : onClose} title={`Delete ${userName}`} size="large">
        <div className={styles.wizard}>
          {state === 'loading' && <p className={styles.state} role="status">Reading what this deletion does…</p>}
          {state === 'denied' && (
            <p className={styles.error} role="alert">You cannot delete this account: {loadError}</p>
          )}
          {state === 'error' && (
            <div className={styles.error} role="alert">
              <span>{loadError}</span>{' '}
              <button type="button" className={styles.button} onClick={() => void load()}>Try again</button>
            </div>
          )}
          {state === 'ready' && plan && (
            <>
              <p className={styles.hint}>{plan.account.email}</p>
              <div aria-live="polite">
                {status && <p className={styles.status}>{status}</p>}
                {actionError && <p className={styles.error} role="alert">{actionError}</p>}
              </div>

              <section aria-labelledby="del-shared">
                <h3 id="del-shared" className={styles.heading}>Shared projects</h3>
                {shared.length === 0
                  ? <p className={styles.state}>None: no project of this account is shared with anyone.</p>
                  : <p className={styles.hint}>Decide what happens to each before the account can be deleted.</p>}
                {!plan.transfers.available && shared.length > 0 && (
                  <p className={styles.hint}>Root&apos;s sharing policy is at Read only, so these projects cannot change owner: they can only be deleted.</p>
                )}
                {shared.map((p) => (
                  <SharedProject
                    key={p.id}
                    project={p}
                    choice={choiceOf(p.id)}
                    transfersAvailable={plan.transfers.available}
                    mayForce={plan.transfers.mayForce}
                    onChoose={(change) => choose(p.id, change)}
                    onSend={(kind, toUserId) => setPending({ kind, project: p, toUserId })}
                    onWithdraw={() => void withdraw(p)}
                  />
                ))}
              </section>

              <section aria-labelledby="del-unshared">
                <h3 id="del-unshared" className={styles.heading}>Deleted with the account</h3>
                {plan.unsharedProjects.length === 0
                  ? <p className={styles.state}>No other project.</p>
                  : (
                    <ul className={styles.list}>
                      {plan.unsharedProjects.map((p) => (
                        <li key={p.id}>{p.name}{p.running ? <span className={styles.hint}> (running now: {p.running}; it is stopped)</span> : null}</li>
                      ))}
                    </ul>
                  )}
              </section>

              <section aria-labelledby="del-elsewhere">
                <h3 id="del-elsewhere" className={styles.heading}>Shares in other people&apos;s projects</h3>
                {plan.memberships.length === 0
                  ? <p className={styles.state}>None.</p>
                  : (
                    <ul className={styles.list}>
                      {plan.memberships.map((m) => (
                        <li key={m.project.id}>{m.project.name} <span className={styles.hint}>(owned by {who(m.owner)}, {m.access === 'write' ? 'Read + Write' : 'Read'}): ends with the account</span></li>
                      ))}
                    </ul>
                  )}
              </section>

              <section aria-labelledby="del-also">
                <h3 id="del-also" className={styles.heading}>Also</h3>
                <ul className={styles.list}>
                  <li>{plural(plan.conversationsReassigned, 'conversation')} in other people&apos;s projects stay there, with their project&apos;s owner.</li>
                  <li>
                    {plan.liveWork.agentRuns === null ? 'Agent runs (the agent could not say how many)' : plural(plan.liveWork.agentRuns, 'agent run')} stopped,{' '}
                    {plural(plan.liveWork.queuedScans, 'queued scan')} cancelled, {plural(plan.liveWork.schedules, 'schedule')} paused.
                  </li>
                  <li>{plural(plan.endsWithAccount.mcpTokens, 'MCP token')} and {plural(plan.endsWithAccount.deviceSessions, 'device session')} end with the account.</li>
                  <li>{plural(plan.endsWithAccount.nucleiTemplates, 'own Nuclei template')} move to you.</li>
                  <li>The deletion is recorded in the audit log.</li>
                </ul>
              </section>

              <div className={styles.actions}>
                <button type="button" className={styles.button} onClick={() => void load()} disabled={deleting}>Refresh</button>
                <button type="button" className={styles.button} onClick={onClose} disabled={deleting}>Cancel</button>
                <button
                  type="button"
                  className={`${styles.button} ${styles.danger}`}
                  onClick={() => void startDelete()}
                  disabled={!resolved || deleting}
                  aria-describedby={resolved ? undefined : 'del-unresolved'}
                >
                  {deleting ? 'Deleting…' : 'Delete the account'}
                </button>
              </div>
              {!resolved && <p id="del-unresolved" className={styles.hint}>Resolve each shared project first.</p>}
            </>
          )}
        </div>
      </Modal>

      <StepUpModal
        isOpen={!!stepUp}
        title={stepUp ? stepUpText[stepUp.kind].title : ''}
        message={stepUp ? stepUpText[stepUp.kind].message : ''}
        confirmLabel={stepUp ? stepUpText[stepUp.kind].confirm : ''}
        onConfirm={async (password) => runPending(password)}
        onClose={() => setPending(null)}
      />
    </>
  )
}

function SharedProject({ project, choice, transfersAvailable, mayForce, onChoose, onSend, onWithdraw }: {
  project: SharedProjectPlan
  choice: Choice
  transfersAvailable: boolean
  mayForce: boolean
  onChoose: (change: Partial<Choice>) => void
  onSend: (kind: 'offer' | 'force', toUserId: string) => void
  onWithdraw: () => void
}) {
  const active = project.collaborators.filter((c) => c.active)
  const canGive = transfersAvailable && active.length > 0
  const name = `del-choice-${project.id}`
  const selectId = `del-to-${project.id}`
  const { offer } = project
  return (
    <fieldset className={styles.project}>
      <legend className={styles.legend}>{project.name}</legend>
      <p className={styles.hint}>
        Shared with {project.collaborators.map((c) => `${who(c)}${c.active ? '' : ' (inactive)'}`).join(', ')}
      </p>
      {project.running && <p className={styles.hint}>Running now: {project.running}. A transfer waits for it to end.</p>}
      {offer ? (
        <div className={styles.offer}>
          <span>
            Offered to {who(offer.to)}: {offer.status === 'failed'
              ? `the last attempt failed (${offer.error ?? 'unknown'}); they can accept again`
              : `waiting for their answer until ${day(offer.expiresAt)}`}.
          </span>
          <button type="button" className={styles.button} onClick={onWithdraw}>Withdraw the offer</button>
        </div>
      ) : (
        <div className={styles.choices}>
          <label className={styles.radio}>
            <input type="radio" name={name} value="offer" checked={choice.mode === 'offer'} disabled={!canGive}
              onChange={() => onChoose({ mode: 'offer' })} />
            Offer it to a collaborator (they accept or decline)
          </label>
          {mayForce && (
            <label className={styles.radio}>
              <input type="radio" name={name} value="force" checked={choice.mode === 'force'} disabled={!canGive}
                onChange={() => onChoose({ mode: 'force' })} />
              Give it to a collaborator now, without their acceptance (Root)
            </label>
          )}
          <label className={styles.radio}>
            <input type="radio" name={name} value="delete" checked={choice.mode === 'delete'}
              onChange={() => onChoose({ mode: 'delete' })} />
            Delete it anyway with the account
          </label>
          {(choice.mode === 'offer' || choice.mode === 'force') && (
            <div className={styles.send}>
              <label htmlFor={selectId}>Collaborator</label>
              <select id={selectId} value={choice.toUserId} onChange={(e) => onChoose({ toUserId: e.target.value })}>
                <option value="">Choose…</option>
                {active.map((c) => <option key={c.id} value={c.id}>{who(c)}</option>)}
              </select>
              <button type="button" className={styles.button} disabled={!choice.toUserId}
                onClick={() => onSend(choice.mode as 'offer' | 'force', choice.toUserId)}>
                {choice.mode === 'offer' ? 'Send the offer' : 'Transfer now'}
              </button>
            </div>
          )}
        </div>
      )}
    </fieldset>
  )
}
