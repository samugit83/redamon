'use client'

import { useId, useMemo, useState, type FormEvent } from 'react'
import { Modal } from '@/components/ui'
import { NOT_HELD_SUFFIX } from '@/components/admin/PermissionPicker'
import { fetchJson, toApiError } from '@/lib/apiError'
import { PERMISSIONS, type PermissionId } from '@/lib/authz/permissions'
import {
  MAX_DESCRIPTION, MAX_NAME, addable, addedBy, cloneStart, createBody, editBody, passwordNeeded, pickableAreas,
  type Draft, type SetKind, type SetRow,
} from './setModel'
import { SET_WORDS } from './setWords'
import pageStyles from '@/app/settings/users/page.module.css'
import choiceStyles from '@/components/admin/UserPermissions.module.css'
import styles from './sets.module.css'

export type EditorMode = { kind: 'create'; source?: SetRow } | { kind: 'edit'; set: SetRow }

interface SetEditorProps {
  kind: SetKind
  mode: EditorMode
  /** What the signed-in person may give (permissionModel.ts `givableFrom`). */
  givable: ReadonlySet<PermissionId>
  onClose: () => void
  /** Saved: the line the page shows. */
  onSaved: (message: string) => void
}

interface PutAnswer {
  set?: { name?: string }
  changed?: boolean
  added?: string[]
  removed?: string[]
  signedOut?: number
}

const JSON_HEADERS = { 'Content-Type': 'application/json' }

function startOf(mode: EditorMode, givable: ReadonlySet<PermissionId>): { draft: Draft; leftOut: PermissionId[] } {
  if (mode.kind === 'edit') {
    return { draft: { name: mode.set.name, description: mode.set.description ?? '', permissions: [...mode.set.permissions] }, leftOut: [] }
  }
  if (mode.source) return cloneStart(mode.source, givable)
  return { draft: { name: '', description: '', permissions: [] }, leftOut: [] }
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

function savedLine(name: string, answer: PutAnswer): string {
  if (answer.changed === false) return `Nothing changed in ${name}.`
  const signedOut = answer.signedOut ?? 0
  return `Saved ${name}: ${answer.added?.length ?? 0} added, ${answer.removed?.length ?? 0} removed.${signedOut
    ? ` ${plural(signedOut, 'holder')} lost a permission and ${signedOut === 1 ? 'was' : 'were'} signed out.`
    : ''}`
}

/**
 * Creates, clones or edits a set or profile (step 6.3; GV-02, GV-03; PE-11). The permissions it may
 * hold are listed by area; one the editor may not give is disabled with the reason in its label,
 * unless the set already holds it (keeping or removing it adds nothing). It asks for the editor's
 * password where the server takes it: every profile write (the confirmed Root's), and a member set
 * edit that adds a dangerous permission (ID-25). The server decides; its refusal shows here as it came.
 */
export function SetEditor({ kind, mode, givable, onClose, onSaved }: SetEditorProps) {
  const uid = useId()
  const words = SET_WORDS[kind]
  const [start] = useState(() => startOf(mode, givable))
  const [draft, setDraft] = useState<Draft>(start.draft)
  const [password, setPassword] = useState('')
  const [askedByServer, setAskedByServer] = useState(false)
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  const original = mode.kind === 'edit' ? mode.set.permissions : []
  const groups = useMemo(() => pickableAreas(kind), [kind])
  const added = addedBy(original, draft.permissions)
  const needed = passwordNeeded(kind, mode.kind, added)
  const askPassword = needed !== null || askedByServer
  const body = mode.kind === 'edit' ? editBody(mode.set, draft) : createBody(draft, mode.source?.id)

  function toggle(permission: PermissionId, on: boolean) {
    setError('')
    setDraft((d) => ({ ...d, permissions: on ? [...d.permissions, permission] : d.permissions.filter((p) => p !== permission) }))
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (pending || !body) return
    if (!draft.name.trim()) {
      setError(`Give the ${words.short} a name.`)
      return
    }
    if (askPassword && !password) {
      setError('Enter your password to confirm this change.')
      return
    }
    setError('')
    setPending(true)
    const edit = mode.kind === 'edit'
    try {
      const answer = await fetchJson<PutAnswer>(edit ? words.itemUrl(mode.set.id) : words.listUrl, {
        method: edit ? 'PUT' : 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify(askPassword ? { ...body, stepUpPassword: password } : body),
      }, edit ? `Could not change the ${words.one}` : `Could not create the ${words.one}`)
      onSaved(edit ? savedLine(mode.set.name, answer) : `Created ${draft.name.trim()}.`)
      onClose()
    } catch (err) {
      const refusal = toApiError(err, `The ${words.one} was not saved`)
      if (refusal.code === 'step_up_required') setAskedByServer(true)
      setError(refusal.message)
      setPending(false)
    }
  }

  const title = mode.kind === 'edit' ? `Edit ${mode.set.name}` : mode.source ? `Clone ${mode.source.name}` : `New ${words.one}`
  const ids = { name: `${uid}-name`, description: `${uid}-description`, password: `${uid}-password` }

  return (
    <Modal isOpen onClose={pending ? () => {} : onClose} title={title} size="large">
      <form className={styles.editor} onSubmit={submit} noValidate>
        {error && <div className={pageStyles.error} role="alert">{error}</div>}
        <div className={pageStyles.field}>
          <label className={pageStyles.label} htmlFor={ids.name}>Name</label>
          <input
            id={ids.name}
            className={pageStyles.input}
            value={draft.name}
            maxLength={MAX_NAME}
            onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
            disabled={pending}
            required
          />
        </div>
        <div className={pageStyles.field}>
          <label className={pageStyles.label} htmlFor={ids.description}>Description</label>
          <textarea
            id={ids.description}
            className={`${pageStyles.input} ${styles.textarea}`}
            value={draft.description}
            maxLength={MAX_DESCRIPTION}
            onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
            disabled={pending}
          />
        </div>

        <fieldset className={choiceStyles.section}>
          <legend className={choiceStyles.sectionTitle}>Permissions</legend>
          <span className={pageStyles.hint}>{words.pickHint}</span>
          {start.leftOut.length > 0 && (
            <span className={choiceStyles.refusal}>Left out because you do not hold them: {start.leftOut.join(', ')}.</span>
          )}
          <div className={styles.permissionChoices}>
            {groups.map(({ area, permissions }) => (
              <div key={area.id} className={choiceStyles.area}>
                <p className={choiceStyles.areaTitle}>{area.title}</p>
                {permissions.map((p) => {
                  const refused = !addable(p, original, givable)
                  const checked = draft.permissions.includes(p)
                  const hint = `${uid}-${p}`
                  return (
                    <div key={p} className={choiceStyles.item}>
                      <label className={choiceStyles.choice}>
                        <input
                          type="checkbox"
                          checked={checked}
                          disabled={pending || (refused && !checked)}
                          onChange={(e) => toggle(p, e.target.checked)}
                          aria-describedby={hint}
                        />
                        <span className={choiceStyles.permission}>{p}{refused ? NOT_HELD_SUFFIX : ''}</span>
                      </label>
                      <span id={hint} className={choiceStyles.description}>{PERMISSIONS[p].description}</span>
                    </div>
                  )
                })}
              </div>
            ))}
          </div>
        </fieldset>

        {askPassword && (
          <div className={pageStyles.field}>
            <label className={pageStyles.label} htmlFor={ids.password}>Your password</label>
            <input
              id={ids.password}
              type="password"
              className={pageStyles.input}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              disabled={pending}
              aria-describedby={`${ids.password}-why`}
            />
            <span id={`${ids.password}-why`} className={pageStyles.hint}>
              {needed === 'root'
                ? 'Every change to an admin profile is Root\'s and takes your password.'
                : needed
                  ? `This change adds ${needed.join(', ')}. Adding a cross-tenant tool, an exploitation approval, shell sessions or Kali commands takes your own password.`
                  : 'Confirm this change with your own password.'}
            </span>
          </div>
        )}

        <div className={pageStyles.modalActions}>
          <button type="button" className={pageStyles.actionButton} onClick={onClose} disabled={pending}>Cancel</button>
          <button type="submit" className="primaryButton" disabled={pending || !body}>
            {pending ? 'Saving…' : mode.kind === 'edit' ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
