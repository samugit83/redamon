'use client'

import { useId } from 'react'
import { Plus, X } from 'lucide-react'
import { useOptionalAuth } from '@/providers/AuthProvider'
import type { MaskedCredentials } from '@/lib/tradecraft/masking'
import { FormSection } from './FormSection'
import css from '../tradecraft.module.css'
import fcss from './form.module.css'

/** The placeholder every tradecraft answer shows for a stored secret; sent back, it keeps the value. */
const SET = 'set'
export const LOGIN_NOTE = 'A resource with a login is read without the browser, and only from its own map: its pages go to nobody but you.'
export const HEADERS_MAX = 20

/**
 * The Access section as the form holds it. A secret is `'set'` while the stored value is kept;
 * anything else is what the person typed. The GitHub token override is '' until one is typed.
 */
export interface AccessDraft {
  githubToken: string
  cookie: string
  headers: { name: string; value: string }[]
  basic: { username: string; password: string } | null
}

export function accessDraftOf(credentials: MaskedCredentials | undefined): AccessDraft {
  return {
    githubToken: '',
    cookie: credentials?.cookie === SET ? SET : '',
    headers: (credentials?.headers ?? []).map(h => ({ name: h.name, value: h.value === SET ? SET : '' })),
    basic: credentials?.basic_auth ? { username: credentials.basic_auth.username, password: credentials.basic_auth.password === SET ? SET : '' } : null,
  }
}

function loginOf(d: AccessDraft) {
  const headers = d.headers.filter(h => h.name.trim() || h.value)
  return { cookie: d.cookie, headers: headers.map(h => ({ name: h.name.trim(), value: h.value })), basic_auth: d.basic && (d.basic.username.trim() || d.basic.password) ? { username: d.basic.username.trim(), password: d.basic.password } : null }
}

function loginIsEmpty(l: ReturnType<typeof loginOf>): boolean {
  return !l.cookie && l.headers.length === 0 && !l.basic_auth
}

/**
 * The login to send, in the contract's names (`cookie`, `headers`, `basic_auth`): undefined when
 * the person changed nothing, `null` when everything was removed. A kept secret travels as "set",
 * which the route answers by keeping the stored value (a header by its name).
 */
export function credentialsPayload(initial: AccessDraft, draft: AccessDraft): ReturnType<typeof loginOf> | null | undefined {
  const before = loginOf(initial)
  const after = loginOf(draft)
  if (JSON.stringify(before) === JSON.stringify(after)) return undefined
  return loginIsEmpty(after) ? null : after
}

/** The inline error of the login as typed, or '': the route checks again. */
export function accessError(d: AccessDraft): string {
  const names = new Set<string>()
  for (const h of d.headers) {
    const name = h.name.trim()
    if (!name && !h.value) continue
    if (!name) return 'A header needs a name'
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) return `${name} is not a header name (letters, digits and -)`
    if (names.has(name.toLowerCase())) return `The header ${name} is named twice`
    names.add(name.toLowerCase())
    if (!h.value) return `Type the value of ${name}`
  }
  if (d.basic && (d.basic.username.trim() || d.basic.password)) {
    if (!d.basic.username.trim()) return 'Basic authentication needs a user name'
    if (d.basic.username.includes(':')) return 'A user name cannot hold ":"'
    if (!d.basic.password) return 'Type the basic authentication password'
  }
  return ''
}

/** The section's one-line status (§6.2): "GitHub token · cookie, 2 headers" or "no token · no cookies or headers". */
export function accessStatus(d: AccessDraft, tokenSet: boolean): string {
  const token = d.githubToken || tokenSet ? 'GitHub token' : 'no GitHub token'
  const l = loginOf(d)
  const parts = [
    ...(l.cookie ? ['cookie'] : []),
    ...(l.headers.length ? [l.headers.length === 1 ? '1 header' : `${l.headers.length} headers`] : []),
    ...(l.basic_auth ? ['basic authentication'] : []),
  ]
  return `${token} · ${parts.length ? parts.join(', ') : 'no cookies or headers'}`
}

/**
 * Access (§6.6): the GitHub token override, cookies, custom headers and basic authentication. A
 * stored value shows as "set", never as its value; typing replaces it. While an administrator acts
 * as the account every field is disabled: a login is neither changed nor used then.
 */
export function AccessSection({ draft, onChange, tokenSet }: {
  draft: AccessDraft
  onChange: (next: AccessDraft) => void
  /** A GitHub token override is stored. */
  tokenSet: boolean
}) {
  const id = useId()
  const actingAs = useOptionalAuth()?.user?.actingAs ?? null
  const locked = !!actingAs
  const set = (patch: Partial<AccessDraft>) => onChange({ ...draft, ...patch })
  const setHeader = (i: number, patch: Partial<{ name: string; value: string }>) =>
    set({ headers: draft.headers.map((h, j) => (j === i ? { ...h, ...patch } : h)) })
  const error = accessError(draft)
  const secretPlaceholder = (value: string, empty: string) => (value === SET ? 'set: type a new value to replace it' : empty)
  // A kept secret is held as "set" but never shown in its field: the field shows what was typed.
  const shown = (value: string) => (value === SET ? '' : value)

  return (
    <FormSection title="Access" status={accessStatus(draft, tokenSet)}>
      {locked && (
        <span className={css.hint} role="note">Not available while acting as {actingAs.name || actingAs.email}: the logins stay the account&apos;s own.</span>
      )}
      <fieldset disabled={locked} style={{ border: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="formGroup">
          <label className="formLabel" htmlFor={`${id}-token`}>GitHub token override</label>
          <input
            id={`${id}-token`} className="textInput" type="password" autoComplete="new-password" value={draft.githubToken}
            onChange={e => set({ githubToken: e.target.value })}
            placeholder={tokenSet ? 'A token is set: type a new one to replace it' : 'optional: ghp_…'}
          />
        </div>
        <div className="formGroup">
          <label className="formLabel" htmlFor={`${id}-cookie`}>Cookies</label>
          <div className={fcss.row}>
            <input
              id={`${id}-cookie`} className={`textInput ${fcss.grow}`} type="password" autoComplete="new-password" maxLength={8000}
              value={shown(draft.cookie)} onChange={e => set({ cookie: e.target.value })}
              placeholder={secretPlaceholder(draft.cookie, 'session=…; other=…')}
            />
            {draft.cookie && (
              <button type="button" className="secondaryButton" onClick={() => set({ cookie: '' })}>Remove the cookie</button>
            )}
          </div>
          <span className={css.hint}>The Cookie header for a site that needs a session, such as a paid knowledge base.</span>
        </div>
        <div className="formGroup">
          <span className="formLabel">Custom headers</span>
          {draft.headers.map((h, i) => (
            <div key={i} className={fcss.row} data-header-row={i}>
              <input
                className={`textInput ${fcss.grow}`} aria-label={`Header ${i + 1} name`} value={h.name} maxLength={200}
                onChange={e => setHeader(i, { name: e.target.value })} placeholder="X-Api-Key"
              />
              <input
                className={`textInput ${fcss.grow}`} type="password" autoComplete="new-password" aria-label={`Header ${i + 1} value`}
                value={shown(h.value)} maxLength={4096} onChange={e => setHeader(i, { value: e.target.value })}
                placeholder={secretPlaceholder(h.value, 'value')}
              />
              <button type="button" className="iconButton" aria-label={`Remove header ${i + 1}`} onClick={() => set({ headers: draft.headers.filter((_, j) => j !== i) })}>
                <X size={14} />
              </button>
            </div>
          ))}
          <div>
            <button
              type="button" className="secondaryButton" disabled={draft.headers.length >= HEADERS_MAX}
              onClick={() => set({ headers: [...draft.headers, { name: '', value: '' }] })}
            >
              <Plus size={12} /> Add a header
            </button>
          </div>
        </div>
        <div className="formGroup">
          <label className={css.storageOption}>
            <input
              type="checkbox" checked={!!draft.basic}
              onChange={e => set({ basic: e.target.checked ? { username: '', password: '' } : null })}
            />
            <span>Basic authentication</span>
          </label>
          {draft.basic && (
            <div className={fcss.row}>
              <input
                className={`textInput ${fcss.grow}`} aria-label="User name" value={draft.basic.username} maxLength={500}
                onChange={e => set({ basic: { ...draft.basic!, username: e.target.value } })} placeholder="user name"
              />
              <input
                className={`textInput ${fcss.grow}`} type="password" autoComplete="new-password" aria-label="Password"
                value={shown(draft.basic.password)} maxLength={2000}
                onChange={e => set({ basic: { ...draft.basic!, password: e.target.value } })}
                placeholder={secretPlaceholder(draft.basic.password, 'password')}
              />
            </div>
          )}
        </div>
        <span className={css.hint}>{LOGIN_NOTE}</span>
        {error && <span className={css.failure} role="alert">{error}</span>}
      </fieldset>
    </FormSection>
  )
}
