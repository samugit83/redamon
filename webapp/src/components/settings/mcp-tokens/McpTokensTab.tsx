'use client'

/**
 * MCP Server - access tokens for the INBOUND direction.
 *
 * The sibling "MCP Tool Plugins" tab is OUTBOUND (RedAmon connecting out to
 * servers the operator registers). This one mints credentials that let other
 * agents connect IN. Two tabs, opposite directions, so the subtitle says so
 * explicitly rather than relying on the reader to infer it from the name.
 */
import { useState, useEffect, useCallback } from 'react'
import {
  KeyRound, Plus, Loader2, Copy, Check, Trash2, Pencil,
  AlertTriangle, RefreshCw, ShieldAlert, Braces, GraduationCap, MoreVertical,
} from 'lucide-react'
import { Menu, MenuItem, Tooltip, useAlertModal, WikiInfoButton } from '@/components/ui'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { copyText } from '@/lib/copyText'
import { readApiError, toApiError } from '@/lib/apiError'
import {
  MCP_SCOPES,
  MCP_DEFAULT_EXPIRY_DAYS,
  DEFAULT_MCP_SCOPES,
  isTokenWidening,
  type McpScope,
} from '@/lib/mcpAuth'
import {
  DEFAULT_PROFILE,
  PROFILES,
  PROFILE_LIST,
  profileOrDefault,
  profileScopeDiff,
  scopesForProfile,
  type ProfileId,
} from '@/lib/mcp/profiles'
import ScopeChecklist from './ScopeChecklist'
import SharedProjectsField from './SharedProjectsField'
import AgentOnboardingModal from './AgentOnboardingModal'
import styles from './McpTokensTab.module.css'
import { profileOffered } from '@/lib/agentInTheLoop'

interface Props {
  userId: string
  onDirtyChange?: (dirty: boolean) => void
}

interface TokenRow {
  id: string
  name: string
  tokenPrefix: string
  scopes: string[]
  profile: string | null
  lastUsedAt: string | null
  expiresAt: string | null
  revokedAt: string | null
  createdAt: string
  /** Present with the sharing switch on (step 4.10). */
  includeSharedProjects?: boolean
  projectAllowlist?: string[]
}

/**
 * Ending a token does not undo what it muted, and after a delete its prefix is
 * the only thing left that says which token did it. Said where it is ended.
 */
export function muteReviewLine(t: Pick<TokenRow, 'scopes' | 'tokenPrefix'>): string | null {
  if (!t.scopes.includes('triage:mute')) return null
  return 'Findings this token muted stay muted. Review them in Muted Nodes with the Token filter ' +
    `${t.tokenPrefix}; after a delete the prefix is the only record of which token did it.`
}

const EXPIRY_OPTIONS: { value: number | 'never'; label: string }[] = [
  { value: 30, label: '30 days' },
  { value: 60, label: '60 days' },
  { value: 90, label: '90 days' },
  { value: 365, label: '1 year' },
  { value: 'never', label: 'No expiry' },
]

/**
 * Expiry choices when EDITING. Presets count from today, not from when the
 * token was minted, because "30 days" is read as "30 more days".
 */
type EditExpiry = 'keep' | 'now' | '30' | '60' | '90' | '365' | 'never' | 'date'

const EDIT_EXPIRY_PRESETS: { value: EditExpiry; label: string }[] = [
  { value: 'now', label: 'Expire now' },
  { value: '30', label: '30 days from today' },
  { value: '60', label: '60 days from today' },
  { value: '90', label: '90 days from today' },
  { value: '365', label: '1 year from today' },
  { value: 'never', label: 'No expiry' },
  { value: 'date', label: 'Pick a date…' },
]

const DAY_MS = 86_400_000

/** What the chosen expiry would be, so the UI can tell widening before the server does. */
function prospectiveExpiry(choice: EditExpiry, date: string, current: string | null): Date | null {
  switch (choice) {
    case 'keep': return current ? new Date(current) : null
    case 'now': return new Date()
    case 'never': return null
    case 'date': return date ? new Date(`${date}T23:59:59.999Z`) : (current ? new Date(current) : null)
    default: return new Date(Date.now() + Number(choice) * DAY_MS)
  }
}

/** The PATCH `expiry` value, or undefined to leave it unchanged. */
function expiryPayload(choice: EditExpiry, date: string): string | number | undefined {
  if (choice === 'keep') return undefined
  if (choice === 'date') return date
  if (choice === 'now' || choice === 'never') return choice
  return Number(choice)
}

const todayIso = () => new Date().toISOString().slice(0, 10)

const fmtDate = (iso: string | null) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : null

function tokenState(t: TokenRow): 'active' | 'revoked' | 'expired' {
  if (t.revokedAt) return 'revoked'
  if (t.expiresAt && new Date(t.expiresAt).getTime() <= Date.now()) return 'expired'
  return 'active'
}

function clientSnippet(token: string): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://<redamon-host>'
  return JSON.stringify(
    { mcpServers: { redamon: { url: `${origin}/api/mcp-server`, headers: { Authorization: `Bearer ${token}` } } } },
    null,
    2
  )
}

export default function McpTokensTab({ userId, onDirtyChange }: Props) {
  const { dangerConfirm, confirm, alertError } = useAlertModal()

  const [tokens, setTokens] = useState<TokenRow[]>([])
  // Agent in the Loop on this deployment (from the list answer): off, its scope
  // and its profile are not offered.
  const [loopOn, setLoopOn] = useState(false)
  const profileList = PROFILE_LIST.filter(p => profileOffered(p.id, loopOn))
  // The scopes this account cannot grant and why (permissions switch on; absent off). A profile
  // or the defaults never tick one, and the checklist shows it disabled with the reason.
  const [scopeLimits, setScopeLimits] = useState<Partial<Record<McpScope, readonly string[]>> | undefined>(undefined)
  const grantable = useCallback(
    (list: McpScope[]) => (scopeLimits ? list.filter(s => scopeLimits[s] === undefined) : list),
    [scopeLimits],
  )
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  // The real session user. Minting is self-only on the REAL identity, so when
  // an admin is viewing someone else's settings the form is disabled WITH A
  // REASON rather than being a button that 403s on click.
  const [sessionUserId, setSessionUserId] = useState<string | null>(null)
  // Sharing in force (/api/auth/me): only then can a token opt in to shared projects.
  const [sharingOn, setSharingOn] = useState(false)
  const [includeShared, setIncludeShared] = useState(false)
  const [allowlist, setAllowlist] = useState<string[]>([])
  const [editIncludeShared, setEditIncludeShared] = useState(false)
  const [editAllowlist, setEditAllowlist] = useState<string[]>([])

  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [profile, setProfile] = useState<ProfileId>(DEFAULT_PROFILE)
  const [scopes, setScopes] = useState<McpScope[]>([...DEFAULT_MCP_SCOPES])
  const [expiresInDays, setExpiresInDays] = useState<number | 'never'>(MCP_DEFAULT_EXPIRY_DAYS)
  const [password, setPassword] = useState('')
  const [creating, setCreating] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const [minted, setMinted] = useState<string | null>(null)
  // The shape the token was minted WITH, kept because resetForm has already run
  // by the time the reveal panel is on screen.
  const [mintedShape, setMintedShape] = useState<
    { profile: ProfileId; scopes: McpScope[]; name: string } | null
  >(null)
  const [copied, setCopied] = useState<'token' | 'snippet' | null>(null)

  const [editing, setEditing] = useState<TokenRow | null>(null)
  const [editName, setEditName] = useState('')
  const [editProfile, setEditProfile] = useState<ProfileId>(DEFAULT_PROFILE)
  const [editScopes, setEditScopes] = useState<McpScope[]>([])
  const [editExpiry, setEditExpiry] = useState<EditExpiry>('keep')
  const [editDate, setEditDate] = useState('')
  const [editPassword, setEditPassword] = useState('')
  const [editError, setEditError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  // Set when the server says a step-up is needed that the client did not
  // predict (a preset computed a moment later lands past the current expiry).
  const [serverWantsPassword, setServerWantsPassword] = useState(false)

  const [onboarding, setOnboarding] = useState<
    { profile: ProfileId | null; scopes: McpScope[]; name?: string } | null
  >(null)
  // A pack downloaded before this edit now describes the wrong token, so the
  // offer to re-export is made at the moment that becomes true.
  const [reExport, setReExport] = useState<
    { profile: ProfileId; scopes: McpScope[]; name: string } | null
  >(null)

  const draft = { name, profile, scopes, expiresInDays, password, includeShared, allowlist }
  const { isDirty, setBaseline } = useDirtyState(draft)

  const editScopesChanged = editing !== null && (
    editScopes.length !== editing.scopes.length || editScopes.some(s => !editing.scopes.includes(s))
  )
  const editProfileChanged = editing !== null && editProfile !== profileOrDefault(editing.profile)
  const editSharedChanged = editing !== null && sharingOn && (
    editIncludeShared !== (editing.includeSharedProjects === true)
    || editAllowlist.length !== (editing.projectAllowlist ?? []).length
    || editAllowlist.some(id => !(editing.projectAllowlist ?? []).includes(id))
  )
  const editDirty = editing !== null && (
    editName.trim() !== editing.name || editScopesChanged || editProfileChanged || editExpiry !== 'keep' || editSharedChanged
  )
  const editWidens = editing !== null && isTokenWidening(
    {
      scopes: editing.scopes, expiresAt: editing.expiresAt ? new Date(editing.expiresAt) : null,
      includeSharedProjects: editing.includeSharedProjects === true, projectAllowlist: editing.projectAllowlist ?? [],
    },
    {
      scopes: editScopes, expiresAt: prospectiveExpiry(editExpiry, editDate, editing.expiresAt),
      ...(editSharedChanged ? { includeSharedProjects: editIncludeShared, projectAllowlist: editAllowlist } : {}),
    },
  )
  const editNeedsPassword = editWidens || serverWantsPassword

  const dirty = (showForm && isDirty) || editDirty
  useUnsavedChangesGuard(dirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(dirty) }, [dirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const canMint = sessionUserId !== null && sessionUserId === userId
  // Distinct from !canMint: an unresolved session also blocks minting, but
  // must not claim the operator is looking at someone else's account.
  const viewingOtherUser = sessionUserId !== null && !canMint

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens`)
      if (!r.ok) throw await readApiError(r, 'Could not load tokens')
      const data = await r.json()
      setTokens(Array.isArray(data.tokens) ? data.tokens : [])
      setLoopOn(data.features?.agentInTheLoop === true)
      setScopeLimits(data.ungrantableScopes && typeof data.ungrantableScopes === 'object' ? data.ungrantableScopes : undefined)
    } catch (e) {
      // Never a silent empty list: that reads as "you have no tokens" and
      // prompts a duplicate mint.
      setLoadError(toApiError(e, 'Could not load tokens').message)
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        // /api/auth/me resolves getSession(), i.e. the REAL login identity, not
        // the act-as target. That is exactly the identity minting is judged on.
        const r = await fetch('/api/auth/me')
        if (!r.ok) return
        const data = await r.json()
        if (!cancelled) {
          setSessionUserId(typeof data?.id === 'string' ? data.id : null)
          setSharingOn(data?.sharing?.enabled === true)
        }
      } catch {
        // Leaving it null keeps the form disabled, which is the safe direction.
      }
    })()
    return () => { cancelled = true }
  }, [])

  const resetForm = useCallback(() => {
    setName('')
    setProfile(DEFAULT_PROFILE)
    setScopes(grantable([...DEFAULT_MCP_SCOPES]))
    setExpiresInDays(MCP_DEFAULT_EXPIRY_DAYS)
    setPassword('')
    setIncludeShared(false)
    setAllowlist([])
    setFormError(null)
    setBaseline({
      name: '', profile: DEFAULT_PROFILE, scopes: grantable([...DEFAULT_MCP_SCOPES]),
      expiresInDays: MCP_DEFAULT_EXPIRY_DAYS, password: '', includeShared: false, allowlist: [],
    })
  }, [setBaseline, grantable])

  const toggleScope = (s: McpScope) => {
    setScopes(prev => (prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]))
  }

  /**
   * Picking a profile re-ticks the permissions, which is the whole point of the
   * feature. But it must not silently discard a set the operator hand-tuned, so
   * a divergent selection is confirmed first.
   *
   * The opt-in scopes (`recon:overwrite`, and the engagement writes) are never
   * carried in by this, even for the profiles that recommend them:
   * `scopesForProfile` returns the recommended set only.
   */
  const changeProfile = async (next: ProfileId) => {
    // Measured against what the profile could tick for this account, so the scopes it left out
    // for want of a permission do not read as a hand edit.
    const ticked = grantable(scopesForProfile(profile))
    const diverged = scopeLimits
      ? ticked.length !== scopes.length || scopes.some(s => !ticked.includes(s))
      : profileScopeDiff(profile, scopes).modified
    if (diverged) {
      const ok = await confirm(
        `Switching to ${PROFILES[next].label} resets the permissions to that profile's ` +
          'recommendation, discarding the ones you picked by hand.',
        'Change Agent Profile',
        { confirmLabel: "Use the profile's permissions", cancelLabel: 'Keep mine' }
      )
      setProfile(next)
      if (!ok) return
    } else {
      setProfile(next)
    }
    setScopes(grantable(scopesForProfile(next)))
  }

  const changeEditProfile = async (next: ProfileId) => {
    if (!editing) return
    // Measured against the profile CURRENTLY SELECTED in the panel, not the one
    // stored on the token. Using the stored one made every switch after the
    // first compare the new profile's scopes against the ORIGINAL profile's
    // recommendation, so a second switch always looked hand-edited and accused
    // the operator of discarding permissions they had never touched.
    const diverged = profileScopeDiff(editProfile, editScopes).modified
    setServerWantsPassword(false)
    if (diverged) {
      const ok = await confirm(
        `Switching to ${PROFILES[next].label} resets the permissions to that profile's ` +
          'recommendation. Adding one still asks for your password; removing one does not.',
        'Change Agent Profile',
        { confirmLabel: "Use the profile's permissions", cancelLabel: 'Keep the current ones' }
      )
      setEditProfile(next)
      if (!ok) return
    } else {
      setEditProfile(next)
    }
    // A scope the account cannot grant is ticked only when the token already holds it.
    setEditScopes(scopesForProfile(next).filter(s => scopeLimits?.[s] === undefined || editing.scopes.includes(s)))
  }

  const openEdit = (t: TokenRow) => {
    setShowForm(false)
    setEditing(t)
    setEditName(t.name)
    setEditProfile(profileOrDefault(t.profile))
    setEditScopes(t.scopes.filter((s): s is McpScope => (MCP_SCOPES as readonly string[]).includes(s)))
    setEditExpiry('keep')
    setEditDate('')
    setEditPassword('')
    setEditIncludeShared(t.includeSharedProjects === true)
    setEditAllowlist([...(t.projectAllowlist ?? [])])
    setEditError(null)
    setServerWantsPassword(false)
  }

  const closeEdit = () => {
    setEditing(null)
    setEditPassword('')
    setEditError(null)
  }

  const saveEdit = async () => {
    if (!editing || saving) return
    setSaving(true)
    setEditError(null)
    try {
      const body: Record<string, unknown> = { name: editName }
      if (editScopesChanged) body.scopes = editScopes
      if (editProfileChanged) body.profile = editProfile === 'custom' ? null : editProfile
      const expiry = expiryPayload(editExpiry, editDate)
      if (expiry !== undefined) body.expiry = expiry
      if (editSharedChanged) {
        body.includeSharedProjects = editIncludeShared
        body.projectAllowlist = editAllowlist
      }
      if (editNeedsPassword) body.password = editPassword

      const r = await fetch(`/api/users/${userId}/mcp-tokens/${editing.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!r.ok) {
        const err = await readApiError(r, 'Could not save the token')
        if (err.body?.passwordRequired) setServerWantsPassword(true)
        // Keep the panel populated so nothing is re-chosen.
        setEditError(err.message)
        return
      }
      const saved = { profile: editProfile, scopes: [...editScopes], name: editName }
      const changedWhatThePackSays = editScopesChanged || editProfileChanged
      closeEdit()
      await load()
      if (changedWhatThePackSays) setReExport(saved)
    } catch (e) {
      setEditError(toApiError(e, 'Could not save the token').message)
    } finally {
      setSaving(false)
    }
  }

  const create = async () => {
    if (creating) return // a double-submit must not mint two tokens
    setCreating(true)
    setFormError(null)
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name, scopes, expiresInDays, password,
          // `custom` means "no profile", which is what every pre-existing row
          // already reads as. Storing the literal string would make the absence
          // of a choice indistinguishable from choosing Custom.
          profile: profile === 'custom' ? null : profile,
          // Sent only with sharing in force, so the request is the one before sharing otherwise.
          ...(sharingOn ? { includeSharedProjects: includeShared, projectAllowlist: allowlist } : {}),
        }),
      })
      if (!r.ok) {
        // Keep the form populated so the operator does not retype everything.
        setFormError((await readApiError(r, 'Could not create the token')).message)
        return
      }
      const data = await r.json()
      setMinted(data.plaintext)
      setMintedShape({ profile, scopes: [...scopes], name })
      setShowForm(false)
      resetForm()
      await load()
    } catch (e) {
      setFormError(toApiError(e, 'Could not create the token').message)
    } finally {
      setCreating(false)
    }
  }

  const remove = async (t: TokenRow) => {
    const mutes = muteReviewLine(t)
    const confirmed = await dangerConfirm(
      `Delete '${t.name}' (${t.tokenPrefix}…)? The token is removed from the database, not ` +
      'just switched off, so this row disappears and any agent using it stops working ' +
      'immediately. The audit log keeps a record that it existed. This cannot be undone.' +
      (mutes ? `\n\n${mutes}` : ''),
      'Delete MCP Access Token',
    )
    if (!confirmed) return
    try {
      const r = await fetch(`/api/users/${userId}/mcp-tokens/${t.id}`, { method: 'DELETE' })
      if (!r.ok) {
        await alertError((await readApiError(r, 'Delete failed')).message, 'Delete MCP Access Token')
        return
      }
      // The edit panel may be open on the row that just stopped existing.
      if (editing?.id === t.id) closeEdit()
      await load()
    } catch (e) {
      await alertError(toApiError(e, 'Delete failed').message, 'Delete MCP Access Token')
    }
  }

  const copy = async (text: string, which: 'token' | 'snippet') => {
    try {
      await copyText(text)
      setCopied(which)
      setTimeout(() => setCopied(null), 2000)
    } catch {
      await alertError('Could not copy to the clipboard. Select the text and copy it manually.', 'Copy')
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <div>
          <h3 className={styles.sectionTitle}>
            <KeyRound size={16} /> MCP Server
            <WikiInfoButton
              target="https://github.com/samugit83/redamon/wiki/MCP-Server"
              title="Open MCP Server wiki page"
            />
            <WikiInfoButton
              target="https://github.com/samugit83/redamon/wiki/MCP-API-Reference"
              title="Open MCP API Reference wiki page"
              icon={Braces}
            />
          </h3>
          <p className={styles.sectionDescription}>
            <strong>Inbound:</strong> let an external AI agent connect to RedAmon and act as you,
            within your own projects. (The <em>MCP Tool Plugins</em> tab is the opposite
            direction: RedAmon connecting out to other servers.)
          </p>
        </div>
        <div className={styles.headerActions}>
          <button
            className={styles.secondaryBtn}
            title="Generate the instructions an external agent loads"
            onClick={() => setOnboarding({ profile: null, scopes: [...DEFAULT_MCP_SCOPES] })}
          >
            <GraduationCap size={14} /> Agent Onboarding
          </button>
          <button className={styles.secondaryBtn} onClick={() => void load()} disabled={loading}>
            <RefreshCw size={14} /> Refresh
          </button>
          <Tooltip
            content="You can only create a token for the account you are logged in with, admins included. To create one for this user, log in as them."
            position="bottom"
            maxWidth={280}
            disabled={!viewingOtherUser}
          >
            <button
              className={styles.primaryBtn}
              onClick={() => { closeEdit(); setShowForm(true); resetForm() }}
              disabled={!canMint || showForm}
            >
              <Plus size={14} /> New token
            </button>
          </Tooltip>
        </div>
      </div>

      {viewingOtherUser && (
        <div className={styles.noticeBanner}>
          <ShieldAlert size={14} />
          <span>
            You are viewing another user&apos;s settings. A token can only be created by its own
            user, signed in as themselves. You can still review and revoke their tokens here.
          </span>
        </div>
      )}

      {reExport && (
        <div className={styles.noticeBanner}>
          <GraduationCap size={14} />
          <span>
            You changed what <strong>{reExport.name}</strong> can do, so any onboarding pack you
            already gave that agent is out of date.
          </span>
          <button
            className={styles.linkBtn}
            onClick={() => {
              setOnboarding({
                profile: reExport.profile === 'custom' ? null : reExport.profile,
                scopes: reExport.scopes,
                name: reExport.name,
              })
              setReExport(null)
            }}
          >
            Re-export onboarding
          </button>
          <button className={styles.linkBtn} onClick={() => setReExport(null)}>Dismiss</button>
        </div>
      )}

      {minted && (
        <div className={styles.revealPanel}>
          <div className={styles.revealHeader}>
            <AlertTriangle size={15} />
            <strong>Copy this token now. You will not be able to see it again.</strong>
          </div>
          <div className={styles.revealRow}>
            <code className={styles.revealToken}>{minted}</code>
            <button className={styles.secondaryBtn} onClick={() => void copy(minted, 'token')}>
              {copied === 'token' ? <Check size={14} /> : <Copy size={14} />} Copy
            </button>
          </div>
          <p className={styles.muted}>Paste this into your MCP client&apos;s config:</p>
          <div className={styles.revealRow}>
            <pre className={styles.snippet}>{clientSnippet(minted)}</pre>
            <button className={styles.secondaryBtn} onClick={() => void copy(clientSnippet(minted), 'snippet')}>
              {copied === 'snippet' ? <Check size={14} /> : <Copy size={14} />} Copy
            </button>
          </div>
          {mintedShape && (
            <>
              <p className={styles.muted}>
                Now teach your agent how to use RedAmon. This is a second, separate install from the
                config above.
              </p>
              <button
                className={styles.secondaryBtn}
                onClick={() => setOnboarding({
                  profile: mintedShape.profile === 'custom' ? null : mintedShape.profile,
                  scopes: mintedShape.scopes,
                  name: mintedShape.name,
                })}
              >
                <GraduationCap size={14} /> Export onboarding
              </button>
            </>
          )}
          <button className={styles.linkBtn} onClick={() => setMinted(null)}>I have saved it - dismiss</button>
        </div>
      )}

      {showForm && (
        <div className={styles.formBlock}>
          <div className={`${styles.formHeader} ${styles.stickyFormHeader}`}>
            <div>
              <h4 className={styles.formTitle}>New access token</h4>
              <p className={styles.formSubtitle}>
                Name it after the agent that will use it, so a revoke later is an obvious choice.
              </p>
            </div>
            <div className={styles.formHeaderActions}>
              <button
                className={styles.secondaryBtn}
                onClick={() => { setShowForm(false); resetForm() }}
                disabled={creating}
              >
                Cancel
              </button>
              <button className={styles.primaryBtn} onClick={() => void create()} disabled={creating}>
                {creating ? <Loader2 className={styles.spin} size={14} /> : <Plus size={14} />} Create token
              </button>
            </div>
          </div>

          {formError && <div className={styles.errorBanner}>{formError}</div>}

          <div className={styles.formBody}>
            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpTokenName">Name</label>
              <input
                id="mcpTokenName"
                className={`textInput ${styles.control}`}
                value={name}
                maxLength={64}
                placeholder="e.g. CI agent"
                onChange={e => setName(e.target.value)}
              />
            </div>

            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpTokenProfile">Agent Profile</label>
              <select
                id="mcpTokenProfile"
                className={`select ${styles.control}`}
                value={profile}
                onChange={e => void changeProfile(e.target.value as ProfileId)}
              >
                {profileList.map(p => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
              <span className="formHint">
                {PROFILES[profile].blurb} Choosing a job ticks the permissions it needs; you can
                still change them.
              </span>
            </div>

            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpTokenExpiry">Expires</label>
              <select
                id="mcpTokenExpiry"
                className={`select ${styles.control}`}
                value={String(expiresInDays)}
                onChange={e => setExpiresInDays(e.target.value === 'never' ? 'never' : Number(e.target.value))}
              >
                {EXPIRY_OPTIONS.map(o => (
                  <option key={String(o.value)} value={String(o.value)}>{o.label}</option>
                ))}
              </select>
            </div>

            <ScopeChecklist selected={scopes} onToggle={toggleScope} profile={profile} loopOff={!loopOn} limits={scopeLimits} />

            {sharingOn && (
              <SharedProjectsField
                idPrefix="mcpToken"
                include={includeShared}
                allowlist={allowlist}
                onChange={(include, ids) => { setIncludeShared(include); setAllowlist(ids) }}
              />
            )}

            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpTokenPassword">Confirm your password</label>
              <input
                id="mcpTokenPassword"
                type="password"
                className={`textInput ${styles.control}`}
                value={password}
                autoComplete="current-password"
                onChange={e => setPassword(e.target.value)}
              />
              <span className="formHint">
                Creating a long-lived credential asks for your password again.
              </span>
            </div>
          </div>
        </div>
      )}

      {editing && (
        <div className={styles.formBlock}>
          <div className={`${styles.formHeader} ${styles.stickyFormHeader}`}>
            <div>
              <h4 className={styles.formTitle}>Edit token</h4>
              <p className={styles.formSubtitle}>
                <code className={styles.prefix}>{editing.tokenPrefix}…</code> Changes apply to the
                agent&apos;s very next call.
              </p>
            </div>
            <div className={styles.formHeaderActions}>
              <button className={styles.secondaryBtn} onClick={closeEdit} disabled={saving}>
                Cancel
              </button>
              <button
                className={styles.primaryBtn}
                onClick={() => void saveEdit()}
                disabled={
                  saving || !editDirty || !editName.trim() || editScopes.length === 0 ||
                  (editExpiry === 'date' && !editDate) ||
                  (editNeedsPassword && !canMint)
                }
              >
                {saving ? <Loader2 className={styles.spin} size={14} /> : <Check size={14} />} Save changes
              </button>
            </div>
          </div>

          {editing.revokedAt && (
            <div className={styles.noticeBanner}>
              <ShieldAlert size={14} />
              <span>This token is revoked, so only its name can change. Create a new token to restore access.</span>
            </div>
          )}

          {editError && <div className={styles.errorBanner}>{editError}</div>}

          <div className={styles.formBody}>
            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpEditName">Name</label>
              <input
                id="mcpEditName"
                className={`textInput ${styles.control}`}
                value={editName}
                maxLength={64}
                onChange={e => setEditName(e.target.value)}
              />
            </div>

            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpEditProfile">Agent Profile</label>
              <select
                id="mcpEditProfile"
                className={`select ${styles.control}`}
                value={editProfile}
                disabled={!!editing.revokedAt}
                onChange={e => void changeEditProfile(e.target.value as ProfileId)}
              >
                {profileList.map(p => (
                  <option key={p.id} value={p.id}>{p.label}</option>
                ))}
              </select>
              <span className="formHint">{PROFILES[editProfile].blurb}</span>
            </div>

            <div className={`formGroup ${styles.field}`}>
              <label className="formLabel" htmlFor="mcpEditExpiry">Expires</label>
              <select
                id="mcpEditExpiry"
                className={`select ${styles.control}`}
                value={editExpiry}
                disabled={!!editing.revokedAt}
                onChange={e => { setEditExpiry(e.target.value as EditExpiry); setServerWantsPassword(false) }}
              >
                <option value="keep">
                  {editing.expiresAt
                    ? `Keep current (${tokenState(editing) === 'expired' ? 'expired ' : ''}${fmtDate(editing.expiresAt)})`
                    : 'Keep current (no expiry)'}
                </option>
                {EDIT_EXPIRY_PRESETS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              {editExpiry === 'now' && (
                <span className="formHint">
                  The agent&apos;s next call fails. Unlike revoking, you can extend it again later.
                  {muteReviewLine(editing) && <> {muteReviewLine(editing)}</>}
                </span>
              )}
            </div>

            {editExpiry === 'date' && (
              <div className={`formGroup ${styles.field}`}>
                <label className="formLabel" htmlFor="mcpEditDate">Expiry date</label>
                <input
                  id="mcpEditDate"
                  type="date"
                  className={`textInput ${styles.control}`}
                  value={editDate}
                  min={todayIso()}
                  onChange={e => setEditDate(e.target.value)}
                />
                <span className="formHint">The token works until the end of that day (UTC).</span>
              </div>
            )}

            <ScopeChecklist
              selected={editScopes}
              disabled={!!editing.revokedAt}
              profile={editProfile}
              loopOff={!loopOn}
              limits={scopeLimits}
              onToggle={s => {
                setEditScopes(prev => (prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]))
                setServerWantsPassword(false)
              }}
            />

            {sharingOn && (
              <SharedProjectsField
                idPrefix="mcpEdit"
                include={editIncludeShared}
                allowlist={editAllowlist}
                disabled={!!editing.revokedAt}
                onChange={(include, ids) => {
                  setEditIncludeShared(include)
                  setEditAllowlist(ids)
                  setServerWantsPassword(false)
                }}
              />
            )}

            {editScopesChanged && profileScopeDiff(editProfile, editScopes).modified && (
              <div className={styles.noticeBanner}>
                <ShieldAlert size={14} />
                <span>
                  These permissions no longer match the <strong>{PROFILES[editProfile].label}</strong>{' '}
                  profile. That is allowed: the profile is a starting point and a label, never a
                  permission. Switch the profile above if you want it to match, or leave it, and the
                  onboarding pack will still describe only what this token can actually call.
                </span>
              </div>
            )}

            {editNeedsPassword && !canMint && (
              <div className={styles.noticeBanner}>
                <ShieldAlert size={14} />
                <span>
                  Only the token&apos;s own user can add a permission, extend the expiry or open it to
                  more shared projects. You can still remove permissions, shorten the expiry or revoke it.
                </span>
              </div>
            )}

            {editNeedsPassword && canMint && (
              <div className={`formGroup ${styles.field}`}>
                <label className="formLabel" htmlFor="mcpEditPassword">Confirm your password</label>
                <input
                  id="mcpEditPassword"
                  type="password"
                  className={`textInput ${styles.control}`}
                  value={editPassword}
                  autoComplete="current-password"
                  onChange={e => setEditPassword(e.target.value)}
                />
                <span className="formHint">
                  Adding a permission, extending the expiry or opening it to more shared projects gives
                  this token more power, so it asks for your password again.
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {loading && (
        <div className={styles.skeleton} aria-busy="true" aria-label="Loading tokens">
          <div className={styles.skeletonRow} />
          <div className={styles.skeletonRow} />
        </div>
      )}

      {!loading && loadError && (
        <div className={styles.errorBanner}>
          <AlertTriangle size={14} /> {loadError}
          <button className={styles.linkBtn} onClick={() => void load()}>Retry</button>
        </div>
      )}

      {!loading && !loadError && tokens.length === 0 && (
        <div className={styles.empty}>
          <p>No MCP access tokens yet.</p>
          <p className={styles.muted}>
            A token lets an external AI agent start recon scans, read your attack-surface graph and
            adjust recon tuning, scoped to your own projects and to the permissions you tick.
          </p>
        </div>
      )}

      <AgentOnboardingModal
        userId={userId}
        isOpen={onboarding !== null}
        onClose={() => setOnboarding(null)}
        initialProfile={onboarding?.profile ?? null}
        initialScopes={onboarding?.scopes ?? [...DEFAULT_MCP_SCOPES]}
        tokenName={onboarding?.name}
        loopOn={loopOn}
        limits={scopeLimits}
      />

      {!loading && !loadError && tokens.length > 0 && (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Name</th>
                <th>Token</th>
                <th>Permissions</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {tokens.map(t => {
                const state = tokenState(t)
                return (
                  <tr key={t.id} className={state === 'active' ? '' : styles.deadRow}>
                    <td className={styles.nameCell}>
                      <span className={styles.cellTitle}>{t.name}</span>
                      {state !== 'active' && (
                        <span className={styles.deadTag}>{state}</span>
                      )}
                    </td>
                    <td><code className={styles.prefix}>{t.tokenPrefix}…</code></td>
                    <td className={styles.permsCell}>
                      {t.scopes.map(s => (
                        <span key={s} className={styles.tag}>{s}</span>
                      ))}
                    </td>
                    <td>{fmtDate(t.createdAt)}</td>
                    <td>{fmtDate(t.expiresAt) ?? <span className={styles.muted}>Never</span>}</td>
                    <td>{fmtDate(t.lastUsedAt) ?? <span className={styles.muted}>Never used</span>}</td>
                    <td className={styles.actionsCell}>
                      <Menu
                        align="right"
                        ariaLabel={`Actions for ${t.name}`}
                        trigger={<span className={styles.rowMenuBtn}><MoreVertical size={16} /></span>}
                      >
                        <MenuItem
                          icon={<GraduationCap size={14} />}
                          onClick={() => setOnboarding({
                            profile: profileOrDefault(t.profile),
                            scopes: t.scopes.filter((x): x is McpScope =>
                              (MCP_SCOPES as readonly string[]).includes(x)),
                            name: t.name,
                          })}
                        >
                          Onboard
                        </MenuItem>
                        <MenuItem
                          icon={<Pencil size={14} />}
                          onClick={() => openEdit(t)}
                          disabled={editing?.id === t.id}
                        >
                          Edit
                        </MenuItem>
                        <MenuItem
                          icon={<Trash2 size={14} />}
                          destructive
                          onClick={() => void remove(t)}
                        >
                          Delete
                        </MenuItem>
                      </Menu>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
