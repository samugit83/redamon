'use client'

/**
 * Agent Onboarding: generate the instructions an EXTERNAL agent loads.
 *
 * "Agent Skills teach RedAmon's agent. Agent Onboarding teaches yours." That
 * distinction is stated in the modal because it will otherwise be asked about
 * forever: RedAmon already has built-in Agent Skills, Chat Skills and Community
 * Agent Skills, and all three are INBOUND. This one is outbound.
 *
 * This modal GENERATES A DOCUMENT. It never changes the token. The profile and
 * permissions here are editable so an operator can preview what a different
 * shape would produce, and the panel says so explicitly, because otherwise
 * ticking a box here reads as having widened a credential.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Copy, Check, Download, Loader2, GraduationCap, AlertTriangle, FileText,
} from 'lucide-react'
import { Modal, useAlertModal } from '@/components/ui'
import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { copyText } from '@/lib/copyText'
import { readApiError, toApiError } from '@/lib/apiError'
import {
  PROFILE_LIST,
  PROFILES,
  profileOrDefault,
  scopesForProfile,
  type ProfileId,
} from '@/lib/mcp/profiles'
import ScopeChecklist from './ScopeChecklist'
import styles from './McpTokensTab.module.css'
import { MAX_REVIEW_BUDGET, MCP_RUNS_PER_DAY } from '@/lib/triage/limits'
import { LOOP_PROFILE_ID, profileOffered } from '@/lib/agentInTheLoop'
import type { LoopClient } from '@/lib/mcp/loopSkill'
import { loopTokenWarning } from '@/lib/mcp/loopScopes'

interface GeneratedFile {
  path: string
  content: string
}

interface Props {
  userId: string
  isOpen: boolean
  onClose: () => void
  /** Pre-fills the picker. Null means the token has no profile. */
  initialProfile: ProfileId | null
  /** Pre-fills the checklist from the token's ACTUAL scopes. */
  initialScopes: McpScope[]
  /** Shown in the header so it is obvious which token this describes. */
  tokenName?: string
  /** Agent in the Loop is on for this deployment (its scope and profile are offered). */
  loopOn?: boolean
}

/**
 * Warnings about a scope SHAPE that produces a confusing pack, checked here
 * rather than server-side because they are advice, not validation: an operator
 * may deliberately want any of these.
 */
function shapeWarnings(scopes: McpScope[]): string[] {
  const has = (s: McpScope) => scopes.includes(s)
  const out: string[] = []
  if (!has('recon:read')) {
    out.push('Without `recon:read` the agent cannot list projects, so it can never discover a project id to use with anything else. The token is effectively inert.')
  }
  if (has('recon:overwrite') && !has('recon:scan')) {
    out.push('`recon:overwrite` does nothing without `recon:scan`: it only permits a mode of starting a scan.')
  }
  if (has('triage:write') && !has('triage:read')) {
    out.push('`triage:write` without `triage:read` lets the agent record verdicts it cannot check against the suppressed findings first.')
  }
  if (has('triage:mute') && !has('triage:read')) {
    out.push('`triage:mute` without `triage:read` lets the agent mute findings but never find a muted one again, so it cannot check or undo its own mutes, and cannot unmute anything by id.')
  }
  if (has('triage:review') && !has('triage:read')) {
    out.push('`triage:review` without `triage:read`: the agent can submit reviews but cannot read the evidence it must quote, so every review it sends will be refused.')
  }
  if (has('triage:run') && !has('triage:read')) {
    out.push('`triage:run` without `triage:read`: the agent can start runs but cannot see their progress or results.')
  }
  if (has('triage:run') && has('recon:settings')) {
    out.push(`\`triage:run\` with \`recon:settings\`: the agent can start triage runs and change the review budget and model they use. Runs it starts are capped at ${MAX_REVIEW_BUDGET} reviews and ${MCP_RUNS_PER_DAY} a day.`)
  }
  if (has('recon:queue')) {
    out.push('Queued work dispatches later and is NOT cancelled when you revoke the token. The pack tells the agent so.')
  }
  if (has('kali:exec')) {
    out.push('`kali:exec` is the only permission that reaches a live target outside a scan. The pack includes the command-execution reference.')
  }
  const loopWarning = loopTokenWarning(scopes)
  if (loopWarning) out.push(loopWarning)
  return out
}

export default function AgentOnboardingModal({
  userId, isOpen, onClose, initialProfile, initialScopes, tokenName, loopOn = false,
}: Props) {
  const { alertError } = useAlertModal()

  const [profile, setProfile] = useState<ProfileId>(profileOrDefault(initialProfile))
  const [scopes, setScopes] = useState<McpScope[]>(initialScopes)
  const [serverUrl, setServerUrl] = useState('')
  const [style, setStyle] = useState<'mcp' | 'http'>('mcp')
  const [layout, setLayout] = useState<'folder' | 'single'>('folder')
  const [client, setClient] = useState<LoopClient>('claude-code')

  const [files, setFiles] = useState<GeneratedFile[] | null>(null)
  const [active, setActive] = useState(0)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [zipping, setZipping] = useState(false)

  // Re-seeded whenever the modal is opened against a different token, so it
  // never shows the previous token's shape.
  useEffect(() => {
    if (!isOpen) return
    setProfile(profileOrDefault(initialProfile))
    setScopes(initialScopes)
    setServerUrl(typeof window !== 'undefined' ? window.location.origin : '')
    setFiles(null)
    setActive(0)
    setError(null)
  }, [isOpen, initialProfile, initialScopes])

  const warnings = useMemo(() => shapeWarnings(scopes), [scopes])

  const generate = useCallback(async () => {
    setGenerating(true)
    setError(null)
    try {
      const r = await fetch(`/api/users/${userId}/agent-onboarding`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ profile, scopes, serverUrl, style, layout, client }),
      })
      if (!r.ok) {
        setError((await readApiError(r, 'Could not generate the pack')).message)
        return
      }
      const data = await r.json()
      setFiles(data.files)
      setActive(0)
    } catch (e) {
      setError(toApiError(e, 'Could not generate the pack').message)
    } finally {
      setGenerating(false)
    }
  }, [userId, profile, scopes, serverUrl, style, layout, client])

  const skillDir = profile === 'custom' ? 'redamon-mcp' : `redamon-${profile.replace(/_/g, '-')}`

  const copy = async () => {
    if (!files) return
    try {
      await copyText(files[active].content)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      await alertError('Could not copy to the clipboard. Select the text and copy it manually.', 'Copy')
    }
  }

  /**
   * Hand a blob to the browser as a download.
   *
   * The object URL is revoked on a LATER task, never synchronously after
   * `click()`. Revoking immediately races the browser's read of the blob and
   * the download silently produces nothing - which is most of why the old
   * multi-file version appeared to save only the first file.
   */
  const saveBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
  }

  const download = (file: GeneratedFile) => {
    // A single file keeps its basename; the folder it belongs in comes from the
    // zip, not from a flattened name.
    saveBlob(
      new Blob([file.content], { type: 'text/markdown;charset=utf-8' }),
      file.path.split('/').pop() || 'SKILL.md'
    )
  }

  /**
   * The whole pack as ONE zip, with its directory structure intact.
   *
   * It used to loop `download` over every file. That failed twice over: a
   * browser refuses a burst of programmatic downloads from one gesture (Chrome
   * prompts once and then drops the rest), and flattening `references/x.md` to
   * `references-x.md` destroyed exactly the layout the install hint below tells
   * the operator to create. One archive fixes both, and `jszip` is already a
   * dependency - imported dynamically so it costs nothing until it is used.
   */
  const downloadAll = async () => {
    if (!files) return
    setZipping(true)
    try {
      const { default: JSZip } = await import('jszip')
      const zip = new JSZip()
      const root = zip.folder(skillDir) ?? zip
      for (const f of files) root.file(f.path, f.content)
      saveBlob(await zip.generateAsync({ type: 'blob' }), `${skillDir}.zip`)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not build the archive')
    } finally {
      setZipping(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size="large"
      className={styles.onboardModal}
      title={tokenName ? `Agent Onboarding - ${tokenName}` : 'Agent Onboarding'}
    >
      <div className={styles.onboardBody}>
        <p className={styles.onboardLede}>
          RedAmon writes the instructions your agent loads: what RedAmon is, what its recon pipeline
          produces, how to work the job you pick, and exactly what this token can and cannot do.
          <br />
          <em>Agent Skills teach RedAmon&apos;s agent. Agent Onboarding teaches yours.</em>
        </p>

        <div className={styles.onboardNotice}>
          <AlertTriangle size={14} />
          <span>
            This generates a document. It does <strong>not</strong> change the token: ticking a
            permission here previews what the instructions would say, and grants nothing.
          </span>
        </div>

        <div className={`formGroup ${styles.field}`}>
          <label className="formLabel" htmlFor="onboardProfile">Agent Profile</label>
          <select
            id="onboardProfile"
            className={`select ${styles.control}`}
            value={profile}
            onChange={e => {
              const next = e.target.value as ProfileId
              setProfile(next)
              // The modal is a preview, so following the profile is the useful
              // default here; nothing is persisted either way.
              setScopes(scopesForProfile(next))
              setFiles(null)
            }}
          >
            {PROFILE_LIST.filter(p => profileOffered(p.id, loopOn)).map(p => (
              <option key={p.id} value={p.id}>{p.label}</option>
            ))}
          </select>
          <span className="formHint">{PROFILES[profile].blurb}</span>
        </div>

        <ScopeChecklist
          selected={scopes}
          profile={profile}
          loopOff={!loopOn}
          onToggle={s => {
            setScopes(prev => (prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]))
            setFiles(null)
          }}
        />

        {warnings.length > 0 && (
          <ul className={styles.onboardWarnings}>
            {warnings.map(w => <li key={w}>{w}</li>)}
          </ul>
        )}

        <div className={styles.onboardRow}>
          <div className={`formGroup ${styles.field}`}>
            <label className="formLabel" htmlFor="onboardUrl">Server URL</label>
            <input
              id="onboardUrl"
              className={`textInput ${styles.control}`}
              value={serverUrl}
              placeholder="https://your-redamon-host"
              onChange={e => { setServerUrl(e.target.value); setFiles(null) }}
            />
            <span className="formHint">Where your agent reaches this RedAmon.</span>
          </div>

          <div className={`formGroup ${styles.field}`}>
            <label className="formLabel" htmlFor="onboardStyle">Connection style</label>
            <select
              id="onboardStyle"
              className={`select ${styles.control}`}
              value={style}
              onChange={e => { setStyle(e.target.value as 'mcp' | 'http'); setFiles(null) }}
            >
              <option value="mcp">MCP client</option>
              <option value="http">Raw HTTP (adds curl examples)</option>
            </select>
          </div>

          <div className={`formGroup ${styles.field}`}>
            <label className="formLabel" htmlFor="onboardClient">Client</label>
            <select
              id="onboardClient"
              className={`select ${styles.control}`}
              value={client}
              onChange={e => { setClient(e.target.value as LoopClient); setFiles(null) }}
            >
              <option value="claude-code">Claude Code</option>
              <option value="codex">Codex</option>
              <option value="other">Other MCP client</option>
            </select>
          </div>

          <div className={`formGroup ${styles.field}`}>
            <label className="formLabel" htmlFor="onboardLayout">Output</label>
            <select
              id="onboardLayout"
              className={`select ${styles.control}`}
              value={layout}
              onChange={e => { setLayout(e.target.value as 'folder' | 'single'); setFiles(null) }}
            >
              <option value="folder">SKILL.md plus reference files</option>
              <option value="single">One single file</option>
            </select>
          </div>
        </div>

        {error && <div className={styles.errorBanner}>{error}</div>}

        <div className={styles.formActions}>
          <button className={styles.primaryBtn} onClick={() => void generate()} disabled={generating}>
            {generating ? <Loader2 className={styles.spin} size={14} /> : <GraduationCap size={14} />}
            {files ? 'Regenerate' : 'Generate'}
          </button>
        </div>

        {files && (
          <div className={styles.onboardResult}>
            <div className={styles.onboardTabs}>
              {files.map((f, i) => (
                <button
                  key={f.path}
                  className={`${styles.onboardTab} ${i === active ? styles.onboardTabActive : ''}`}
                  onClick={() => setActive(i)}
                >
                  <FileText size={12} /> {f.path}
                </button>
              ))}
            </div>

            <pre className={styles.onboardPreview}>{files[active].content}</pre>

            <div className={styles.onboardActions}>
              <button className={styles.secondaryBtn} onClick={() => void copy()}>
                {copied ? <Check size={14} /> : <Copy size={14} />} Copy this file
              </button>
              <button className={styles.secondaryBtn} onClick={() => download(files[active])}>
                <Download size={14} /> Download this file
              </button>
              <button
                className={styles.secondaryBtn}
                onClick={() => void downloadAll()}
                disabled={zipping}
              >
                {zipping ? <Loader2 className={styles.spin} size={14} /> : <Download size={14} />}
                Download all {files.length} as .zip
              </button>
            </div>

            <div className={styles.onboardHint}>
              <p>
                <strong>Where it goes.</strong> The archive already contains a{' '}
                <code className={styles.scopeCode}>{skillDir}/</code> folder with{' '}
                <code className={styles.scopeCode}>SKILL.md</code> at its root and the reference files
                under <code className={styles.scopeCode}>references/</code>,{' '}
                {client === 'codex' ? (
                  <>so for Codex unzip it into{' '}
                    <code className={styles.scopeCode}>.agents/skills/</code> in the folder you run
                    Codex from.</>
                ) : client === 'other' ? (
                  <>so put it wherever your client keeps skills.</>
                ) : profile === LOOP_PROFILE_ID ? (
                  <>so for Claude Code unzip it into{' '}
                    <code className={styles.scopeCode}>.claude/skills/</code> of an empty folder you
                    use only for this, and follow the Connecting steps in{' '}
                    <code className={styles.scopeCode}>SKILL.md</code>.</>
                ) : (
                  <>so for Claude Code and Claude Desktop just unzip it into{' '}
                    <code className={styles.scopeCode}>~/.claude/skills/</code>. Other clients have
                    their own skill directory.</>
                )}
              </p>
              <p>
                <strong>This is a second install.</strong> The MCP server config (the token and the
                URL) and this pack are two separate things: the config lets your agent connect, the
                pack teaches it what to do once connected.
              </p>
              <p>
                <strong>Not every client reads a pack.</strong> Claude Code and Claude Desktop load a{' '}
                <code className={styles.scopeCode}>SKILL.md</code>. Cursor, Windsurf, Cline, Goose,
                Gemini CLI, Codex CLI and anything built on an agent SDK do not. Those clients get a
                short version of the same guidance automatically when they connect, so nothing is
                missing and the download is a document for you to paste or adapt.
              </p>
              <p>
                <strong>Re-export after changes.</strong> A downloaded pack is a snapshot. Export
                again after editing the token, changing its profile, or upgrading RedAmon.
              </p>
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}

/** Only scopes this build still knows, so a stale row cannot break the checklist. */
export function knownScopes(raw: readonly string[]): McpScope[] {
  return MCP_SCOPES.filter(s => raw.includes(s))
}
