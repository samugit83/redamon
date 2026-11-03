'use client'

import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, GitBranch, Globe, Info, Lock } from 'lucide-react'
import { Modal } from '@/components/ui'
import { CredentialShortcut } from '@/components/settings/CredentialShortcut'
import { useCredentialKeys, type CredentialKeysApi } from '@/hooks/useCredentialKeys'
import { useAuth } from '@/providers/AuthProvider'
import { useOptionalProject } from '@/providers/ProjectProvider'
import { fetchJson, toApiError, type ApiError } from '@/lib/apiError'
import { credentialField } from '@/lib/credentialFields'
import { isGithubFamilyHost, isGithubFamilyUrl } from '@/lib/workspaceImport/githubHosts'
import { IMPORT_PRESETS } from '@/lib/workspaceImport/presets'
import { formatBytes } from './transferMessages'
import styles from './ImportUrlDialog.module.css'

// =============================================================================
// Kinds (shared with the drawer's badge and Properties)
// =============================================================================

const KIND_LABELS: Record<string, string> = {
  'github-repo': 'GitHub repository',
  'github-file': 'GitHub file',
  'github-gist': 'GitHub gist',
  'gitlab-repo': 'GitLab repository',
  'bitbucket-repo': 'Bitbucket repository',
  'codeberg-repo': 'Codeberg repository',
  git: 'Git repository',
  archive: 'Archive',
  file: 'File',
  'docs-site': 'Documentation site',
  website: 'Website',
}

const REPOSITORY_KINDS = new Set(['github-repo', 'gitlab-repo', 'bitbucket-repo', 'codeberg-repo', 'git'])
const SINGLE_FILE_KINDS = new Set(['github-file', 'file'])

export function importKindLabel(kind: string): string {
  return KIND_LABELS[kind] ?? kind
}

export function isRepositoryKind(kind: string | undefined): boolean {
  return !!kind && REPOSITORY_KINDS.has(kind)
}

/** Imports of these kinds save one file; every other kind saves a folder. */
export function importSavesFile(kind: string | undefined): boolean {
  return !!kind && SINGLE_FILE_KINDS.has(kind)
}

function ImportKindIcon({ kind }: { kind: string }) {
  return isRepositoryKind(kind) ? <GitBranch size={12} /> : <Globe size={12} />
}

// =============================================================================
// Types and words
// =============================================================================

interface Preview {
  kind: string
  url: string
  suggestedName: string
  host: string
  details: {
    ref?: string
    sha7?: string
    files?: number
    bytes?: number
    subpath?: string
    private?: boolean
    contentType?: string
  }
  warnings: string[]
  supported: boolean
}

/** What the import route answered (202), plus the link's host for the panel. */
export interface ImportJob {
  jobId: string
  kind: string
  destDir: string
  name: string
  host?: string
}

export interface ImportUrlDialogProps {
  onClose: () => void
  projectId: string
  /** The folder the drawer shows; the destination starts there. */
  defaultDestDir: string
  /**
   * A job for the Transfers panel to follow: the import this dialog started
   * (the dialog then closes), or the identical import already running (busy).
   */
  onImportJob: (job: ImportJob) => void
}

/**
 * A re-check of the same link (a new subfolder, a saved token) keeps showing
 * the preview it replaces, so the fields being edited stay mounted and focused.
 */
type Check =
  | { phase: 'idle' }
  | { phase: 'checking'; url: string; previous: Preview | null }
  | { phase: 'preview'; url: string; preview: Preview }
  | { phase: 'error'; url: string; error: ApiError }

type Conflict = 'keep_both' | 'replace'

const GITHUB_TOKEN_KEY = 'githubAccessToken'
const CHECK_FAILED = 'Could not check the link'
const IMPORT_FAILED = 'Could not start the import'

const WARNINGS: Record<string, string> = {
  history_not_included: 'Only the files are imported, not the git history.',
  tree_truncated: 'GitHub listed only part of this repository, so the file count and size are lower than the real ones.',
  large_download: 'Large download: it can take a while and fill a lot of disk space.',
  submodules_not_included: 'Git submodules are not included.',
}

const DISABLED_TEXT = 'URL import is turned off on this server.'
const NOT_SUPPORTED_TEXT = 'Websites and documentation sites can be previewed but not imported yet.'
const ACT_AS_TEXT = 'You are acting as another user, so GitHub imports run without a token: public repositories only.'
const NO_TOKEN_TEXT = 'No GitHub token: public repositories only, and GitHub allows this server 60 requests an hour '
  + 'without one (an import uses several). Add a token to import private repositories and lift the limit.'

/** The line a GitHub failure gets, and whether the token editor helps with it. */
function tokenAdvice(code: string | undefined, hasToken: boolean): { line: ReactNode; editor: boolean } | null {
  switch (code) {
    case 'not_found':
      return hasToken
        ? {
            line: <>If this repository is private, check that your GitHub token can read it (a classic token needs
              the <code>repo</code> scope; a fine-grained one needs read access to Contents).</>,
            editor: true,
          }
        : { line: 'If this repository is private, add a GitHub token that can read it.', editor: true }
    case 'rate_limited':
      return hasToken
        ? { line: "Your token's hourly GitHub limit is used up. Try again later.", editor: false }
        : { line: "GitHub's hourly limit for this server is used up. A token lifts it to 5,000 requests an hour.", editor: true }
    case 'auth_failed':
      return { line: 'GitHub refused your token: it may be expired or revoked. Replace it.', editor: true }
    default:
      return null
  }
}

function trimSlashes(s: string): string {
  return s.trim().replace(/^\/+|\/+$/g, '')
}

/** A workspace folder as the API takes it: "." for the root, no leading "/workspace/" as the breadcrumb shows it. */
function normalizeDestDir(raw: string): string {
  let s = raw.trim().replace(/\\/g, '/')
  if (/^\/workspace(\/|$)/.test(s)) s = s.slice('/workspace'.length)
  s = trimSlashes(s).replace(/^(\.\/)+/, '')
  return s || '.'
}

// =============================================================================
// Pieces
// =============================================================================

function PreviewFacts({ preview }: { preview: Preview }) {
  const d = preview.details
  const rows: Array<[string, ReactNode]> = [['Host', preview.host]]
  if (d.ref) {
    rows.push(['Ref', d.sha7 ? <><span>{d.ref}</span> · <code>{d.sha7}</code></> : <span>{d.ref}</span>])
  }
  if (typeof d.files === 'number') {
    rows.push(['Content', `${d.files.toLocaleString()} file${d.files === 1 ? '' : 's'} · ${formatBytes(d.bytes ?? 0)}`])
  } else if (typeof d.bytes === 'number') {
    rows.push(['Size', formatBytes(d.bytes)])
  }
  if (d.contentType) rows.push(['Type', d.contentType])

  return (
    <div className={styles.card} role="group" aria-label="Preview">
      <div className={styles.kindRow}>
        <ImportKindIcon kind={preview.kind} />
        <span className={styles.kindLabel}>{importKindLabel(preview.kind)}</span>
        {d.private && <span className={styles.privateTag}><Lock size={10} /> Private</span>}
      </div>
      <dl className={styles.facts}>
        {rows.map(([label, value]) => (
          <div key={label} className={styles.fact}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
      {preview.warnings.length > 0 && (
        <ul className={styles.warnings}>
          {preview.warnings.map((w) => (
            <li key={w}><AlertTriangle size={11} /> <span>{WARNINGS[w] ?? w}</span></li>
          ))}
        </ul>
      )}
    </div>
  )
}

function TokenEditor({ keys }: { keys: CredentialKeysApi }) {
  return (
    <>
      <CredentialShortcut settingsKey={GITHUB_TOKEN_KEY} keys={keys} optional compact />
      <p className={styles.hint}>
        This is the token Global Settings lists as {credentialField(GITHUB_TOKEN_KEY)?.label}.
      </p>
    </>
  )
}

// =============================================================================
// Dialog
// =============================================================================

/**
 * Paste a link, check it, import it into a workspace folder. Mount it to open
 * it: closing unmounts it, which drops whatever the user typed.
 *
 * The browser never sends a token. For a GitHub link the web app adds the
 * user's own token on the server, so this dialog only explains what a token
 * changes and lets the user save one in place.
 */
export function ImportUrlDialog({ onClose, projectId, defaultDestDir, onImportJob }: ImportUrlDialogProps) {
  const ids = { url: useId(), name: useId(), subpath: useId(), dest: useId(), conflict: useId() }

  const [url, setUrl] = useState('')
  const [check, setCheck] = useState<Check>({ phase: 'idle' })
  const [name, setName] = useState('')
  const [subpath, setSubpath] = useState('')
  const [destDir, setDestDir] = useState(defaultDestDir || '.')
  const [onConflict, setOnConflict] = useState<Conflict>('keep_both')
  const [importing, setImporting] = useState(false)
  const [importError, setImportError] = useState<ApiError | null>(null)
  const [runningJobId, setRunningJobId] = useState<string | null>(null)
  const [tokenSaved, setTokenSaved] = useState(false)

  const seq = useRef(0)
  const inflight = useRef<AbortController | null>(null)
  const lastCheck = useRef<{ url: string; subpath?: string } | null>(null)
  const nameEdited = useRef(false)

  const effectiveUserId = useOptionalProject()?.userId ?? null
  const signedInId = useAuth().user?.id
  // Saving a token now would write the simulated user's settings, and the
  // server sends no token under act-as anyway.
  const actingAs = Boolean(effectiveUserId && signedInId && effectiveUserId !== signedInId)
  const keys = useCredentialKeys()
  const hasToken = keys.isSet(GITHUB_TOKEN_KEY)

  useEffect(() => () => {
    seq.current++
    inflight.current?.abort()
  }, [])

  const cancelCheck = () => {
    seq.current++
    inflight.current?.abort()
    inflight.current = null
  }

  const runCheck = useCallback(async (target: string, sub?: string) => {
    const link = target.trim()
    if (!link) return
    inflight.current?.abort()
    const ctrl = new AbortController()
    inflight.current = ctrl
    const mine = ++seq.current
    lastCheck.current = { url: link, subpath: sub }
    setCheck((cur) => {
      const shown = cur.phase === 'preview' ? cur.preview : cur.phase === 'checking' ? cur.previous : null
      return { phase: 'checking', url: link, previous: 'url' in cur && cur.url === link ? shown : null }
    })
    setImportError(null)
    setRunningJobId(null)
    try {
      const preview = await fetchJson<Preview>('/api/agent/workspace/import-url/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, url: link, ...(sub !== undefined ? { subpath: sub } : {}) }),
        signal: ctrl.signal,
      }, CHECK_FAILED)
      if (mine !== seq.current) return
      setCheck({ phase: 'preview', url: link, preview })
      if (!nameEdited.current) setName(preview.suggestedName)
      setSubpath(preview.details?.subpath ?? '')
    } catch (e) {
      if (mine !== seq.current) return
      setCheck({ phase: 'error', url: link, error: toApiError(e, CHECK_FAILED) })
    }
  }, [projectId])

  // The webapp reads the token on the server at every request, so a check run
  // right after the save already uses it.
  const keysThatRecheck: CredentialKeysApi = {
    ...keys,
    save: async (key, value) => {
      const ok = await keys.save(key, value)
      if (ok && lastCheck.current) {
        setTokenSaved(true)
        void runCheck(lastCheck.current.url, lastCheck.current.subpath)
      }
      return ok
    },
  }

  const startCheckFromLink = (target: string) => {
    setTokenSaved(false)
    void runCheck(target)
  }

  const handleUrlChange = (value: string) => {
    setUrl(value)
    nameEdited.current = false
    setTokenSaved(false)
    if (check.phase !== 'idle') {
      cancelCheck()
      setCheck({ phase: 'idle' })
      setImportError(null)
      setRunningJobId(null)
    }
  }

  const checkedUrl = check.phase === 'idle' ? '' : check.url
  const preview = check.phase === 'preview' ? check.preview : check.phase === 'checking' ? check.previous : null
  const previewSubpath = preview?.details.subpath ?? ''
  const subpathStale = preview?.kind === 'github-repo' && trimSlashes(subpath) !== previewSubpath
  const disabled = (check.phase === 'error' && check.error.code === 'import_disabled')
    || importError?.code === 'import_disabled'
  const canImport = check.phase === 'preview' && check.preview.supported && !subpathStale && !importing && !disabled

  const startImport = async () => {
    if (check.phase !== 'preview' || !canImport) return
    const shown = check.preview
    const finalName = name.trim()
    const dest = normalizeDestDir(destDir)
    setImporting(true)
    setImportError(null)
    setRunningJobId(null)
    try {
      const started = await fetchJson<Omit<ImportJob, 'host'>>('/api/agent/workspace/import-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          url: check.url,
          destDir: dest,
          ...(finalName ? { name: finalName } : {}),
          onConflict,
          // What the preview showed, not the field: Import is off while they differ.
          options: shown.kind === 'github-repo' ? { subpath: previewSubpath } : {},
        }),
      }, IMPORT_FAILED)
      onImportJob({ ...started, host: shown.host })
      onClose()
    } catch (e) {
      const err = toApiError(e, IMPORT_FAILED)
      const jobId = typeof err.body?.jobId === 'string' ? err.body.jobId : ''
      if (err.code === 'busy' && jobId) {
        onImportJob({ jobId, kind: shown.kind, destDir: dest, name: finalName || shown.suggestedName, host: shown.host })
        setRunningJobId(jobId)
      } else {
        setImportError(err)
      }
      setImporting(false)
    }
  }

  // --- GitHub token help ----------------------------------------------------

  const failure = importError ?? (check.phase === 'error' ? check.error : null)
  const failureIsGithub = failure !== null && (
    preview ? isGithubFamilyHost(preview.host) : check.phase === 'error' && isGithubFamilyUrl(check.url))

  const renderFailureHelp = () => {
    if (!failure || !failureIsGithub || keys.loading) return null
    const advice = tokenAdvice(failure.code, hasToken)
    if (!advice) return null
    if (actingAs) return <p className={styles.note}><Info size={12} /> <span>{ACT_AS_TEXT}</span></p>
    return (
      <div className={styles.tokenHelp}>
        <p className={styles.adviceLine}>{advice.line}</p>
        {advice.editor && <TokenEditor keys={keysThatRecheck} />}
      </div>
    )
  }

  const renderPreviewHelp = () => {
    if (!preview || !isGithubFamilyHost(preview.host) || keys.loading) return null
    if (actingAs) return <p className={styles.note}><Info size={12} /> <span>{ACT_AS_TEXT}</span></p>
    if (hasToken) return null
    return (
      <div className={styles.tokenHelp}>
        <p className={styles.note}><Info size={12} /> <span>{NO_TOKEN_TEXT}</span></p>
        <TokenEditor keys={keysThatRecheck} />
      </div>
    )
  }

  // --- Render ---------------------------------------------------------------

  const footer = (
    <>
      <button type="button" className="secondaryButton" onClick={onClose}>Cancel</button>
      <button type="button" className="primaryButton" onClick={() => void startImport()} disabled={!canImport}>
        {importing ? 'Importing…' : 'Import'}
      </button>
    </>
  )

  return (
    <Modal isOpen onClose={onClose} title="Import from URL" footer={footer} className={styles.dialog}>
      <div className={styles.body}>
        <div className={styles.presets} role="group" aria-label="Quick import">
          {IMPORT_PRESETS.map((p) => (
            <button
              key={p.label}
              type="button"
              className={`chip chipClickable ${styles.preset}`}
              title={`${p.description}\n${p.url}`}
              onClick={() => {
                handleUrlChange(p.url)
                startCheckFromLink(p.url)
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        <div className={styles.field}>
          <label htmlFor={ids.url}>Link</label>
          <div className={styles.inline}>
            <input
              id={ids.url}
              className="textInput"
              type="url"
              inputMode="url"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              placeholder="https://github.com/owner/repository"
              value={url}
              onChange={(e) => handleUrlChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  startCheckFromLink(url)
                }
              }}
            />
            <button
              type="button"
              className="secondaryButton"
              onClick={() => startCheckFromLink(url)}
              disabled={!url.trim() || check.phase === 'checking'}
            >
              Check
            </button>
          </div>
          <p className={styles.hint}>
            A repository, a folder or a file on GitHub, a gist, a GitLab, Bitbucket or Codeberg repository, a git
            link, an archive or a file.
          </p>
        </div>

        {check.phase === 'checking' && (
          <div className={styles.checking} role="status" aria-label="Checking the link">
            <span className={`spinner spinnerSmall ${styles.spinner}`} aria-hidden="true" /> Checking…
          </div>
        )}

        {disabled ? (
          <p className={styles.disabled} role="status">{DISABLED_TEXT}</p>
        ) : (
          <>
            {tokenSaved && check.phase !== 'checking' && (
              <p className={styles.saved}>Token saved to Global Settings. The link was checked again with it.</p>
            )}
            {check.phase === 'error' && (
              <p className={styles.error} role="alert">{check.error.message}</p>
            )}
            {check.phase === 'error' && renderFailureHelp()}

            {preview && (
              <>
                <PreviewFacts preview={preview} />
                {!preview.supported && <p className={styles.note}><Info size={12} /> <span>{NOT_SUPPORTED_TEXT}</span></p>}
                {renderPreviewHelp()}

                {preview.supported && (
                  <>
                    <div className={styles.field}>
                      <label htmlFor={ids.name}>Name</label>
                      <input
                        id={ids.name}
                        className="textInput"
                        spellCheck={false}
                        autoComplete="off"
                        value={name}
                        placeholder={preview.suggestedName}
                        onChange={(e) => {
                          nameEdited.current = true
                          setName(e.target.value)
                        }}
                      />
                    </div>

                    {preview.kind === 'github-repo' && (
                      <div className={styles.field}>
                        <label htmlFor={ids.subpath}>Subfolder</label>
                        <div className={styles.inline}>
                          <input
                            id={ids.subpath}
                            className="textInput"
                            spellCheck={false}
                            autoComplete="off"
                            placeholder="the whole repository"
                            value={subpath}
                            onChange={(e) => setSubpath(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                e.preventDefault()
                                void runCheck(checkedUrl, trimSlashes(subpath))
                              }
                            }}
                          />
                          {subpathStale && (
                            <button
                              type="button"
                              className="secondaryButton"
                              onClick={() => void runCheck(checkedUrl, trimSlashes(subpath))}
                              disabled={check.phase === 'checking'}
                            >
                              Update
                            </button>
                          )}
                        </div>
                        {subpathStale && (
                          <p className={styles.hint}>Check again to preview this subfolder before importing it.</p>
                        )}
                      </div>
                    )}
                  </>
                )}
              </>
            )}

            {(preview?.supported ?? true) && (
              <div className={styles.field}>
                <label htmlFor={ids.dest}>Destination folder</label>
                <input
                  id={ids.dest}
                  className="textInput"
                  spellCheck={false}
                  autoComplete="off"
                  value={destDir}
                  placeholder="."
                  onChange={(e) => setDestDir(e.target.value)}
                />
                <p className={styles.hint}>A workspace folder, such as uploads or notes/wordlists. A dot is the workspace root.</p>
              </div>
            )}

            {(preview?.supported ?? true) && (
              <fieldset className={styles.conflict}>
                <legend>If the name is taken</legend>
                <label>
                  <input
                    type="radio"
                    name={ids.conflict}
                    checked={onConflict === 'keep_both'}
                    onChange={() => setOnConflict('keep_both')}
                  />
                  Keep both
                </label>
                <label>
                  <input
                    type="radio"
                    name={ids.conflict}
                    checked={onConflict === 'replace'}
                    onChange={() => setOnConflict('replace')}
                  />
                  Replace
                </label>
                {onConflict === 'replace' && (
                  <p className={styles.warningLine}>
                    <AlertTriangle size={11} /> <span>Replace overwrites the entry of that name in the folder, with everything inside it.</span>
                  </p>
                )}
              </fieldset>
            )}

            {importError && <p className={styles.error} role="alert">{importError.message}</p>}
            {importError && renderFailureHelp()}
            {runningJobId && (
              <p className={styles.note} role="status">
                <Info size={12} />{' '}
                <span>{`An identical import is already running (job ${runningJobId.slice(0, 8)}). Its progress is in the Transfers panel.`}</span>
              </p>
            )}
          </>
        )}
      </div>
    </Modal>
  )
}
