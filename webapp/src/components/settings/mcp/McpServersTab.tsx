'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { Plus, Pencil, Trash2, Loader2, AlertTriangle, CheckCircle2, XCircle, Server, Terminal, Globe, Zap, Eye, EyeOff } from 'lucide-react'
import {
  mcpServerSchema,
  PHASES,
  TRANSPORTS,
  BUILTIN_RESERVED_TOOL_NAMES,
  SYSTEM_SERVER_IDS,
  type MCPServer,
  type ToolSpec,
  type Transport,
  type Phase,
} from '@/lib/mcp/schema'
import { MCP_PRESETS, PRESET_CATEGORY_LABELS, type McpPreset } from '@/lib/mcp/presets'
import { useAlertModal, useToast } from '@/components/ui'
import { readApiError, toApiError, type ApiError } from '@/lib/apiError'
import { actionFailedText, failureText, saveWarningLines } from '../failureText'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import styles from './McpServersTab.module.css'

/**
 * The secret a save or test was refused for because the URL, or a stdio server's command,
 * changed (HD-24): `auth.token`, `headers.<name>` or `env.<name>`, with the server's sentence.
 */
function reentryOf(err: ApiError): { field: string; message: string } | null {
  const field = err.body?.field
  return err.code === 'secret_reentry_required' && typeof field === 'string' ? { field, message: err.reason } : null
}

interface Props {
  userId: string
  /** Reports unsaved-changes state to the parent (drives the tab-switch guard). */
  onDirtyChange?: (dirty: boolean) => void
}

interface TestResult {
  ok: boolean
  elapsed_ms: number
  discovered_tools: { name: string; description: string; input_schema: unknown }[]
  error: string | null
  warnings: { server_id: string; code: string; message: string }[]
}

/**
 * Render an MCP-server-provided JSON Schema as an LLM-friendly args
 * summary. Surfaces the full strategic info a model needs to call the
 * tool correctly: type · required-or-optional · enum constraints · default
 * value · min/max bounds · format hints · per-property description.
 *
 * Handles the common JSON-Schema shapes: primitive types, type unions,
 * enums, arrays (incl. arrays of objects), `oneOf` / `anyOf`, `const`.
 * Falls back to a placeholder when the schema is missing.
 *
 * Output format (one line per property when descriptions are present,
 * single comma-separated line when they aren't):
 *
 *   "q": <string>                  // Search query (GitHub syntax)
 *   "page": <number, optional, default 1, min 1>
 *   "perPage": <number, optional, default 30, max 100>  // Results per page
 *   "order": <"asc"|"desc", optional>  // Sort direction
 */
function argsFormatFromSchema(schema: unknown): string {
  if (!schema || typeof schema !== 'object') return '"...": "..."'
  const obj = schema as Record<string, unknown>
  const props = obj.properties as Record<string, Record<string, unknown>> | undefined
  if (!props || Object.keys(props).length === 0) return '"...": "..."'
  const required = new Set<string>(Array.isArray(obj.required) ? (obj.required as string[]) : [])

  const fmtType = (v: Record<string, unknown>): string => {
    if (Array.isArray(v.enum) && v.enum.length > 0) {
      const opts = (v.enum as unknown[]).slice(0, 4).map(e => JSON.stringify(e))
      return opts.join('|') + (v.enum.length > 4 ? '|...' : '')
    }
    if ('const' in v) return JSON.stringify((v as Record<string, unknown>).const)
    for (const key of ['oneOf', 'anyOf'] as const) {
      const branches = (v as Record<string, unknown>)[key]
      if (Array.isArray(branches) && branches.length > 0) {
        const sigs = branches.slice(0, 3).map(b => fmtType(b as Record<string, unknown>))
        return sigs.join('|') + (branches.length > 3 ? '|...' : '')
      }
    }
    const t = v.type
    if (typeof t === 'string') {
      if (t === 'array' && v.items && typeof v.items === 'object') {
        return `array<${fmtType(v.items as Record<string, unknown>)}>`
      }
      if (t === 'object') return 'object'
      return t
    }
    if (Array.isArray(t)) return (t as string[]).join('|')
    return 'any'
  }

  /** Collect numeric/string/format constraints into a comma-suffix list. */
  const fmtConstraints = (v: Record<string, unknown>): string[] => {
    const out: string[] = []
    if ('default' in v) out.push(`default ${JSON.stringify((v as Record<string, unknown>).default)}`)
    if (typeof v.minimum === 'number') out.push(`min ${v.minimum}`)
    if (typeof v.maximum === 'number') out.push(`max ${v.maximum}`)
    if (typeof v.minLength === 'number') out.push(`minLen ${v.minLength}`)
    if (typeof v.maxLength === 'number') out.push(`maxLen ${v.maxLength}`)
    if (typeof v.minItems === 'number') out.push(`minItems ${v.minItems}`)
    if (typeof v.maxItems === 'number') out.push(`maxItems ${v.maxItems}`)
    if (typeof v.format === 'string') out.push(`format=${v.format}`)
    if (typeof v.pattern === 'string') out.push('regex-constrained')
    return out
  }

  const fmtDescription = (v: Record<string, unknown>): string => {
    const d = v.description
    if (typeof d !== 'string') return ''
    const trimmed = d.trim().replace(/\s+/g, ' ')
    if (!trimmed) return ''
    return trimmed.length > 140 ? trimmed.slice(0, 140) + '…' : trimmed
  }

  const entries = Object.entries(props)
  const hasAnyDescription = entries.some(([, v]) => fmtDescription(v) !== '')

  const fmtSig = (k: string, v: Record<string, unknown>): string => {
    const type = fmtType(v)
    const tag = required.has(k) ? type : `${type}, optional`
    const constraints = fmtConstraints(v)
    const constraintStr = constraints.length ? `, ${constraints.join(', ')}` : ''
    return `"${k}": <${tag}${constraintStr}>`
  }

  if (hasAnyDescription) {
    // Multi-line layout: signature on the left, description after `//`.
    const lines = entries.slice(0, 12).map(([k, v]) => {
      const sig = fmtSig(k, v)
      const desc = fmtDescription(v)
      return desc ? `${sig}  // ${desc}` : sig
    })
    if (entries.length > 12) lines.push('// ... ' + (entries.length - 12) + ' more property/properties')
    return lines.join('\n')
  }
  // Compact one-liner when the schema has no per-property descriptions.
  const parts = entries.slice(0, 8).map(([k, v]) => fmtSig(k, v))
  if (entries.length > 8) parts.push('...')
  return parts.join(', ')
}

function emptyTool(): ToolSpec {
  return {
    name: '',
    purpose: '',
    when_to_use: '',
    args_format: '',
    description: '',
    default_phases: undefined,
  }
}

function emptyServer(): MCPServer {
  return {
    id: '',
    name: '',
    description: '',
    enabled: true,
    transport: 'streamable_http',
    default_phases: [...PHASES],
    tags: [],
    url: '',
    headers: {},
    auth: undefined,
    connect_timeout: 60,
    read_timeout: 600,
    command: '',
    args: [],
    env: {},
    cwd: '',
    encoding: 'utf-8',
    tools: [],
  }
}

function transportIcon(t: Transport) {
  if (t === 'stdio') return <Terminal size={14} />
  return <Globe size={14} />
}

const LOAD_FAILED = "Couldn't load your MCP Tool Plugins"

export default function McpServersTab({ userId, onDirtyChange }: Props) {
  const [servers, setServers] = useState<MCPServer[]>([])
  const [loading, setLoading] = useState(false)
  // Never a silent empty list: that reads as "nothing saved" and invites a duplicate.
  const [loadError, setLoadError] = useState<string | null>(null)
  const [editing, setEditing] = useState<MCPServer | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [topLevelError, setTopLevelError] = useState<string | null>(null)
  const [tokenVisible, setTokenVisible] = useState(false)
  // Focus target after a re-entry refusal: the token input, the headers box or the env box.
  const tokenInput = useRef<HTMLInputElement | null>(null)
  const headersInput = useRef<HTMLTextAreaElement | null>(null)
  const envInput = useRef<HTMLTextAreaElement | null>(null)
  const [reentryFocus, setReentryFocus] = useState<{ field: string } | null>(null)
  useEffect(() => {
    if (!reentryFocus) return
    const { field } = reentryFocus
    const target = field === 'auth.token' ? tokenInput.current
      : field.startsWith('env.') ? envInput.current : headersInput.current
    target?.focus()
  }, [reentryFocus])
  const { dangerConfirm, alertError } = useAlertModal()
  const toast = useToast()

  // The save is stored even when the agent did not reload it; say so.
  const warnIfNotReloaded = useCallback((body: unknown) => {
    const lines = saveWarningLines(body)
    if (lines.length) toast.warning(lines.join('\n'), 'Saved, but not live yet')
  }, [toast])

  // Dirty tracking only matters in the edit/add view. Baseline is set when
  // entering that view: an existing server for edit (dirty on any change), or an
  // empty server for new/preset (so a prefilled preset is dirty and saveable).
  const { isDirty: editingChanged, setBaseline } = useDirtyState<MCPServer | null>(editing)
  const dirty = editing != null && editingChanged
  // Local-only: the parent /settings page owns the global sidebar/beforeunload
  // guard via onDirtyChange (avoids a duplicate confirm).
  const { guardedNavigate } = useUnsavedChangesGuard(dirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(dirty) }, [dirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await fetch(`/api/users/${userId}/mcp`)
      if (r.ok) {
        const data = await r.json()
        setServers(Array.isArray(data.servers) ? data.servers : [])
        setLoadError(null)
      } else {
        setLoadError(failureText(LOAD_FAILED, await readApiError(r, LOAD_FAILED)))
      }
    } catch (e) {
      console.error('load mcp servers', e)
      setLoadError(failureText(LOAD_FAILED, e))
    } finally {
      setLoading(false)
    }
  }, [userId])

  useEffect(() => {
    if (userId) load()
  }, [userId, load])

  const startNew = () => {
    setEditing(emptyServer())
    setBaseline(emptyServer())
    setIsNew(true)
    setErrors({})
    setTestResult(null)
    setTopLevelError(null)
  }

  const startFromPreset = (preset: McpPreset) => {
    // Deep-clone the template and append a numeric suffix to id if it would
    // collide with an existing server (so picking the same preset twice
    // produces "github" then "github-2", not a save error).
    const taken = new Set(servers.map(s => s.id))
    let id = preset.template.id
    if (taken.has(id)) {
      let n = 2
      while (taken.has(`${id}-${n}`)) n++
      id = `${id}-${n}`
    }
    const cloned: MCPServer = JSON.parse(JSON.stringify(preset.template))
    cloned.id = id
    setEditing(cloned)
    // Baseline = empty, so the prefilled preset is immediately dirty/saveable.
    setBaseline(emptyServer())
    setIsNew(true)
    setErrors({})
    setTestResult(null)
    setTopLevelError(null)
  }

  const startEdit = (srv: MCPServer) => {
    setEditing({ ...srv })
    setBaseline({ ...srv })
    setIsNew(false)
    setErrors({})
    setTestResult(null)
    setTopLevelError(null)
  }

  const cancel = () => {
    setEditing(null)
    setErrors({})
    setTestResult(null)
    setTopLevelError(null)
  }

  const validate = (srv: MCPServer): Record<string, string> => {
    const parsed = mcpServerSchema.safeParse(srv)
    const out: Record<string, string> = {}
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        out[issue.path.join('.')] = issue.message
      }
    }
    return out
  }

  const onTest = async () => {
    if (!editing) return
    setTesting(true)
    setTestResult(null)
    try {
      // Test is for connection check + tool discovery, NOT strict validation.
      // Strip incomplete tool rows so the user can click Test before they've
      // filled in the four strategic fields (purpose / when_to_use /
      // args_format / description). Strict validation runs on Save.
      const draft = {
        ...editing,
        tools: editing.tools.filter(t =>
          t.name && t.purpose && t.when_to_use && t.args_format && t.description,
        ),
      }
      const r = await fetch('/api/mcp/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server: draft, userId }),
      })
      if (!r.ok) {
        const err = await readApiError(r, 'The MCP test failed')
        const reentry = reentryOf(err)
        if (reentry) {
          setErrors({ [reentry.field]: reentry.message })
          setReentryFocus({ field: reentry.field })
        }
        throw err
      }
      const data = await r.json() as Partial<TestResult>
      setTestResult({
        ok: data.ok === true,
        elapsed_ms: typeof data.elapsed_ms === 'number' ? data.elapsed_ms : 0,
        discovered_tools: Array.isArray(data.discovered_tools) ? data.discovered_tools : [],
        error: typeof data.error === 'string' ? data.error : null,
        warnings: Array.isArray(data.warnings) ? data.warnings : [],
      })
    } catch (e) {
      setTestResult({
        ok: false,
        elapsed_ms: 0,
        discovered_tools: [],
        error: toApiError(e, 'The MCP test failed').message,
        warnings: [],
      })
    } finally {
      setTesting(false)
    }
  }

  const onSave = async () => {
    if (!editing) return
    const localErrors = validate(editing)
    if (Object.keys(localErrors).length > 0) {
      setErrors(localErrors)
      return
    }
    setSaving(true)
    setTopLevelError(null)
    try {
      const url = isNew
        ? `/api/users/${userId}/mcp`
        : `/api/users/${userId}/mcp/${encodeURIComponent(editing.id)}`
      const r = await fetch(url, {
        method: isNew ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editing),
      })
      if (!r.ok) {
        const err = await readApiError(r, isNew ? 'Failed to add the MCP Tool Plugin' : 'Failed to update the MCP Tool Plugin')
        setTopLevelError(err.message)
        const issues = err.body?.issues
        if (Array.isArray(issues)) {
          const issueMap: Record<string, string> = {}
          for (const i of issues) {
            issueMap[(i.path || []).join('.')] = i.message
          }
          setErrors(issueMap)
        }
        const reentry = reentryOf(err)
        if (reentry) {
          setErrors({ [reentry.field]: reentry.message })
          setReentryFocus({ field: reentry.field })
        }
        return
      }
      warnIfNotReloaded(await r.json().catch(() => null))
      await load()
      setEditing(null)
      setErrors({})
      setTestResult(null)
    } catch (e) {
      setTopLevelError(toApiError(e, isNew ? 'Failed to add the MCP Tool Plugin' : 'Failed to update the MCP Tool Plugin').message)
    } finally {
      setSaving(false)
    }
  }

  const onDelete = async (serverId: string) => {
    const confirmed = await dangerConfirm(
      `Delete MCP Tool Plugin '${serverId}'? This cannot be undone.`,
      'Delete MCP Tool Plugin',
    )
    if (!confirmed) return
    try {
      const r = await fetch(`/api/users/${userId}/mcp/${encodeURIComponent(serverId)}`, {
        method: 'DELETE',
      })
      if (r.ok) {
        warnIfNotReloaded(await r.json().catch(() => null))
        await load()
      } else {
        await alertError((await readApiError(r, 'Delete failed')).message, 'Delete MCP Tool Plugin')
      }
    } catch (e) {
      await alertError(toApiError(e, 'Delete failed').message, 'Delete MCP Tool Plugin')
    }
  }

  const onToggleEnabled = async (srv: MCPServer) => {
    const updated = { ...srv, enabled: !srv.enabled }
    try {
      const r = await fetch(`/api/users/${userId}/mcp/${encodeURIComponent(srv.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
      })
      if (!r.ok) throw await readApiError(r, 'the server gave no reason')
      warnIfNotReloaded(await r.json().catch(() => null))
      await load()
    } catch (e) {
      console.error('toggle enabled', e)
      toast.error(actionFailedText(updated.enabled ? 'Enable' : 'Disable', e))
    }
  }

  const updateField = <K extends keyof MCPServer>(key: K, value: MCPServer[K]) => {
    if (!editing) return
    setEditing({ ...editing, [key]: value })
  }

  const updateTool = (idx: number, partial: Partial<ToolSpec>) => {
    if (!editing) return
    const tools = editing.tools.map((t, i) => (i === idx ? { ...t, ...partial } : t))
    setEditing({ ...editing, tools })
  }

  const addTool = () => {
    if (!editing) return
    setEditing({ ...editing, tools: [...editing.tools, emptyTool()] })
  }

  const removeTool = (idx: number) => {
    if (!editing) return
    setEditing({ ...editing, tools: editing.tools.filter((_, i) => i !== idx) })
  }

  const buildToolFromDiscovery = (
    name: string,
    description: string,
    inputSchema: unknown,
  ): ToolSpec => {
    const desc = description || '(filled from MCP server - please refine)'
    return {
      name,
      description: desc,
      // First line of the MCP description is usually a one-line summary -
      // good enough as a default purpose. User can refine.
      purpose: desc.split('\n')[0].slice(0, 120) || name,
      // when_to_use is the only field the user genuinely has to think
      // about (it's the LLM's tool-selection signal). Seed it with the
      // description so save isn't blocked, but flag for refinement.
      when_to_use: desc.split('\n')[0].slice(0, 200) || `Use ${name} when relevant.`,
      args_format: argsFormatFromSchema(inputSchema),
    }
  }

  const importDiscoveredTool = (
    name: string,
    description: string,
    inputSchema: unknown,
  ) => {
    if (BUILTIN_RESERVED_TOOL_NAMES.has(name)) return
    setEditing(prev => {
      if (!prev) return prev
      if (prev.tools.some(t => t.name === name)) return prev
      return {
        ...prev,
        tools: [...prev.tools, buildToolFromDiscovery(name, description, inputSchema)],
      }
    })
  }

  const importAllDiscoveredTools = (
    discovered: Array<{ name: string; description: string; input_schema: unknown }>,
  ) => {
    setEditing(prev => {
      if (!prev) return prev
      const existing = new Set(prev.tools.map(t => t.name))
      const additions: ToolSpec[] = []
      for (const d of discovered) {
        if (existing.has(d.name)) continue
        if (BUILTIN_RESERVED_TOOL_NAMES.has(d.name)) continue
        additions.push(buildToolFromDiscovery(d.name, d.description, d.input_schema))
        existing.add(d.name)
      }
      return additions.length === 0 ? prev : { ...prev, tools: [...prev.tools, ...additions] }
    })
  }

  // ===== List View =====
  if (!editing) {
    return (
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <div>
            <h2 className={styles.sectionTitle}>
              <Server size={18} /> MCP Tool Plugins
            </h2>
            <p className={styles.sectionDescription}>
              Plug Model-Context-Protocol (MCP) servers into the agent to extend its tool arsenal.
              New tools auto-appear in every project&apos;s Tool Matrix with all three phases enabled by default.
            </p>
          </div>
          <button className={styles.primaryBtn} onClick={startNew}>
            <Plus size={14} /> Add MCP
          </button>
        </div>

        {loading && <p className={styles.muted}><Loader2 className={styles.spin} size={14} /> Loading…</p>}

        {!loading && loadError && (
          <div className={styles.errorBanner} role="alert">
            <AlertTriangle size={14} /> {loadError}.{' '}
            <button type="button" className="textButton" onClick={load}>Retry</button>
          </div>
        )}

        {/* Quick-Add presets - 10 publicly-available MCPs vetted for pentest workflow */}
        {!loading && (
          <div className={styles.presetsBlock}>
            <div className={styles.presetsHeader}>
              <strong>Quick add</strong>
              <span className={styles.muted} style={{ fontSize: '11px', marginLeft: 'var(--space-2)' }}>
                click a preset → form opens prefilled (paste your API key if needed, then Save)
              </span>
            </div>
            <div className={styles.presetsGrid}>
              {MCP_PRESETS.map(preset => {
                const alreadyAdded = servers.some(s => s.id === preset.template.id)
                return (
                  <button
                    key={preset.key}
                    className={styles.presetCard}
                    onClick={() => startFromPreset(preset)}
                    title={preset.whyForRedamon}
                  >
                    <div className={styles.presetCardTop}>
                      <span className={styles.presetCardLabel}>{preset.label}</span>
                      <span className={styles.presetCategoryTag}>{PRESET_CATEGORY_LABELS[preset.category]}</span>
                    </div>
                    <div className={styles.presetCardBlurb}>{preset.blurb}</div>
                    <div className={styles.presetCardFooter}>
                      <span className={styles.presetTransportTag}>{preset.template.transport}</span>
                      {preset.authRequired && (
                        <span className={styles.presetAuthTag}>auth</span>
                      )}
                      {alreadyAdded && (
                        <span className={styles.presetAddedTag}>already added</span>
                      )}
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {!loading && !loadError && servers.length === 0 && (
          <p className={styles.muted}>No saved MCP Tool Plugins yet - pick one from Quick add above, or click Add MCP to configure one manually.</p>
        )}

        {!loading && servers.length > 0 && (
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Name</th>
                <th>Transport</th>
                <th>Tools</th>
                <th>Enabled</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {servers.map(srv => (
                <tr key={srv.id}>
                  <td>
                    <div className={styles.cellTitle}>{srv.name || srv.id}</div>
                    <div className={styles.cellSub}>{srv.id}{srv.description ? ` - ${srv.description}` : ''}</div>
                  </td>
                  <td>
                    <span className={styles.transportPill}>
                      {transportIcon(srv.transport)} {srv.transport}
                    </span>
                  </td>
                  <td>{srv.tools.length}</td>
                  <td>
                    <label className={styles.switch}>
                      <input
                        type="checkbox"
                        checked={srv.enabled}
                        onChange={() => onToggleEnabled(srv)}
                      />
                      <span></span>
                    </label>
                  </td>
                  <td>
                    <button className={styles.iconBtn} onClick={() => startEdit(srv)} title="Edit">
                      <Pencil size={14} />
                    </button>
                    <button className={styles.iconBtn} onClick={() => onDelete(srv.id)} title="Delete">
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    )
  }

  // ===== Edit / Add View =====
  const isHttp = editing.transport === 'sse' || editing.transport === 'streamable_http'
  const errOf = (k: string) => errors[k]
  const idLocked = !isNew  // never let users change a server id once saved

  return (
    <div className={styles.section}>
      <div className={`${styles.sectionHeader} ${styles.stickyHeader}`}>
        <h2 className={styles.sectionTitle}>
          <Server size={18} /> {isNew ? 'Add MCP' : `Edit MCP Tool Plugin: ${editing.id}`}
        </h2>
        <div className={styles.headerActions}>
          <button className={styles.discoverBtn} onClick={onTest} disabled={testing}>
            {testing
              ? <><Loader2 className={styles.spin} size={14} /> Discovering…</>
              : <><Zap size={14} /> Discover and add new tools</>}
          </button>
          <button className={styles.secondaryBtn} onClick={() => guardedNavigate(cancel)} disabled={saving}>Cancel</button>
          <button className={styles.primaryBtn} onClick={onSave} disabled={saving || !dirty}>
            {saving ? <><Loader2 className={styles.spin} size={14} /> Saving…</> : 'Save'}
          </button>
        </div>
      </div>

      {topLevelError && (
        <div className={styles.errorBanner}>
          <AlertTriangle size={14} /> {topLevelError}
        </div>
      )}

      {testResult && (
        <div className={testResult.ok ? styles.testOk : styles.testFail}>
          {testResult.ok ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
          {testResult.ok
            ? <span><strong>OK</strong> - {testResult.discovered_tools.length} tool(s) discovered in {testResult.elapsed_ms}ms.</span>
            : <span><strong>Failed</strong> - {testResult.error}</span>}
          {testResult.warnings.length > 0 && (
            <ul className={styles.warnList}>
              {testResult.warnings.map((w, i) => (
                <li key={i}><AlertTriangle size={12} /> [{w.code}] {w.message}</li>
              ))}
            </ul>
          )}
          {testResult.ok && testResult.discovered_tools.length > 0 && (
            <div className={styles.discoveredToolsBlock}>
              <div className={styles.discoveredHeader}>
                <strong>Discovered tools ({testResult.discovered_tools.length})</strong>
                <button
                  className={styles.primaryBtn}
                  onClick={() => importAllDiscoveredTools(testResult.discovered_tools)}
                  style={{ padding: '4px 10px', fontSize: '12px' }}
                >
                  <Plus size={12} /> Add all
                </button>
              </div>
              <div className={styles.discoveredTableWrap}>
                <table className={styles.discoveredTable}>
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Description</th>
                      <th style={{ width: '160px', textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {testResult.discovered_tools.map(t => {
                      const alreadyAdded = editing.tools.some(x => x.name === t.name)
                      const reserved = BUILTIN_RESERVED_TOOL_NAMES.has(t.name)
                      const desc = t.description || '(no description)'
                      return (
                        <tr key={t.name}>
                          <td><code>{t.name}</code></td>
                          <td className={styles.discoveredDescCell}>
                            {desc.length > 160 ? desc.slice(0, 160) + '…' : desc}
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            {!alreadyAdded && !reserved && (
                              <button
                                className={styles.secondaryBtn}
                                onClick={() => importDiscoveredTool(t.name, t.description, t.input_schema)}
                                style={{ padding: '3px 8px', fontSize: '11px' }}
                              >
                                <Plus size={11} /> Add
                              </button>
                            )}
                            {alreadyAdded && <span className={styles.tag}>already added</span>}
                            {reserved && <span className={styles.tagWarn}>reserved</span>}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      <div className={styles.formGrid}>
        <label className={styles.field}>
          <span>id</span>
          <input
            type="text"
            value={editing.id}
            onChange={e => updateField('id', e.target.value)}
            disabled={idLocked}
            placeholder="my-mcp"
          />
          {errOf('id') && <span className={styles.fieldErr}>{errOf('id')}</span>}
          {idLocked && <span className={styles.muted}>id is immutable after creation</span>}
        </label>

        <label className={styles.field}>
          <span>name</span>
          <input
            type="text"
            value={editing.name}
            onChange={e => updateField('name', e.target.value)}
            placeholder="My MCP Tool Plugin"
          />
          {errOf('name') && <span className={styles.fieldErr}>{errOf('name')}</span>}
        </label>

        <label className={`${styles.field} ${styles.fieldWide}`}>
          <span>description</span>
          <input
            type="text"
            value={editing.description}
            onChange={e => updateField('description', e.target.value)}
            placeholder="Short summary shown in the project Tool Matrix"
          />
        </label>

        <label className={styles.field}>
          <span>transport</span>
          <select value={editing.transport} onChange={e => updateField('transport', e.target.value as Transport)}>
            {TRANSPORTS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>

        <label className={styles.field}>
          <span>enabled</span>
          <select value={editing.enabled ? '1' : '0'} onChange={e => updateField('enabled', e.target.value === '1')}>
            <option value="1">yes</option>
            <option value="0">no</option>
          </select>
        </label>

        <label className={`${styles.field} ${styles.fieldWide}`}>
          <span>default phases (apply to tools that don&apos;t override)</span>
          <div className={styles.phasesRow}>
            {PHASES.map(p => (
              <label key={p} className={styles.checkInline}>
                <input
                  type="checkbox"
                  checked={editing.default_phases.includes(p)}
                  onChange={e => updateField('default_phases',
                    e.target.checked
                      ? [...editing.default_phases, p]
                      : editing.default_phases.filter(x => x !== p) as Phase[],
                  )}
                />
                {p}
              </label>
            ))}
          </div>
        </label>

        <label className={`${styles.field} ${styles.fieldWide}`}>
          <span>tags (comma-separated, optional)</span>
          <input
            type="text"
            value={(editing.tags || []).join(', ')}
            onChange={e => updateField('tags',
              e.target.value.split(',').map(s => s.trim()).filter(s => s !== ''),
            )}
            placeholder="osint, recon, threat-intel"
          />
          <span className={styles.muted} style={{ fontSize: '11px' }}>
            Cosmetic labels shown on the server card. No functional effect.
          </span>
        </label>

        {isHttp && (
          <>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>url</span>
              <input
                type="text"
                value={editing.url || ''}
                onChange={e => updateField('url', e.target.value)}
                placeholder="http://my-mcp:8080/mcp or https://api.example.com/mcp/sse"
              />
              {errOf('url') && <span className={styles.fieldErr}>{errOf('url')}</span>}
            </label>
            <label className={styles.field}>
              <span>connect_timeout (s)</span>
              <input
                type="number"
                value={editing.connect_timeout}
                onChange={e => updateField('connect_timeout', parseInt(e.target.value, 10) || 60)}
              />
            </label>
            <label className={styles.field}>
              <span>read_timeout (s)</span>
              <input
                type="number"
                value={editing.read_timeout}
                onChange={e => updateField('read_timeout', parseInt(e.target.value, 10) || 600)}
              />
            </label>
            <div className={`${styles.field} ${styles.fieldWide}`}>
              <span>auth (bearer token, optional)</span>
              <div className={styles.tokenInputRow}>
                <input
                  ref={tokenInput}
                  aria-label="bearer token"
                  type={tokenVisible ? 'text' : 'password'}
                  value={editing.auth?.token || ''}
                  onChange={e => updateField('auth', e.target.value
                    ? { type: 'bearer', token: e.target.value }
                    : undefined)}
                  placeholder="paste token here (e.g. ghp_...) - stored in DB, masked on display"
                  autoComplete="off"
                  spellCheck={false}
                />
                <button
                  type="button"
                  className={styles.iconBtn}
                  onClick={() => setTokenVisible(v => !v)}
                  title={tokenVisible ? 'Hide token' : 'Show token'}
                >
                  {tokenVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <span className={styles.muted} style={{ fontSize: '11px' }}>
                Sent as <code>Authorization: Bearer …</code> on every MCP request.
              </span>
              {errOf('auth.token') && <span className={styles.fieldErr} role="alert">{errOf('auth.token')}</span>}
            </div>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>custom headers (one per line, <code>Header-Name: value</code>)</span>
              <textarea
                ref={headersInput}
                rows={3}
                value={Object.entries(editing.headers || {}).map(([k, v]) => `${k}: ${v}`).join('\n')}
                onChange={e => {
                  const next: Record<string, string> = {}
                  for (const line of e.target.value.split('\n')) {
                    const trimmed = line.trim()
                    if (!trimmed) continue
                    const colonIdx = trimmed.indexOf(':')
                    if (colonIdx <= 0) continue
                    const k = trimmed.slice(0, colonIdx).trim()
                    const v = trimmed.slice(colonIdx + 1).trim()
                    if (k) next[k] = v
                  }
                  updateField('headers', next)
                }}
                placeholder="X-Organization-ID: abc-123&#10;X-Custom-Tenant: my-team"
              />
              <span className={styles.muted} style={{ fontSize: '11px' }}>
                Sent verbatim on every MCP request alongside the bearer token. Used by multi-tenant APIs (e.g. Censys requires <code>X-Organization-ID</code>).
              </span>
              {Object.keys(errors).filter(k => k.startsWith('headers.')).map(k => (
                <span key={k} className={styles.fieldErr} role="alert">{errors[k]}</span>
              ))}
            </label>
          </>
        )}

        {!isHttp && (
          <>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>command</span>
              <input
                type="text"
                value={editing.command || ''}
                onChange={e => updateField('command', e.target.value)}
                placeholder="uvx, npx, python, ..."
              />
              {errOf('command') && <span className={styles.fieldErr}>{errOf('command')}</span>}
            </label>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>args (one per line)</span>
              <textarea
                rows={3}
                value={(editing.args || []).join('\n')}
                onChange={e => updateField('args', e.target.value.split('\n').map(s => s).filter(s => s !== ''))}
                placeholder="duckduckgo-mcp-server"
              />
            </label>
            <label className={styles.field}>
              <span>cwd</span>
              <input
                type="text"
                value={editing.cwd || ''}
                onChange={e => updateField('cwd', e.target.value)}
                placeholder="/tmp (optional)"
              />
            </label>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>env vars (one per line, <code>KEY=VALUE</code>)</span>
              <textarea
                ref={envInput}
                rows={4}
                value={Object.entries(editing.env || {}).map(([k, v]) => `${k}=${v}`).join('\n')}
                onChange={e => {
                  const next: Record<string, string> = {}
                  for (const line of e.target.value.split('\n')) {
                    const trimmed = line.trim()
                    if (!trimmed || trimmed.startsWith('#')) continue
                    const eqIdx = trimmed.indexOf('=')
                    if (eqIdx <= 0) continue
                    const k = trimmed.slice(0, eqIdx).trim()
                    const v = trimmed.slice(eqIdx + 1)
                    if (k) next[k] = v
                  }
                  updateField('env', next)
                }}
                placeholder="SHODAN_API_KEY=kQDRu5etVi2vSb1LjopLSlIKDMRDFtkR&#10;ANOTHER_VAR=optional-second-line"
                autoComplete="off"
                spellCheck={false}
              />
              <span className={styles.muted} style={{ fontSize: '11px' }}>
                Passed to the spawned process as environment variables. Used by stdio MCPs that read API keys from env (Shodan, VirusTotal, Snyk, etc.). Stored as plaintext in the DB.
              </span>
              {Object.keys(errors).filter(k => k.startsWith('env.')).map(k => (
                <span key={k} className={styles.fieldErr} role="alert">{errors[k]}</span>
              ))}
            </label>
          </>
        )}
      </div>

      <h3 className={styles.subTitle}>
        Tools <span className={styles.muted}>({editing.tools.length})</span>
        <button
          className={styles.secondaryBtn}
          onClick={addTool}
          style={{ marginLeft: 'auto', padding: '4px 10px', fontSize: '12px' }}
        >
          <Plus size={12} /> Add Tool Manually
        </button>
      </h3>
      <p className={styles.sectionDescription}>
        Each tool needs all four strategic fields filled. Use <strong>Discover and add new tools</strong> to import live tools from the server, or add them manually.
      </p>

      {editing.tools.length === 0 && (
        <p className={styles.muted}>No tools yet. Click &ldquo;Discover and add new tools&rdquo; (top of page) or &ldquo;Add Tool Manually&rdquo; above.</p>
      )}

      {editing.tools.map((t, i) => (
        <div key={i} className={styles.toolBlock}>
          <div className={styles.toolHeader}>
            <strong>Tool #{i + 1}</strong>
            <button className={styles.iconBtn} onClick={() => removeTool(i)} title="Remove tool">
              <Trash2 size={14} />
            </button>
          </div>
          <div className={styles.formGrid}>
            <label className={styles.field}>
              <span>
                name
                <span className={styles.injectedBadge} title="Injected into the LLM system prompt's tool_name enum (every iteration)">
                  → injected in LLM prompt
                </span>
              </span>
              <input
                type="text"
                value={t.name}
                onChange={e => updateTool(i, { name: e.target.value })}
                placeholder="my_tool_name"
              />
              {errOf(`tools.${i}.name`) && <span className={styles.fieldErr}>{errOf(`tools.${i}.name`)}</span>}
            </label>
            <label className={styles.field}>
              <span>
                purpose
                <span className={styles.injectedBadge} title="Injected into the system prompt's tool availability table (every iteration)">
                  → injected in LLM prompt
                </span>
              </span>
              <input
                type="text"
                value={t.purpose}
                onChange={e => updateTool(i, { purpose: e.target.value })}
                placeholder="One-line summary"
              />
              {errOf(`tools.${i}.purpose`) && <span className={styles.fieldErr}>{errOf(`tools.${i}.purpose`)}</span>}
            </label>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>
                when_to_use
                <span className={styles.injectedBadge} title="Injected into the system prompt's tool availability table (every iteration). Strategic signal for tool selection.">
                  → injected in LLM prompt
                </span>
              </span>
              <input
                type="text"
                value={t.when_to_use}
                onChange={e => updateTool(i, { when_to_use: e.target.value })}
                placeholder="Strategic guidance - when should the agent pick this?"
              />
              {errOf(`tools.${i}.when_to_use`) && <span className={styles.fieldErr}>{errOf(`tools.${i}.when_to_use`)}</span>}
            </label>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>
                args_format
                <span className={styles.injectedBadge} title="Injected verbatim into the system prompt's `### Tool Arguments:` section (every iteration). The LLM mimics this pattern when shaping tool_args JSON.">
                  → injected in LLM prompt
                </span>
              </span>
              <textarea
                rows={4}
                value={t.args_format}
                onChange={e => updateTool(i, { args_format: e.target.value })}
                placeholder='&quot;target_url&quot;: &lt;string&gt;  // The URL to scan'
              />
              {errOf(`tools.${i}.args_format`) && <span className={styles.fieldErr}>{errOf(`tools.${i}.args_format`)}</span>}
            </label>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>
                description
                <span className={styles.injectedBadge} title="Injected as full multi-line guidance into the system prompt - every phase where this tool's `default_phases` allows it. The phase checkbox toggles whether the tool exists in the registry for that phase, NOT which fields render. If a tool is allowed in a phase, the LLM sees all four fields (name, purpose, when_to_use, args_format, description) in that phase.">
                  → injected in LLM prompt
                </span>
              </span>
              <textarea
                rows={4}
                value={t.description}
                onChange={e => updateTool(i, { description: e.target.value })}
                placeholder="Detailed guidance shown in the system prompt..."
              />
              {errOf(`tools.${i}.description`) && <span className={styles.fieldErr}>{errOf(`tools.${i}.description`)}</span>}
            </label>
            <label className={`${styles.field} ${styles.fieldWide}`}>
              <span>default_phases for this tool (optional override of server default)</span>
              <div className={styles.phasesRow}>
                {PHASES.map(p => (
                  <label key={p} className={styles.checkInline}>
                    <input
                      type="checkbox"
                      checked={(t.default_phases ?? editing.default_phases).includes(p)}
                      onChange={e => {
                        const current = t.default_phases ?? editing.default_phases
                        const next = e.target.checked
                          ? [...current, p]
                          : current.filter(x => x !== p) as Phase[]
                        updateTool(i, { default_phases: next })
                      }}
                    />
                    {p}
                  </label>
                ))}
              </div>
            </label>
          </div>
        </div>
      ))}
    </div>
  )
}

// Suppress unused-import warning for SYSTEM_SERVER_IDS (used by zod schema)
void SYSTEM_SERVER_IDS
