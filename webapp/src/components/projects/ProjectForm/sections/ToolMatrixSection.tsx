'use client'

import { useState, useEffect, useCallback, useMemo } from 'react'
import { ChevronDown, Grid3X3, AlertTriangle, Eye, EyeOff, Loader2, Server } from 'lucide-react'
import type { Project } from '@prisma/client'
import { useProject } from '@/providers/ProjectProvider'
import { Modal } from '@/components/ui/Modal/Modal'
import { WikiInfoButton } from '@/components/ui/WikiInfoButton'
import { failureText } from '@/components/settings/failureText'
import { readApiError } from '@/lib/apiError'
import { useOwnerCatalogSource } from '@/hooks/useOwnerCatalog'
import styles from '../ProjectForm.module.css'

const ALL_PHASES = ['informational', 'exploitation', 'post_exploitation'] as const

interface ManifestToolSpec {
  name: string
  default_phases?: string[] | null
}

interface ManifestServer {
  id: string
  name: string
  description: string
  enabled: boolean
  default_phases: string[]
  tags?: string[]
  tools: ManifestToolSpec[]
}

interface ManifestPayload {
  servers?: ManifestServer[]
  errors?: { server_id: string; code: string; message: string }[]
  warnings?: { server_id: string; code: string; message: string }[]
  system_server_ids?: string[]
}

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

/** Tool → settings field name + human label + signup URL */
const TOOL_KEY_INFO: Record<string, { field: string; label: string; hint: string; url: string }> = {
  tradecraft_lookup: {
    field: '_tradecraft_resources',  // sentinel: not an API key field
    label: 'Tradecraft Resources',
    hint: 'Configure curated knowledge URLs in Global Settings -> Tradecraft. The agent only sees enabled resources.',
    url: '/settings?tab=tradecraft',
  },
  web_search: {
    field: 'tavilyApiKey',
    label: 'Tavily',
    hint: 'Enables web_search tool for CVE research and exploit lookups',
    url: 'https://app.tavily.com/home',
  },
  shodan: {
    field: 'shodanApiKey',
    label: 'Shodan',
    hint: 'Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)',
    url: 'https://account.shodan.io/',
  },
  google_dork: {
    field: 'serpApiKey',
    label: 'SerpAPI',
    hint: 'Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:)',
    url: 'https://serpapi.com/manage-api-key',
  },
  execute_wpscan: {
    field: 'wpscanApiToken',
    label: 'WPScan',
    hint: 'Enriches execute_wpscan results with vulnerability data from the WPScan database (free: 25 req/day)',
    url: 'https://wpscan.com/register',
  },
  execute_gau: {
    field: 'urlscanApiKey',
    label: 'URLScan',
    hint: 'Enriches execute_gau results with URLScan archived data (free tier available)',
    url: 'https://urlscan.io/user/signup',
  },
  cve_intel: {
    field: 'pdcpApiKey',
    label: 'PDCP',
    hint: 'Optional. Lifts the 10 req/min anonymous rate limit on the ProjectDiscovery CVE database (vulnx).',
    url: 'https://cloud.projectdiscovery.io',
  },
}

function ToolPhaseHeader() {
  return (
    <div className={styles.toolPhaseHeader}>
      <span className={styles.toolPhaseHeaderLabel}>Tool</span>
      <span className={styles.toolPhaseHeaderLabel}>Informational</span>
      <span className={styles.toolPhaseHeaderLabel}>Exploitation</span>
      <span className={styles.toolPhaseHeaderLabel}>Post-Exploitation</span>
    </div>
  )
}

interface ToolMatrixSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

export function ToolMatrixSection({ data, updateField }: ToolMatrixSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()
  // A collaborator's form (step 5.7): the agent runs with the project OWNER's keys, tradecraft and
  // MCP servers, so the matrix shows those, by name and presence, and offers no key to save.
  const owner = useOwnerCatalogSource()
  const ownerForm = owner !== null
  const [ownMissingKeys, setMissingKeys] = useState<Set<string>>(new Set())
  // A failed read must not mark a tool as missing its key: that is a guess.
  const [ownKeyStatusError, setKeyStatusError] = useState<string | null>(null)
  const [ownMcpServers, setUserMcpServers] = useState<ManifestServer[]>([])
  const ownerCatalog = owner?.catalog ?? null
  const ownerMissingKeys = useMemo(() => {
    const missing = new Set<string>()
    if (!ownerCatalog) return missing
    for (const [tool, info] of Object.entries(TOOL_KEY_INFO)) {
      if (tool === 'tradecraft_lookup') continue
      if (ownerCatalog.keys[info.field as keyof typeof ownerCatalog.keys] !== true) missing.add(tool)
    }
    if (!ownerCatalog.tradecraftResources.some(r => r.enabled)) missing.add('tradecraft_lookup')
    return missing
  }, [ownerCatalog])
  const missingKeys = ownerForm ? ownerMissingKeys : ownMissingKeys
  const keyStatusError = ownerForm
    ? (owner.status === 'error' ? `${owner.error ?? "Couldn't read the project owner's keys"}` : null)
    : ownKeyStatusError
  const userMcpServers: ManifestServer[] = ownerForm
    ? (ownerCatalog?.mcpServers ?? []).map(srv => ({ ...srv, description: '' }))
    : ownMcpServers
  // Choosing the owner's MCP tools' phases needs Manage (step 5.7).
  const mcpRefusal = owner?.pickRefusal ?? null

  // Source the user MCP list from the DATABASE (the user's saved
  // configuration), not from the agent's runtime manifest. The DB is the
  // source of truth - the agent's registry is downstream and may lag
  // until a chat session triggers a settings reload (e.g., right after
  // an agent restart). Reading from the DB means the matrix always
  // reflects what the user has saved, regardless of agent state.
  useEffect(() => {
    if (!userId || ownerForm) return
    fetch(`/api/users/${userId}/mcp`)
      .then(r => r.ok ? r.json() : null)
      .then((d: { servers?: ManifestServer[] } | null) => {
        if (d?.servers && Array.isArray(d.servers)) {
          setUserMcpServers(d.servers)
        }
      })
      .catch(() => {/* graceful: matrix still works with built-ins */})
  }, [userId, ownerForm])

  // API key modal state
  const [keyModal, setKeyModal] = useState<string | null>(null) // tool id or null
  const [keyValue, setKeyValue] = useState('')
  const [keyVisible, setKeyVisible] = useState(false)
  const [keySaving, setKeySaving] = useState(false)
  const [keyError, setKeyError] = useState<string | null>(null)

  // Fetch API key status from global settings
  const fetchKeyStatus = useCallback(() => {
    if (!userId || ownerForm) return
    const SETTINGS_FAILED = "Couldn't check which API keys are set"
    fetch(`/api/users/${userId}/settings`)
      .then(async r => {
        if (r.ok) return r.json()
        setKeyStatusError(failureText(SETTINGS_FAILED, await readApiError(r, SETTINGS_FAILED)))
        return null
      })
      .then(settings => {
        if (!settings) return
        setKeyStatusError(null)
        const missing = new Set<string>()
        if (!settings.tavilyApiKey) missing.add('web_search')
        if (!settings.shodanApiKey) missing.add('shodan')
        if (!settings.serpApiKey) missing.add('google_dork')
        if (!settings.wpscanApiToken) missing.add('execute_wpscan')
        if (!settings.urlscanApiKey) missing.add('execute_gau')
        if (!settings.pdcpApiKey) missing.add('cve_intel')
        // tradecraft_lookup: warn when zero enabled resources are configured
        const TRADECRAFT_FAILED = "Couldn't check your tradecraft resources"
        fetch(`/api/users/${userId}/tradecraft-resources`)
          .then(async r2 => {
            if (r2.ok) return r2.json()
            throw await readApiError(r2, TRADECRAFT_FAILED)
          })
          .then((arr: Array<{ enabled?: boolean }>) => {
            const enabledCount = (arr || []).filter(r => r.enabled !== false).length
            const next = new Set(missing)
            if (enabledCount === 0) next.add('tradecraft_lookup')
            setMissingKeys(next)
          })
          .catch(err => {
            setMissingKeys(missing)
            setKeyStatusError(failureText(TRADECRAFT_FAILED, err))
          })
      })
      .catch(err => setKeyStatusError(failureText(SETTINGS_FAILED, err)))
  }, [userId, ownerForm])

  useEffect(() => { fetchKeyStatus() }, [fetchKeyStatus])

  const openKeyModal = (toolId: string) => {
    // Special-case: tradecraft_lookup has no API key. Redirect to the Tradecraft tab.
    if (toolId === 'tradecraft_lookup') {
      window.location.href = '/settings?tab=tradecraft'
      return
    }
    setKeyModal(toolId)
    setKeyValue('')
    setKeyVisible(false)
    setKeyError(null)
  }

  const closeKeyModal = () => {
    setKeyModal(null)
    setKeyValue('')
    setKeyVisible(false)
    setKeyError(null)
  }

  const saveApiKey = async () => {
    if (!userId || !keyModal || !keyValue.trim()) return
    const info = TOOL_KEY_INFO[keyModal]
    if (!info) return
    setKeySaving(true)
    setKeyError(null)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [info.field]: keyValue.trim() }),
      })
      if (resp.ok) {
        closeKeyModal()
        fetchKeyStatus()
      } else {
        setKeyError((await readApiError(resp, 'The key was not saved')).message)
      }
    } catch (err) {
      setKeyError(failureText('The key was not saved', err))
    } finally {
      setKeySaving(false)
    }
  }

  const modalInfo = keyModal ? TOOL_KEY_INFO[keyModal] : null

  return (
    <div className={`${styles.section} ${styles.formSkin}`}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Grid3X3 size={16} />
          Tool Phase Restrictions
          <WikiInfoButton target="ToolMatrix" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Controls which tools the agent can use in each phase. Check the phases where each tool should be available.
          </p>
          {keyStatusError && (
            <p className={styles.sectionDescription} role="alert">
              <AlertTriangle size={12} /> {keyStatusError}, so a tool may be shown without its missing-key warning.
            </p>
          )}
          <div className={styles.toolPhaseGrid}>
            <ToolPhaseHeader />
            {[
              { id: 'query_graph', label: 'query_graph' },
              { id: 'proxy_brain', label: 'proxy_brain ⚠' },
              { id: 'web_search', label: 'web_search' },
              { id: 'cve_intel', label: 'cve_intel' },
              { id: 'shodan', label: 'shodan' },
              { id: 'google_dork', label: 'google_dork' },
              { id: 'execute_curl', label: 'execute_curl' },
              { id: 'execute_naabu', label: 'execute_naabu' },
              { id: 'execute_httpx', label: 'execute_httpx' },
              { id: 'execute_subfinder', label: 'execute_subfinder' },
              { id: 'execute_gau', label: 'execute_gau' },
              { id: 'execute_nmap', label: 'execute_nmap' },
              { id: 'execute_nuclei', label: 'execute_nuclei' },
              { id: 'execute_wpscan', label: 'execute_wpscan' },
              { id: 'execute_jsluice', label: 'execute_jsluice' },
              { id: 'execute_osv_scanner', label: 'execute_osv_scanner' },
              { id: 'execute_guarddog', label: 'execute_guarddog ⚠' },
              { id: 'execute_amass', label: 'execute_amass' },
              { id: 'execute_katana', label: 'execute_katana' },
              { id: 'execute_arjun', label: 'execute_arjun' },
              { id: 'execute_ffuf', label: 'execute_ffuf' },
              { id: 'kali_shell', label: 'kali_shell' },
              { id: 'execute_code', label: 'execute_code' },
              { id: 'execute_playwright', label: 'execute_playwright' },
              { id: 'execute_hydra', label: 'execute_hydra' },
              { id: 'metasploit_console', label: 'metasploit_console' },
              { id: 'msf_restart', label: 'msf_restart' },
              { id: 'tradecraft_lookup', label: 'tradecraft_lookup' },
            ].map(tool => {
              const phaseMap = (typeof data.agentToolPhaseMap === 'string'
                ? JSON.parse(data.agentToolPhaseMap)
                : data.agentToolPhaseMap ?? {}) as Record<string, string[]>
              const toolPhases = phaseMap[tool.id] || []

              const togglePhase = (phase: string) => {
                const newMap = { ...phaseMap }
                const current = newMap[tool.id] || []
                if (current.includes(phase)) {
                  newMap[tool.id] = current.filter((p: string) => p !== phase)
                } else {
                  newMap[tool.id] = [...current, phase]
                }
                updateField('agentToolPhaseMap', newMap as typeof data.agentToolPhaseMap)
              }

              const needsKey = missingKeys.has(tool.id) && toolPhases.length > 0
              const keyInfo = TOOL_KEY_INFO[tool.id]

              return (
                <div key={tool.id} className={styles.toolPhaseRow}>
                  <span className={styles.toolPhaseName}>
                    {tool.label}
                    {needsKey && keyInfo && ownerForm && (
                      <span className={styles.apiKeyMissing} data-testid={`owner-key-missing-${tool.id}`}>
                        <AlertTriangle size={12} />
                        {tool.id === 'tradecraft_lookup' ? "The owner has no enabled tradecraft resource" : `The owner has no ${keyInfo.label} key`}
                      </span>
                    )}
                    {needsKey && keyInfo && !ownerForm && (
                      <span
                        className={styles.apiKeyMissing}
                        title={`Set ${keyInfo.label} API key`}
                        onClick={(e) => { e.stopPropagation(); openKeyModal(tool.id) }}
                        role="button"
                        tabIndex={0}
                      >
                        <AlertTriangle size={12} />
                        No {keyInfo.label} key - Add
                      </span>
                    )}
                  </span>
                  {['informational', 'exploitation', 'post_exploitation'].map(phase => (
                    <label key={phase} className={styles.phaseCheck}>
                      <input
                        type="checkbox"
                        checked={toolPhases.includes(phase)}
                        onChange={() => togglePhase(phase)}
                      />
                    </label>
                  ))}
                </div>
              )
            })}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>
              <Server size={14} />
              MCP Tool Plugins
            </h3>
            {ownerForm ? (
              <p className={styles.sectionDescription}>
                The project owner&apos;s MCP Tool Plugins. Only the owner adds or edits them, in their Global Settings.
                {mcpRefusal && <> Their phases here need Manage.</>}
              </p>
            ) : (
              <p className={styles.sectionDescription}>
                User-installed MCP Tool Plugins - add or edit in{' '}
                <a href="/settings?tab=mcp">
                  Global Settings → MCP Tool Plugins
                </a>.
              </p>
            )}

            {ownerForm && owner.status === 'loading' ? (
              <p className={styles.itemEmpty}>
                <Loader2 size={12} className={styles.spinner} /> Loading the project owner&apos;s MCP Tool Plugins…
              </p>
            ) : ownerForm && owner.status === 'error' ? (
              <p className={styles.itemEmpty} role="alert">
                {owner.error}{' '}
                <button type="button" className="secondaryButton" onClick={owner.retry}>Retry</button>
              </p>
            ) : userMcpServers.length === 0 ? (
              <p className={styles.itemEmpty}>
                {ownerForm ? 'The project owner has no MCP Tool Plugins.' : 'No MCP Tool Plugins configured for this user yet.'}
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {userMcpServers.map(srv => (
                  <details key={srv.id} open>
                    <summary className={styles.disclosureSummary}>
                      {srv.name || srv.id}
                      {srv.description && <span className={styles.disclosureMeta}>- {srv.description}</span>}
                      {!srv.enabled && <span className={styles.disclosureMeta}>(disabled)</span>}
                    </summary>
                    <div className={styles.toolPhaseGrid}>
                      <ToolPhaseHeader />
                      {srv.tools.map(tool => {
                        const phaseMap = (typeof data.agentToolPhaseMap === 'string'
                          ? JSON.parse(data.agentToolPhaseMap)
                          : data.agentToolPhaseMap ?? {}) as Record<string, string[]>
                        const defaultPhases = (tool.default_phases && tool.default_phases.length > 0)
                          ? tool.default_phases
                          : (srv.default_phases && srv.default_phases.length > 0
                            ? srv.default_phases
                            : [...ALL_PHASES])
                        const effectivePhases = phaseMap[tool.name] !== undefined
                          ? phaseMap[tool.name]
                          : defaultPhases
                        const togglePhase = (phase: string) => {
                          const newMap = { ...phaseMap }
                          const current = newMap[tool.name] !== undefined ? newMap[tool.name] : effectivePhases
                          newMap[tool.name] = current.includes(phase)
                            ? current.filter((p: string) => p !== phase)
                            : [...current, phase]
                          updateField('agentToolPhaseMap', newMap as typeof data.agentToolPhaseMap)
                        }
                        return (
                          <div key={tool.name} className={styles.toolPhaseRow}>
                            <span className={styles.toolPhaseName}>{tool.name}</span>
                            {ALL_PHASES.map(phase => (
                              <label key={phase} className={styles.phaseCheck}>
                                <input
                                  type="checkbox"
                                  checked={effectivePhases.includes(phase)}
                                  disabled={!srv.enabled || mcpRefusal !== null}
                                  title={mcpRefusal ?? undefined}
                                  aria-label={`${tool.name}: ${phase.replace('_', '-')}`}
                                  onChange={() => togglePhase(phase)}
                                />
                              </label>
                            ))}
                          </div>
                        )
                      })}
                    </div>
                  </details>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* API Key modal */}
      <Modal
        isOpen={!!keyModal}
        onClose={closeKeyModal}
        title={modalInfo ? `${modalInfo.label} API Key` : ''}
        size="small"
        footer={
          <>
            <button className="secondaryButton" onClick={closeKeyModal}>Cancel</button>
            <button
              className="primaryButton"
              disabled={!keyValue.trim() || keySaving}
              onClick={saveApiKey}
            >
              {keySaving ? <Loader2 size={14} className={styles.spinner} /> : null}
              Save
            </button>
          </>
        }
      >
        {modalInfo && (
          <div className="formGroup">
            <label className="formLabel">{modalInfo.label} API Key</label>
            <div className={styles.apiKeyInputWrapper}>
              <input
                className="textInput"
                type={keyVisible ? 'text' : 'password'}
                value={keyValue}
                onChange={e => setKeyValue(e.target.value)}
                placeholder={`Enter ${modalInfo.label.toLowerCase()} API key`}
                autoFocus
              />
              <button
                className={styles.apiKeyToggle}
                onClick={() => setKeyVisible(v => !v)}
                type="button"
              >
                {keyVisible ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <span className={styles.keyModalHint}>
              {modalInfo.hint}
              {' - '}
              <a href={modalInfo.url} target="_blank" rel="noopener noreferrer">
                Get API key
              </a>
            </span>
            {keyError && <span className="formHint" role="alert" style={{ color: 'var(--status-error-text)' }}>{keyError}</span>}
          </div>
        )}
      </Modal>
    </div>
  )
}
