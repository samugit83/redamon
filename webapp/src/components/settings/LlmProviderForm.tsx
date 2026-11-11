'use client'

import { useState, useCallback, useEffect, useRef } from 'react'
import { Loader2, CheckCircle, XCircle, Plus, Trash2, Eye, EyeOff, ExternalLink, AlertTriangle, RefreshCw } from 'lucide-react'
import { useToast } from '@/components/ui'
import { useAgentHealth } from '@/hooks/useAgentHealth'
import { useDirtyState } from '@/hooks/useDirtyState'
import { useUnsavedChangesGuard } from '@/hooks/useUnsavedChangesGuard'
import { PROVIDER_TYPES, OPENAI_COMPAT_PRESETS, NON_CHAT_PROVIDER_TYPES, JEV_MODEL, JEV_BACKENDS, isJevProvider } from '@/lib/llmProviderPresets'
import type { ProviderType } from '@/lib/llmProviderPresets'
import { REASONING_EFFORTS } from '@/lib/llmReasoning'
import { fetchJson, readApiError, toApiError, type ApiError } from '@/lib/apiError'
import type { ReasoningEffort } from '@/lib/llmReasoning'
import styles from './Settings.module.css'

interface LlmProviderFormProps {
  userId: string
  provider?: ProviderData | null
  existingProviderTypes?: string[]
  onSave: () => void
  onCancel: () => void
  /** Reports unsaved-changes state to the parent (drives the tab-switch guard). */
  onDirtyChange?: (dirty: boolean) => void
  /**
   * Opens a new provider of this type with no type picker. Non-chat types
   * (Jev) are only reachable this way: the generic picker never lists them.
   */
  lockedType?: 'jev' | 'jev_openrouter'
  /**
   * Rendered inside another panel (the project form's AI panel): no frame, no
   * title, no Cancel, and the pinned-model block shortened to a hint, because the
   * host panel already says what this is.
   */
  embedded?: boolean
}

export interface ProviderData {
  id?: string
  providerType: string
  name: string
  apiKey: string
  baseUrl: string
  modelIdentifier: string
  defaultHeaders: Record<string, string>
  timeout: number
  temperature: number
  maxTokens: number
  sslVerify: boolean
  reasoningEnabled: boolean
  reasoningEffort: ReasoningEffort
  awsRegion: string
  awsAccessKeyId: string
  awsSecretKey: string
  awsBearerToken: string
}

type BedrockAuthMethod = 'iam' | 'bearer'

/** The secret field a save or test was refused for: its endpoint changed (HD-24). */
interface Reentry { field: string; message: string }

function reentryOf(err: ApiError): Reentry | null {
  const field = err.body?.field
  return err.code === 'secret_reentry_required' && typeof field === 'string' ? { field, message: err.reason } : null
}

const EMPTY_PROVIDER: ProviderData = {
  providerType: '',
  name: '',
  apiKey: '',
  baseUrl: '',
  modelIdentifier: '',
  defaultHeaders: {},
  timeout: 120,
  temperature: 0,
  maxTokens: 16384,
  sslVerify: true,
  reasoningEnabled: false,
  reasoningEffort: 'high',
  awsRegion: 'us-east-1',
  awsAccessKeyId: '',
  awsSecretKey: '',
  awsBearerToken: '',
}

export function LlmProviderForm({ userId, provider, existingProviderTypes = [], onSave, onCancel, onDirtyChange, lockedType, embedded = false }: LlmProviderFormProps) {
  const isEditing = !!provider?.id
  const toast = useToast()
  const [form, setForm] = useState<ProviderData>(() => ({
    ...EMPTY_PROVIDER,
    ...(lockedType && !provider
      ? { providerType: lockedType, name: JEV_BACKENDS[lockedType].name, modelIdentifier: JEV_BACKENDS[lockedType].modelIdentifier }
      : {}),
    ...(provider || {}),
    defaultHeaders: provider?.defaultHeaders || {},
    reasoningEnabled: provider?.reasoningEnabled ?? false,
    reasoningEffort: provider?.reasoningEffort || 'high',
  }))

  // Dirty tracking vs the initial form (create = EMPTY_PROVIDER, edit = provider
  // incl. masked secrets). Gates the Save button and the unsaved-changes guard.
  const { isDirty, setBaseline } = useDirtyState(form)
  // Local-only: the parent /settings page aggregates dirtiness (onDirtyChange)
  // and owns the global sidebar/beforeunload guard, so this instance only wraps
  // the Cancel button.
  const { guardedNavigate } = useUnsavedChangesGuard(isDirty, { trackGlobal: false })
  useEffect(() => { onDirtyChange?.(isDirty) }, [isDirty, onDirtyChange])
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange])
  const [step, setStep] = useState<'type' | 'config'>(isEditing || form.providerType ? 'config' : 'type')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; text?: string; error?: string } | null>(null)
  // The Test button proxies through the agent container, so a dead agent makes
  // every provider look broken. Surface that here instead of letting the click
  // fail with an error the operator will read as "my Base URL is wrong" (#184).
  const agentHealth = useAgentHealth()
  const [showApiKey, setShowApiKey] = useState(false)
  const [headerKey, setHeaderKey] = useState('')
  const [headerValue, setHeaderValue] = useState('')
  // Bedrock auth method derives from whichever field is currently populated.
  // For a saved row the value is masked (••••...), so a non-empty bearer
  // token still flips the toggle to "bearer". User picks via the segmented
  // control; switching clears the other branch's fields.
  const [bedrockAuth, setBedrockAuth] = useState<BedrockAuthMethod>(
    () => (form.awsBearerToken ? 'bearer' : 'iam'),
  )
  // A changed base URL or type with a kept (masked) key is refused by the server:
  // the message goes under that key's input, which takes the focus.
  const [reentry, setReentry] = useState<Reentry | null>(null)
  const secretInputs = useRef<Record<string, HTMLInputElement | null>>({})
  const secretRef = (field: string) => (el: HTMLInputElement | null) => { secretInputs.current[field] = el }
  useEffect(() => {
    if (reentry) secretInputs.current[reentry.field]?.focus()
  }, [reentry])
  const reentryHint = (field: string) => reentry?.field === field && (
    <span className="formHint" role="alert" style={{ color: 'var(--text-error)' }}>{reentry.message}</span>
  )

  const updateForm = useCallback(<K extends keyof ProviderData>(field: K, value: ProviderData[K]) => {
    setForm(prev => ({ ...prev, [field]: value }))
    setTestResult(null)
    setReentry(prev => (prev?.field === field ? null : prev))
  }, [])

  const selectType = useCallback((type: ProviderType) => {
    const typeDef = PROVIDER_TYPES.find(p => p.id === type)
    setForm(prev => {
      const updates: Partial<ProviderData> = {
        providerType: type,
        name: prev.name || typeDef?.name || type,
      }
      return { ...prev, ...updates }
    })
    setStep('config')
  }, [])

  const addHeader = useCallback(() => {
    if (headerKey.trim()) {
      setForm(prev => ({
        ...prev,
        defaultHeaders: { ...prev.defaultHeaders, [headerKey.trim()]: headerValue },
      }))
      setHeaderKey('')
      setHeaderValue('')
    }
  }, [headerKey, headerValue])

  const removeHeader = useCallback((key: string) => {
    setForm(prev => {
      const headers = { ...prev.defaultHeaders }
      delete headers[key]
      return { ...prev, defaultHeaders: headers }
    })
  }, [])

  // A Jev row carries only its backend, name and key: the server pins the model and
  // refuses any base URL or header, so none is sent.
  const requestBody = useCallback(
    () => isJevProvider(form)
      ? { providerType: form.providerType, name: form.name, apiKey: form.apiKey }
      : form,
    [form],
  )

  const handleTest = useCallback(async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const providerId = provider?.id || 'unsaved'
      const result = await fetchJson<{ success?: boolean; response_text?: string; error?: string }>(
        `/api/users/${userId}/llm-providers/${providerId}/test`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(requestBody()),
        },
        'The provider test failed',
      )
      setTestResult({
        success: result.success === true,
        text: result.response_text,
        error: result.error || (result.success === true ? undefined : 'The provider test failed'),
      })
    } catch (err) {
      const apiErr = toApiError(err, 'The provider test failed')
      setTestResult({ success: false, error: apiErr.message })
      setReentry(reentryOf(apiErr))
    } finally {
      setTesting(false)
    }
  }, [userId, provider?.id, requestBody])

  const handleSave = useCallback(async () => {
    setSaving(true)
    try {
      const url = isEditing
        ? `/api/users/${userId}/llm-providers/${provider!.id}`
        : `/api/users/${userId}/llm-providers`
      const method = isEditing ? 'PUT' : 'POST'

      const resp = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody()),
      })

      if (!resp.ok) throw await readApiError(resp, 'Failed to save provider')

      toast.success(isEditing ? 'Provider updated' : 'Provider added')
      setBaseline(form)
      onSave()
    } catch (err) {
      console.error('Failed to save provider:', err)
      // Show what the server actually said. The blanket message hid the real
      // cause of issue #173 (a write against a user id that no longer exists)
      // behind an unactionable "Failed to save provider".
      const apiErr = toApiError(err, 'Failed to save provider')
      toast.error(apiErr.message)
      setReentry(reentryOf(apiErr))
    } finally {
      setSaving(false)
    }
  }, [isEditing, userId, provider, form, requestBody, onSave, setBaseline])

  // Step 1: Choose provider type
  if (step === 'type') {
    return (
      <div className={styles.formSection}>
        <h3 className={styles.formTitle}>Choose Provider Type</h3>
        <div className={styles.providerTypeGrid}>
          {PROVIDER_TYPES.filter(pt => !NON_CHAT_PROVIDER_TYPES.has(pt.id)).map(pt => {
            const alreadyAdded = pt.id !== 'openai_compatible' && existingProviderTypes.includes(pt.id)
            return (
              <button type="button"
                key={pt.id}
                className={styles.providerTypeCard}
                onClick={() => selectType(pt.id)}
                disabled={alreadyAdded}
                title={alreadyAdded ? `${pt.name} already configured` : undefined}
                style={alreadyAdded ? { opacity: 0.45, cursor: 'not-allowed' } : undefined}
              >
                <span className={styles.providerTypeIcon} aria-label={pt.name}>
                  <pt.Icon size={40} />
                </span>
                <span className={styles.providerTypeName}>
                  {pt.name}{alreadyAdded ? ' (added)' : ''}
                </span>
                <span className={styles.providerTypeDesc}>{pt.description}</span>
              </button>
            )
          })}
        </div>
        <div className={styles.formActions}>
          <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onCancel)}>Cancel</button>
        </div>
      </div>
    )
  }

  // Step 2: Configure
  const ptype = form.providerType as ProviderType
  const providerDef = PROVIDER_TYPES.find(p => p.id === ptype)
  const isKeyBased = ['openai', 'anthropic', 'openrouter', 'deepseek', 'gemini', 'glm', 'kimi', 'qwen', 'xai', 'mistral'].includes(ptype)
  const isBedrock = ptype === 'bedrock'
  const isCompat = ptype === 'openai_compatible'
  const isJev = isJevProvider(form)
  const apiKeyUrl = providerDef?.apiKeyUrl
  const apiKeyLinkLabel = isBedrock ? 'Get AWS credentials' : 'Get API key'
  const saveButton = (
    <button type="button"
      className="primaryButton"
      onClick={handleSave}
      disabled={
        saving ||
        !isDirty ||
        !form.name.trim() ||
        (!isCompat && !form.apiKey && !isBedrock) ||
        (isBedrock && bedrockAuth === 'iam' && (!form.awsAccessKeyId || !form.awsSecretKey)) ||
        (isBedrock && bedrockAuth === 'bearer' && !form.awsBearerToken) ||
        (isCompat && (!form.baseUrl || !form.modelIdentifier))
      }
    >
      {saving ? <Loader2 size={14} className={styles.spin} /> : null}
      {embedded ? 'Save token' : `${isEditing ? 'Update' : 'Save'} Provider`}
    </button>
  )
  return (
    <div className={embedded ? styles.formEmbedded : styles.formSection}>
      {!embedded && (
        <div className={`${styles.formHeader} ${styles.stickyHeader}`}>
          <h3 className={styles.formTitle}>
            {isEditing ? 'Edit' : 'Add'} {providerDef?.name || ptype} Provider
          </h3>
          <div className={styles.sectionHeaderActions}>
            {!isEditing && !lockedType && (
              <button type="button" className="textButton" onClick={() => setStep('type')}>Change type</button>
            )}
            <button type="button" className="secondaryButton" onClick={() => guardedNavigate(onCancel)}>Cancel</button>
            {saveButton}
          </div>
        </div>
      )}
      {apiKeyUrl && (
        <a
          href={apiKeyUrl}
          target="_blank"
          rel="noopener noreferrer"
          className={styles.apiKeyLink}
        >
          {apiKeyLinkLabel} <ExternalLink size={12} />
        </a>
      )}

      {isJev && (
        <div className="formGroup">
          <label className="formLabel" htmlFor="jev-backend">Jev backend</label>
          <select id="jev-backend" className="select" value={ptype} disabled={isEditing}
            onChange={e => {
              const type = e.target.value as 'jev' | 'jev_openrouter'
              setForm(prev => ({ ...prev, providerType: type, apiKey: '', modelIdentifier: JEV_BACKENDS[type].modelIdentifier }))
              setTestResult(null)
            }}>
            {Object.entries(JEV_BACKENDS).map(([type, backend]) => <option key={type} value={type}>{backend.name}</option>)}
          </select>
          <span className="formHint">The backend is locked after saving. Create a separate named entry to use another backend.</span>
        </div>
      )}
      {(
        <div className="formGroup">
          <label className="formLabel formLabelRequired">Display Name</label>
          <input
            className="textInput"
            value={form.name}
            onChange={e => updateForm('name', e.target.value)}
            onKeyDown={e => { if (embedded && e.key === 'Enter') e.preventDefault() }}
            aria-label="Display Name"
            placeholder={isJev ? "e.g., Recon Jev production" : "e.g., My OpenAI Key"}
          />
        </div>
      )}

      {/* Key-based providers: just API key */}
      {(isKeyBased || isJev) && (
        <div className="formGroup">
          <label className="formLabel formLabelRequired">API Key</label>
          <div className={styles.secretInputWrapper}>
            <input
              ref={secretRef('apiKey')}
              className="textInput"
              type={showApiKey ? 'text' : 'password'}
              value={form.apiKey}
              onChange={e => updateForm('apiKey', e.target.value)}
              // Inside the project form, Enter would submit the whole project.
              onKeyDown={e => { if (e.key === 'Enter') e.preventDefault() }}
              aria-label={isJev ? `${ptype === 'jev_openrouter' ? 'OpenRouter' : 'TypeSafe'} Jev API key` : 'API key'}
              placeholder={ptype === 'jev' ? 'apikey_...' : 'sk-...'}
            />
            <button
              className={styles.secretToggle}
              onClick={() => setShowApiKey(!showApiKey)}
              type="button"
            >
              {showApiKey ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          {reentryHint('apiKey')}
        </div>
      )}

      {isJev && !embedded && (
        <div className="formGroup">
          <label className="formLabel">Model</label>
          <div className={styles.readonlyValue} data-testid="jev-model">{JEV_BACKENDS[ptype as 'jev' | 'jev_openrouter'].modelIdentifier}</div>
          <span className="formHint">
            Pinned: the recon AI hooks are calibrated against this version.
          </span>
        </div>
      )}

      {/* Bedrock */}
      {isBedrock && (
        <>
          <div className="formGroup">
            <label className="formLabel formLabelRequired">AWS Region</label>
            <input
              className="textInput"
              value={form.awsRegion}
              onChange={e => updateForm('awsRegion', e.target.value)}
              placeholder="us-east-1"
            />
          </div>
          <div className="formGroup">
            <label className="formLabel">Authentication Method</label>
            <div className={styles.segmentedControl} role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={bedrockAuth === 'iam'}
                className={`${styles.segmentedOption} ${bedrockAuth === 'iam' ? styles.segmentedOptionActive : ''}`}
                onClick={() => {
                  setBedrockAuth('iam')
                  updateForm('awsBearerToken', '')
                }}
              >
                IAM Access Keys
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={bedrockAuth === 'bearer'}
                className={`${styles.segmentedOption} ${bedrockAuth === 'bearer' ? styles.segmentedOptionActive : ''}`}
                onClick={() => {
                  setBedrockAuth('bearer')
                  updateForm('awsAccessKeyId', '')
                  updateForm('awsSecretKey', '')
                }}
              >
                Long-term API Key
              </button>
            </div>
            <span className="formHint">
              {bedrockAuth === 'iam'
                ? 'IAM user access key + secret (SigV4). Long-lived, production-ready.'
                : 'Bedrock console "Long-term API key". Single bearer token, simpler to rotate. Short-term keys are not supported (they expire with the AWS console session).'}
            </span>
          </div>
          {bedrockAuth === 'iam' && (
            <>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">AWS Access Key ID</label>
                <input
                  ref={secretRef('awsAccessKeyId')}
                  className="textInput"
                  type="password"
                  value={form.awsAccessKeyId}
                  onChange={e => updateForm('awsAccessKeyId', e.target.value)}
                />
                {reentryHint('awsAccessKeyId')}
              </div>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">AWS Secret Access Key</label>
                <input
                  ref={secretRef('awsSecretKey')}
                  className="textInput"
                  type="password"
                  value={form.awsSecretKey}
                  onChange={e => updateForm('awsSecretKey', e.target.value)}
                />
                {reentryHint('awsSecretKey')}
              </div>
            </>
          )}
          {bedrockAuth === 'bearer' && (
            <div className="formGroup">
              <label className="formLabel formLabelRequired">Bedrock API Key</label>
              <input
                ref={secretRef('awsBearerToken')}
                className="textInput"
                type="password"
                value={form.awsBearerToken}
                onChange={e => updateForm('awsBearerToken', e.target.value)}
                placeholder="bedrock-api-key-..."
              />
              {reentryHint('awsBearerToken')}
              <span className="formHint">Generate in AWS Bedrock console: API keys -&gt; Long-term API keys.</span>
            </div>
          )}
        </>
      )}

      {/* OpenAI-Compatible */}
      {isCompat && (
        <>
          <div className="formGroup">
            <label className="formLabel">Base URL Preset</label>
            <select
              className="select"
              value={OPENAI_COMPAT_PRESETS.find(p => p.baseUrl === form.baseUrl)?.name || 'Custom'}
              onChange={e => {
                const preset = OPENAI_COMPAT_PRESETS.find(p => p.name === e.target.value)
                if (preset && preset.baseUrl) {
                  updateForm('baseUrl', preset.baseUrl)
                }
              }}
            >
              {OPENAI_COMPAT_PRESETS.map(p => (
                <option key={p.name} value={p.name}>{p.name} - {p.description}</option>
              ))}
            </select>
          </div>

          <div className="formGroup">
            <label className="formLabel formLabelRequired">Base URL</label>
            <input
              className="textInput"
              value={form.baseUrl}
              onChange={e => updateForm('baseUrl', e.target.value)}
              placeholder="http://host.docker.internal:11434/v1"
            />
          </div>

          <div className="formGroup">
            <label className="formLabel formLabelRequired">Model Identifier</label>
            <input
              className="textInput"
              value={form.modelIdentifier}
              onChange={e => updateForm('modelIdentifier', e.target.value)}
              placeholder="e.g., llama3.1:8b"
            />
          </div>

          <div className="formGroup">
            <label className="formLabel">API Key</label>
            <input
              ref={secretRef('apiKey')}
              className="textInput"
              type="password"
              value={form.apiKey}
              onChange={e => updateForm('apiKey', e.target.value)}
              placeholder="Optional (leave empty for Ollama)"
              aria-label="API key"
            />
            {reentryHint('apiKey') || (
              <span className="formHint">Leave empty for local servers that don&apos;t require auth</span>
            )}
          </div>

          <div className={styles.reasoningControl}>
            <label className={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={form.reasoningEnabled}
                onChange={e => updateForm('reasoningEnabled', e.target.checked)}
              />
              <span>Enable reasoning effort</span>
            </label>
            <select
              className="select"
              aria-label="Reasoning effort"
              value={form.reasoningEffort}
              disabled={!form.reasoningEnabled}
              onChange={e => updateForm('reasoningEffort', e.target.value as ReasoningEffort)}
            >
              {REASONING_EFFORTS.map(effort => (
                <option key={effort} value={effort}>
                  {effort.charAt(0).toUpperCase() + effort.slice(1)}
                </option>
              ))}
            </select>
            <span className="formHint">
              Sends <code>reasoning_effort</code> to the endpoint. When disabled, nothing
              is sent and the model&apos;s default is used. Enable only for thinking-capable
              models; others reject a level (the agent auto-retries without it).
            </span>
          </div>

          {/* Extra headers */}
          <div className="formGroup">
            <label className="formLabel">Extra Headers</label>
            {Object.entries(form.defaultHeaders).map(([k, v]) => (
              <div key={k} className={styles.headerRow}>
                <code className={styles.headerKey}>{k}</code>
                <code className={styles.headerValue}>{v}</code>
                <button type="button" className={styles.headerRemove} onClick={() => removeHeader(k)}>
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
            <div className={styles.headerAdd}>
              <input
                className="textInput"
                value={headerKey}
                onChange={e => setHeaderKey(e.target.value)}
                placeholder="Header name"
                style={{ flex: 1 }}
              />
              <input
                className="textInput"
                value={headerValue}
                onChange={e => setHeaderValue(e.target.value)}
                placeholder="Value"
                style={{ flex: 1 }}
              />
              <button type="button" className="secondaryButton" onClick={addHeader} disabled={!headerKey.trim()}>
                <Plus size={12} />
              </button>
            </div>
          </div>

          {/* Advanced params */}
          <div className={styles.advancedGrid}>
            <div className="formGroup">
              <label className="formLabel">Timeout (s)</label>
              <input
                className="textInput"
                type="number"
                value={form.timeout}
                onChange={e => updateForm('timeout', parseInt(e.target.value) || 120)}
              />
            </div>
            <div className="formGroup">
              <label className="formLabel">Temperature</label>
              <input
                className="textInput"
                type="number"
                step="0.1"
                min="0"
                max="2"
                value={form.temperature}
                onChange={e => updateForm('temperature', parseFloat(e.target.value) || 0)}
              />
            </div>
            <div className="formGroup">
              <label className="formLabel">Max Tokens</label>
              <input
                className="textInput"
                type="number"
                value={form.maxTokens}
                onChange={e => updateForm('maxTokens', parseInt(e.target.value) || 16384)}
              />
            </div>
          </div>

          {/* SSL verify toggle */}
          <div className="formGroup" style={{ marginTop: 'var(--space-4)' }}>
            <label className={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={!form.sslVerify}
                onChange={e => updateForm('sslVerify', !e.target.checked)}
              />
              <span>Skip SSL certificate verification</span>
            </label>
            <span className="formHint">Enable for internal endpoints with self-signed certificates</span>
          </div>
        </>
      )}

      {isJev && <p className="formHint">Free key/model metadata check only. It does not prove billed Jev decision access or available credit.</p>}
      {/* Test connection */}
      {agentHealth.status === 'offline' && (
        <div className={styles.agentOfflineBanner} role="status">
          <AlertTriangle size={14} />
          <span>
            {agentHealth.error
              || 'The RedAmon agent service is offline, so connections cannot be tested right now.'}
          </span>
          <button className={styles.agentOfflineRetry} onClick={agentHealth.refresh} type="button">
            <RefreshCw size={12} /> Re-check
          </button>
        </div>
      )}
      <div className={styles.testSection}>
        <button type="button"
          className="secondaryButton"
          onClick={handleTest}
          // Never gate on 'unknown': a slow probe must not block a working setup.
          disabled={testing || agentHealth.status === 'offline'}
          title={agentHealth.status === 'offline'
            ? 'Unavailable while the RedAmon agent service is offline'
            : undefined}
        >
          {testing ? <Loader2 size={14} className={styles.spin} /> : null}
          {testing ? 'Testing...' : isJev ? 'Check key (free)' : 'Test Connection'}
        </button>
        {embedded && saveButton}
        {testResult && (
          <div className={`${styles.testResult} ${testResult.success ? styles.testSuccess : styles.testError}`}>
            {testResult.success ? <CheckCircle size={14} /> : <XCircle size={14} />}
            <span>{testResult.success ? testResult.text : testResult.error}</span>
          </div>
        )}
      </div>
    </div>
  )
}
