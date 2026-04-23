'use client'

import { useState, useCallback } from 'react'
import { Loader2, CheckCircle, XCircle, Plus, Trash2, Eye, EyeOff } from 'lucide-react'
import { useToast } from '@/components/ui'
import { PROVIDER_TYPES, OPENAI_COMPAT_PRESETS } from '@/lib/llmProviderPresets'
import type { ProviderType } from '@/lib/llmProviderPresets'
import styles from './Settings.module.css'

interface LlmProviderFormProps {
  userId: string
  provider?: ProviderData | null
  onSave: () => void
  onCancel: () => void
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
  awsRegion: string
  awsAccessKeyId: string
  awsSecretKey: string
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
  awsRegion: 'us-east-1',
  awsAccessKeyId: '',
  awsSecretKey: '',
}

export function LlmProviderForm({ userId, provider, onSave, onCancel }: LlmProviderFormProps) {
  const isEditing = !!provider?.id
  const toast = useToast()
  const [form, setForm] = useState<ProviderData>(() => provider || { ...EMPTY_PROVIDER })
  const [step, setStep] = useState<'type' | 'config'>(isEditing || form.providerType ? 'config' : 'type')
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ success: boolean; text?: string; error?: string } | null>(null)
  const [showApiKey, setShowApiKey] = useState(false)
  const [headerKey, setHeaderKey] = useState('')
  const [headerValue, setHeaderValue] = useState('')

  const updateForm = useCallback(<K extends keyof ProviderData>(field: K, value: ProviderData[K]) => {
    setForm(prev => ({ ...prev, [field]: value }))
    setTestResult(null)
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

  const handleTest = useCallback(async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const providerId = provider?.id || 'unsaved'
      const resp = await fetch(`/api/users/${userId}/llm-providers/${providerId}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const result = await resp.json()
      setTestResult({
        success: result.success,
        text: result.response_text,
        error: result.error,
      })
    } catch (err) {
      setTestResult({ success: false, error: String(err) })
    } finally {
      setTesting(false)
    }
  }, [userId, provider?.id, form])

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
        body: JSON.stringify(form),
      })

      if (!resp.ok) {
        const err = await resp.json()
        throw new Error(err.error || 'Failed to save')
      }

      toast.success(isEditing ? 'Provider updated' : 'Provider added')
      onSave()
    } catch (err) {
      console.error('Failed to save provider:', err)
      toast.error('Failed to save provider')
    } finally {
      setSaving(false)
    }
  }, [isEditing, userId, provider, form, onSave])

  // Step 1: Choose provider type
  if (step === 'type') {
    return (
      <div className={styles.formSection}>
        <h3 className={styles.formTitle}>Choose Provider Type</h3>
        <div className={styles.providerTypeGrid}>
          {PROVIDER_TYPES.map(pt => (
            <button
              key={pt.id}
              className={styles.providerTypeCard}
              onClick={() => selectType(pt.id)}
            >
              <span className={styles.providerTypeIcon}>{pt.icon}</span>
              <span className={styles.providerTypeName}>{pt.name}</span>
              <span className={styles.providerTypeDesc}>{pt.description}</span>
            </button>
          ))}
        </div>
        <div className={styles.formActions}>
          <button className="secondaryButton" onClick={onCancel}>Cancel</button>
        </div>
      </div>
    )
  }

  // Step 2: Configure
  const ptype = form.providerType as ProviderType
  const isKeyBased = ['openai', 'anthropic', 'openrouter'].includes(ptype)
  const isBedrock = ptype === 'bedrock'
  const isCompat = ptype === 'openai_compatible'
  return (
    <div className={styles.formSection}>
      <div className={styles.formHeader}>
        <h3 className={styles.formTitle}>
          {isEditing ? 'Edit' : 'Add'} {PROVIDER_TYPES.find(p => p.id === ptype)?.name || ptype} Provider
        </h3>
        {!isEditing && (
          <button className="textButton" onClick={() => setStep('type')}>Change type</button>
        )}
      </div>

      {/* Name */}
      <div className="formGroup">
        <label className="formLabel formLabelRequired">Display Name</label>
        <input
          className="textInput"
          value={form.name}
          onChange={e => updateForm('name', e.target.value)}
          placeholder="e.g., My OpenAI Key"
        />
      </div>

      {/* Key-based providers: just API key */}
      {isKeyBased && (
        <div className="formGroup">
          <label className="formLabel formLabelRequired">API Key</label>
          <div className={styles.secretInputWrapper}>
            <input
              className="textInput"
              type={showApiKey ? 'text' : 'password'}
              value={form.apiKey}
              onChange={e => updateForm('apiKey', e.target.value)}
              placeholder="sk-..."
            />
            <button
              className={styles.secretToggle}
              onClick={() => setShowApiKey(!showApiKey)}
              type="button"
            >
              {showApiKey ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
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
            <label className="formLabel formLabelRequired">AWS Access Key ID</label>
            <input
              className="textInput"
              type="password"
              value={form.awsAccessKeyId}
              onChange={e => updateForm('awsAccessKeyId', e.target.value)}
            />
          </div>
          <div className="formGroup">
            <label className="formLabel formLabelRequired">AWS Secret Access Key</label>
            <input
              className="textInput"
              type="password"
              value={form.awsSecretKey}
              onChange={e => updateForm('awsSecretKey', e.target.value)}
            />
          </div>
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
                <option key={p.name} value={p.name}>{p.name} — {p.description}</option>
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
              className="textInput"
              type="password"
              value={form.apiKey}
              onChange={e => updateForm('apiKey', e.target.value)}
              placeholder="Optional (leave empty for Ollama)"
            />
            <span className="formHint">Leave empty for local servers that don&apos;t require auth</span>
          </div>

          {/* Extra headers */}
          <div className="formGroup">
            <label className="formLabel">Extra Headers</label>
            {Object.entries(form.defaultHeaders).map(([k, v]) => (
              <div key={k} className={styles.headerRow}>
                <code className={styles.headerKey}>{k}</code>
                <code className={styles.headerValue}>{v}</code>
                <button className={styles.headerRemove} onClick={() => removeHeader(k)}>
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
              <button className="secondaryButton" onClick={addHeader} disabled={!headerKey.trim()}>
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
          <div className="formGroup">
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

      {/* Test connection */}
      <div className={styles.testSection}>
        <button
          className="secondaryButton"
          onClick={handleTest}
          disabled={testing}
        >
          {testing ? <Loader2 size={14} className={styles.spin} /> : null}
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
        {testResult && (
          <div className={`${styles.testResult} ${testResult.success ? styles.testSuccess : styles.testError}`}>
            {testResult.success ? <CheckCircle size={14} /> : <XCircle size={14} />}
            <span>{testResult.success ? testResult.text : testResult.error}</span>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className={styles.formActions}>
        <button className="secondaryButton" onClick={onCancel}>Cancel</button>
        <button
          className="primaryButton"
          onClick={handleSave}
          disabled={saving || !form.name || (!isCompat && !form.apiKey && !isBedrock) || (isBedrock && (!form.awsAccessKeyId || !form.awsSecretKey)) || (isCompat && (!form.baseUrl || !form.modelIdentifier))}
        >
          {saving ? <Loader2 size={14} className={styles.spin} /> : null}
          {isEditing ? 'Update' : 'Save'} Provider
        </button>
      </div>
    </div>
  )
}
