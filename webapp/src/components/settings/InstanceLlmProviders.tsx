'use client'

import { useCallback, useEffect, useState } from 'react'
import { useRbacFlags } from '@/hooks/useCan'
import { readApiError } from '@/lib/apiError'
import { failureText } from './failureText'

export const ACCOUNT_LLM_PROVIDERS_URL = '/api/account/llm-providers'
const LOAD_FAILED = "Couldn't load the providers your administrator made available"

const KIND_LABELS: Record<string, string> = {
  openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', deepseek: 'DeepSeek', gemini: 'Google Gemini',
  glm: 'GLM (Zhipu AI)', kimi: 'Kimi (Moonshot)', qwen: 'Qwen (Alibaba)', xai: 'xAI (Grok)', mistral: 'Mistral AI',
  bedrock: 'AWS Bedrock', openai_compatible: 'OpenAI-compatible endpoint',
}

interface Summary { id: string; name: string; providerType: string }

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; providers: Summary[] }

/**
 * Global Settings -> LLM Providers: the instance LLM providers an administrator made available to the
 * account through a permission set it holds (step 6.11, GV-15), by name and kind only; their models
 * are in every model picker as "Instance: <name>". `onCount` tells the page how many there are, so
 * "Models by feature" opens for an account whose only providers are these. Shown only with
 * RBAC_GOVERNANCE_ENABLED on; off, nothing is read and the count is 0 (DV-30).
 */
export function InstanceLlmProviders({ onCount }: { onCount: (count: number) => void }) {
  const governance = useRbacFlags()?.governance === true
  const [state, setState] = useState<State>({ kind: 'loading' })

  const load = useCallback(async () => {
    setState({ kind: 'loading' })
    try {
      const res = await fetch(ACCOUNT_LLM_PROVIDERS_URL, { cache: 'no-store' })
      if (res.status === 404) {
        setState({ kind: 'ready', providers: [] })
        return
      }
      if (!res.ok) throw await readApiError(res, LOAD_FAILED)
      const body = await res.json() as { providers?: Summary[] }
      setState({ kind: 'ready', providers: body.providers ?? [] })
    } catch (err) {
      setState({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [])

  useEffect(() => {
    if (governance) load()
  }, [governance, load])

  const count = governance && state.kind === 'ready' ? state.providers.length : 0
  useEffect(() => { onCount(count) }, [count, onCount])

  if (!governance) return null
  if (state.kind === 'loading') return <p role="status">Loading the providers your administrator made available…</p>
  if (state.kind === 'error') {
    return (
      <p role="alert">
        {state.message}.{' '}
        <button type="button" className="textButton" onClick={load}>Retry</button>
      </p>
    )
  }
  if (state.providers.length === 0) return null
  return (
    <section aria-labelledby="instance-llm-providers-title">
      <h4 id="instance-llm-providers-title">Provided by your administrator</h4>
      <p>Their models are in every model picker as &quot;Instance: name&quot;. Their keys are never shown.</p>
      <ul aria-label="Instance LLM providers">
        {state.providers.map((p) => <li key={p.id}>{p.name} ({KIND_LABELS[p.providerType] ?? p.providerType})</li>)}
      </ul>
    </section>
  )
}
