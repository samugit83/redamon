'use client'

import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { useAlertModal, useToast } from '@/components/ui'
import { StepUpModal } from '@/components/auth/StepUpModal'
import { readApiError, type ApiError } from '@/lib/apiError'
import { failureText } from '@/components/settings/failureText'
import { CheckField, FieldRow, Panel } from './Panel'
import styles from './instance.module.css'

export const LLM_PROVIDERS_URL = '/api/admin/llm-providers'
const LOAD_FAILED = "Couldn't load the instance LLM providers"
const SAVE_FAILED = 'The instance LLM provider was not saved'
const DELETE_FAILED = 'The instance LLM provider was not deleted'
const POLICY_FAILED = 'The policy was not changed'

const KIND_LABELS: Record<string, string> = {
  openai: 'OpenAI', anthropic: 'Anthropic', openrouter: 'OpenRouter', deepseek: 'DeepSeek', gemini: 'Google Gemini',
  glm: 'GLM (Zhipu AI)', kimi: 'Kimi (Moonshot)', qwen: 'Qwen (Alibaba)', xai: 'xAI (Grok)', mistral: 'Mistral AI',
  bedrock: 'AWS Bedrock', openai_compatible: 'OpenAI-compatible endpoint',
}

interface ProviderRow {
  id: string
  providerType: string
  name: string
  apiKey: string
  baseUrl: string
  modelIdentifier: string
  awsRegion: string
  awsAccessKeyId: string
  awsSecretKey: string
  awsBearerToken: string
  setIds: string[]
}
interface SetOption { id: string; name: string; kind: 'member' | 'admin'; builtin: boolean }
interface View { providers: ProviderRow[]; sets: SetOption[]; byoLlmForbidden: boolean; kinds: string[] }

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'denied'; message: string }
  | { kind: 'ready'; view: View }

interface Draft {
  id: string | null
  providerType: string
  name: string
  apiKey: string
  baseUrl: string
  modelIdentifier: string
  awsRegion: string
  awsAccessKeyId: string
  awsSecretKey: string
  awsBearerToken: string
  setIds: string[]
}

const emptyDraft = (kind: string): Draft => ({
  id: null, providerType: kind, name: '', apiKey: '', baseUrl: '', modelIdentifier: '', awsRegion: 'us-east-1',
  awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', setIds: [],
})
const draftOf = (p: ProviderRow): Draft => ({
  id: p.id, providerType: p.providerType, name: p.name, apiKey: p.apiKey, baseUrl: p.baseUrl, modelIdentifier: p.modelIdentifier,
  awsRegion: p.awsRegion, awsAccessKeyId: p.awsAccessKeyId, awsSecretKey: p.awsSecretKey, awsBearerToken: p.awsBearerToken,
  setIds: [...p.setIds],
})

/** The body a save sends: the fields of the kind only; masked secrets go back as they came (the route keeps them). */
export function providerBody(d: Draft): Record<string, unknown> {
  const body: Record<string, unknown> = { providerType: d.providerType, name: d.name.trim(), setIds: d.setIds }
  if (d.providerType === 'bedrock') {
    Object.assign(body, { awsRegion: d.awsRegion, awsAccessKeyId: d.awsAccessKeyId, awsSecretKey: d.awsSecretKey, awsBearerToken: d.awsBearerToken })
  } else {
    body.apiKey = d.apiKey
  }
  if (d.providerType === 'openai_compatible') Object.assign(body, { baseUrl: d.baseUrl.trim(), modelIdentifier: d.modelIdentifier.trim() })
  return body
}

type PendingWrite = { title: string; message: string; confirmLabel: string; run: (password: string) => Promise<void> }

/**
 * Instance LLM providers on the Instance page (step 6.11, GV-15): the providers Root adds for the
 * whole instance, each assigned to permission sets whose holders may then pick its models, and the
 * bring-your-own policy. GET /api/admin/llm-providers answers the confirmed Root only; every write
 * asks Root's password (StepUpModal) and a delete is confirmed first (useAlertModal). Secrets come
 * masked and go back masked, which keeps the stored value; a new endpoint needs the key typed again.
 */
export function LlmProvidersPanel() {
  const toast = useToast()
  const { dangerConfirm } = useAlertModal()
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [draft, setDraft] = useState<Draft | null>(null)
  const [pending, setPending] = useState<PendingWrite | null>(null)
  const [byoDraft, setByoDraft] = useState(false)

  const load = useCallback(async () => {
    setState({ kind: 'loading' })
    try {
      const res = await fetch(LLM_PROVIDERS_URL, { cache: 'no-store' })
      if (!res.ok) {
        const err = await readApiError(res, LOAD_FAILED)
        setState(res.status === 403 ? { kind: 'denied', message: err.reason } : { kind: 'error', message: err.message })
        return
      }
      const view = await res.json() as View
      setState({ kind: 'ready', view })
      setByoDraft(view.byoLlmForbidden)
    } catch (err) {
      setState({ kind: 'error', message: failureText(LOAD_FAILED, err) })
    }
  }, [])

  useEffect(() => { load() }, [load])

  const title = 'Instance LLM providers'
  const lead = 'LLM providers the whole instance shares. Assign each to permission sets: whoever holds one of them may pick its models; their keys are never shown to anyone.'
  if (state.kind === 'loading') {
    return <Panel id="llm-providers" title={title} lead={lead}><p className={styles.state} role="status">Loading the instance LLM providers…</p></Panel>
  }
  if (state.kind === 'denied') {
    return <Panel id="llm-providers" title={title} lead={lead}><p className={styles.note} role="note">{state.message}</p></Panel>
  }
  if (state.kind === 'error') {
    return (
      <Panel id="llm-providers" title={title} lead={lead}>
        <div className={styles.error} role="alert">
          {state.message}.{' '}
          <button type="button" className="textButton" onClick={load}>Retry</button>
        </div>
      </Panel>
    )
  }

  const { view } = state
  const setName = (id: string) => view.sets.find((s) => s.id === id)?.name ?? id
  const send = async (url: string, method: string, body: Record<string, unknown>, failed: string) => {
    const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
    if (!res.ok) throw await readApiError(res, failed) as ApiError
  }

  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!draft || !draft.name.trim()) return
    const d = draft
    setPending({
      title: d.id ? 'Save the instance LLM provider' : 'Add an instance LLM provider',
      message: `"${d.name.trim()}" will be offered to the holders of ${d.setIds.length} permission set(s). Enter your password to confirm.`,
      confirmLabel: d.id ? 'Save' : 'Add',
      run: async (password) => {
        await send(d.id ? `${LLM_PROVIDERS_URL}/${encodeURIComponent(d.id)}` : LLM_PROVIDERS_URL, d.id ? 'PUT' : 'POST',
          { ...providerBody(d), stepUpPassword: password }, SAVE_FAILED)
        toast.success(d.id ? 'Instance LLM provider saved' : 'Instance LLM provider added')
        setDraft(null)
        await load()
      },
    })
  }

  const remove = async (p: ProviderRow) => {
    const ok = await dangerConfirm(
      `Delete "${p.name}"? Its holders lose its models at once, and a project or feature set to one of them stops until someone picks another model.`,
      'Delete the instance LLM provider', { confirmLabel: 'Delete' })
    if (!ok) return
    setPending({
      title: 'Delete the instance LLM provider',
      message: `Enter your password to delete "${p.name}".`,
      confirmLabel: 'Delete',
      run: async (password) => {
        await send(`${LLM_PROVIDERS_URL}/${encodeURIComponent(p.id)}`, 'DELETE', { stepUpPassword: password }, DELETE_FAILED)
        toast.success('Instance LLM provider deleted')
        await load()
      },
    })
  }

  const savePolicy = () => setPending({
    title: 'Change the bring-your-own policy',
    message: byoDraft
      ? 'Accounts without the "Add your own LLM providers" permission will no longer have the agent use the providers they added. Enter your password to confirm.'
      : 'The agent will again use the providers every account added itself. Enter your password to confirm.',
    confirmLabel: 'Save the policy',
    run: async (password) => {
      await send(`${LLM_PROVIDERS_URL}/policy`, 'PUT', { byoLlmForbidden: byoDraft, stepUpPassword: password }, POLICY_FAILED)
      toast.success('Policy saved')
      await load()
    },
  })

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft((d) => (d ? { ...d, [key]: value } : d))
  const toggleSet = (id: string, on: boolean) =>
    setDraft((d) => (d ? { ...d, setIds: on ? [...d.setIds, id].sort() : d.setIds.filter((s) => s !== id) } : d))

  return (
    <Panel id="llm-providers" title={title} lead={lead}>
      {view.providers.length === 0 ? (
        <p className={styles.state}>No instance LLM provider yet: every account uses only the providers it adds itself.</p>
      ) : (
        <ul className={styles.toolList} aria-label="Instance LLM providers">
          {view.providers.map((p) => (
            <li key={p.id}>
              <strong>{p.name}</strong> ({KIND_LABELS[p.providerType] ?? p.providerType}
              {p.providerType === 'bedrock' ? '' : `, key ${p.apiKey || 'none'}`}):{' '}
              {p.setIds.length ? p.setIds.map(setName).join(', ') : 'assigned to no set, so offered to nobody'}{' '}
              <button type="button" className="textButton" onClick={() => setDraft(draftOf(p))} aria-label={`Edit ${p.name}`}>Edit</button>{' '}
              <button type="button" className="textButton" onClick={() => remove(p)} aria-label={`Delete ${p.name}`}>Delete</button>
            </li>
          ))}
        </ul>
      )}

      {draft ? (
        <form onSubmit={submit} className={styles.page} style={{ gap: 'var(--space-2)' }} aria-label={draft.id ? `Edit ${draft.name}` : 'New instance LLM provider'}>
          <FieldRow id="llm-kind" label="Kind" hint="A chat model provider. Changing the kind of a saved provider needs its key typed again.">
            <select id="llm-kind" className="select" value={draft.providerType} aria-describedby="llm-kind-hint" onChange={(e) => set('providerType', e.target.value)}>
              {view.kinds.map((k) => <option key={k} value={k}>{KIND_LABELS[k] ?? k}</option>)}
            </select>
          </FieldRow>
          <FieldRow id="llm-name" label="Name" hint="What the model pickers show, after 'Instance:'.">
            <input id="llm-name" className="input" value={draft.name} aria-describedby="llm-name-hint" onChange={(e) => set('name', e.target.value)} />
          </FieldRow>
          {draft.providerType === 'openai_compatible' && (
            <>
              <FieldRow id="llm-base-url" label="Base URL" hint="The endpoint's OpenAI-compatible address; a new one needs the key typed again.">
                <input id="llm-base-url" className="input" value={draft.baseUrl} aria-describedby="llm-base-url-hint" onChange={(e) => set('baseUrl', e.target.value)} />
              </FieldRow>
              <FieldRow id="llm-model" label="Model identifier" hint="The model the endpoint serves.">
                <input id="llm-model" className="input" value={draft.modelIdentifier} aria-describedby="llm-model-hint" onChange={(e) => set('modelIdentifier', e.target.value)} />
              </FieldRow>
            </>
          )}
          {draft.providerType === 'bedrock' ? (
            <>
              <FieldRow id="llm-aws-region" label="AWS region" hint="Where the Bedrock models run.">
                <input id="llm-aws-region" className="input" value={draft.awsRegion} aria-describedby="llm-aws-region-hint" onChange={(e) => set('awsRegion', e.target.value)} />
              </FieldRow>
              <FieldRow id="llm-aws-bearer" label="Bedrock API key" hint="A long-term API key, or the access key pair below.">
                <input id="llm-aws-bearer" type="password" autoComplete="off" className="input" value={draft.awsBearerToken} aria-describedby="llm-aws-bearer-hint" onChange={(e) => set('awsBearerToken', e.target.value)} />
              </FieldRow>
              <FieldRow id="llm-aws-id" label="Access key id" hint="With its secret, when there is no API key.">
                <input id="llm-aws-id" type="password" autoComplete="off" className="input" value={draft.awsAccessKeyId} aria-describedby="llm-aws-id-hint" onChange={(e) => set('awsAccessKeyId', e.target.value)} />
              </FieldRow>
              <FieldRow id="llm-aws-secret" label="Secret access key" hint="Kept masked; leave it as it is to keep the stored one.">
                <input id="llm-aws-secret" type="password" autoComplete="off" className="input" value={draft.awsSecretKey} aria-describedby="llm-aws-secret-hint" onChange={(e) => set('awsSecretKey', e.target.value)} />
              </FieldRow>
            </>
          ) : (
            <FieldRow id="llm-key" label="API key" hint="Kept masked; leave it as it is to keep the stored one.">
              <input id="llm-key" type="password" autoComplete="off" className="input" value={draft.apiKey} aria-describedby="llm-key-hint" onChange={(e) => set('apiKey', e.target.value)} />
            </FieldRow>
          )}
          <fieldset className={styles.field}>
            <legend>Offered to the holders of</legend>
            {view.sets.map((s) => (
              <CheckField key={s.id} id={`llm-set-${s.id}`} label={`${s.name}${s.kind === 'admin' ? ' (admin profile)' : ''}`}
                hint={s.builtin ? 'Built-in set' : 'Custom set'} checked={draft.setIds.includes(s.id)} onChange={(on) => toggleSet(s.id, on)} />
            ))}
          </fieldset>
          <div className={styles.actions}>
            <button type="submit" className="primaryButton" disabled={!draft.name.trim()}>{draft.id ? 'Save the provider' : 'Add the provider'}</button>
            <button type="button" className="secondaryButton" onClick={() => setDraft(null)}>Cancel</button>
            <span className={styles.hint}>Saving asks for your password.</span>
          </div>
        </form>
      ) : (
        <div className={styles.actions}>
          <button type="button" className="secondaryButton" onClick={() => setDraft(emptyDraft(view.kinds[0] ?? 'openai'))}>Add an instance LLM provider</button>
        </div>
      )}

      <CheckField id="llm-byo-forbidden" label="Only accounts allowed to add their own providers keep them"
        hint="On: the agent stops using the providers added by accounts without the 'Add your own LLM providers' permission."
        checked={byoDraft} onChange={setByoDraft} />
      <div className={styles.actions}>
        <button type="button" className="secondaryButton" disabled={byoDraft === view.byoLlmForbidden} onClick={savePolicy}>Save the policy</button>
      </div>

      <StepUpModal
        isOpen={pending !== null}
        title={pending?.title ?? ''}
        message={pending?.message ?? ''}
        confirmLabel={pending?.confirmLabel ?? 'Confirm'}
        onConfirm={async (password) => { await pending?.run(password) }}
        onClose={() => setPending(null)}
      />
    </Panel>
  )
}
