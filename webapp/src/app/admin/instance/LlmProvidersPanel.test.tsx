/**
 * The Instance page's "Instance LLM providers" panel (step 6.11, GV-15; DV-06, DV-19): the providers
 * Root adds for the whole instance, their sets and the bring-your-own policy. Every write asks Root's
 * password (the step-up dialog); a delete is confirmed first through useAlertModal; a masked key is
 * sent back as it came, so the route keeps the stored one. The route's own rules (Root only, audit
 * without secrets, masking) are api/admin/llm-providers/route.test.ts.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/LlmProvidersPanel.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const alerts = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async (orig) => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alerts }))
vi.mock('@/components/ui', async (orig) => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alerts }))

import { LlmProvidersPanel, providerBody } from './LlmProvidersPanel'

const VIEW = {
  providers: [{
    id: 'inst-1', providerType: 'openai', name: 'Shared OpenAI', apiKey: '••••••••1234', baseUrl: '', modelIdentifier: '',
    awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '', setIds: ['builtin:red-team-operator'],
  }],
  sets: [
    { id: 'builtin:default-member', name: 'Default member', kind: 'member', builtin: true },
    { id: 'builtin:red-team-operator', name: 'Red-team operator', kind: 'member', builtin: true },
    { id: 'builtin:full-admin', name: 'Full admin', kind: 'admin', builtin: true },
  ],
  byoLlmForbidden: false,
  kinds: ['openai', 'anthropic', 'bedrock', 'openai_compatible'],
}

type Answer = { status: number; body: unknown }
let routes: Record<string, Answer | ((init?: RequestInit) => Answer)>
let fetchMock: ReturnType<typeof vi.fn>
const calls = (method: string, path: string) => fetchMock.mock.calls.filter(([url, init]) => (init?.method ?? 'GET') === method && String(url) === path)
const bodyOf = (call: unknown[]) => JSON.parse(String((call[1] as RequestInit).body))

beforeEach(() => {
  alerts.dangerConfirm.mockReset().mockResolvedValue(true)
  routes = {
    'GET /api/admin/llm-providers': { status: 200, body: VIEW },
    'POST /api/admin/llm-providers': { status: 201, body: {} },
    'PUT /api/admin/llm-providers/inst-1': { status: 200, body: {} },
    'DELETE /api/admin/llm-providers/inst-1': { status: 200, body: { deleted: 'inst-1' } },
    'PUT /api/admin/llm-providers/policy': { status: 200, body: { byoLlmForbidden: true } },
  }
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const a = routes[`${init?.method ?? 'GET'} ${url}`]
    if (!a) return new Response(JSON.stringify({ error: 'unexpected' }), { status: 500 })
    const { status, body } = typeof a === 'function' ? a(init) : a
    return new Response(JSON.stringify(body), { status })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPanel = () => render(<ToastProvider><LlmProvidersPanel /></ToastProvider>)
async function confirmWithPassword(password = 'root-password') {
  const field = await screen.findByLabelText('Your password')
  fireEvent.change(field, { target: { value: password } })
  fireEvent.submit(field.closest('form')!)
}

describe('states', () => {
  test('loading, then the providers with their sets and masked key', async () => {
    renderPanel()
    expect(screen.getByRole('status')).toHaveTextContent('Loading the instance LLM providers')
    const list = await screen.findByRole('list', { name: 'Instance LLM providers' })
    expect(list).toHaveTextContent('Shared OpenAI (OpenAI, key ••••••••1234): Red-team operator')
  })

  test('refused (not the confirmed Root): the reason, no control', async () => {
    routes['GET /api/admin/llm-providers'] = { status: 403, body: { error: 'Only Root manages the instance LLM providers.', code: 'root_only' } }
    renderPanel()
    expect(await screen.findByRole('note')).toHaveTextContent('Only Root manages the instance LLM providers.')
    expect(screen.queryByRole('button')).toBeNull()
  })

  test('a failed read: the error with its cause, and Retry', async () => {
    routes['GET /api/admin/llm-providers'] = { status: 500, body: { error: 'boom', code: 'P1001' } }
    renderPanel()
    expect(await screen.findByRole('alert')).toHaveTextContent('(P1001 · HTTP 500)')
    routes['GET /api/admin/llm-providers'] = { status: 200, body: VIEW }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('list', { name: 'Instance LLM providers' })).toBeInTheDocument()
  })

  test('no provider yet: says so', async () => {
    routes['GET /api/admin/llm-providers'] = { status: 200, body: { ...VIEW, providers: [] } }
    renderPanel()
    expect(await screen.findByText(/No instance LLM provider yet/)).toBeInTheDocument()
  })
})

describe('writes, each with Root\'s password', () => {
  test('add: the kind, the name, the key and the ticked sets, then the password', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Add an instance LLM provider' }))
    const form = screen.getByRole('form', { name: 'New instance LLM provider' })
    fireEvent.change(within(form).getByLabelText('Kind'), { target: { value: 'anthropic' } })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'Shared Claude' } })
    fireEvent.change(within(form).getByLabelText('API key'), { target: { value: 'sk-ant-new' } })
    fireEvent.click(within(form).getByLabelText('Default member'))
    fireEvent.click(within(form).getByLabelText('Full admin (admin profile)'))
    fireEvent.click(within(form).getByRole('button', { name: 'Add the provider' }))
    await confirmWithPassword()
    await waitFor(() => expect(calls('POST', '/api/admin/llm-providers')).toHaveLength(1))
    expect(bodyOf(calls('POST', '/api/admin/llm-providers')[0])).toEqual({
      providerType: 'anthropic', name: 'Shared Claude', apiKey: 'sk-ant-new',
      setIds: ['builtin:default-member', 'builtin:full-admin'], stepUpPassword: 'root-password',
    })
  })

  test('edit: the masked key goes back as it came, so the stored one is kept', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit Shared OpenAI' }))
    const form = screen.getByRole('form', { name: 'Edit Shared OpenAI' })
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'OpenAI for red' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Save the provider' }))
    await confirmWithPassword()
    await waitFor(() => expect(calls('PUT', '/api/admin/llm-providers/inst-1')).toHaveLength(1))
    expect(bodyOf(calls('PUT', '/api/admin/llm-providers/inst-1')[0])).toMatchObject({
      name: 'OpenAI for red', apiKey: '••••••••1234', setIds: ['builtin:red-team-operator'],
    })
  })

  test('changing the kind of a saved provider empties its secret fields, so the new kind\'s are typed', async () => {
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit Shared OpenAI' }))
    const form = screen.getByRole('form', { name: 'Edit Shared OpenAI' })
    fireEvent.change(within(form).getByLabelText('Kind'), { target: { value: 'anthropic' } })
    expect(within(form).getByLabelText('API key')).toHaveValue('')
    fireEvent.change(within(form).getByLabelText('Kind'), { target: { value: 'openai' } })
    expect(within(form).getByLabelText('API key')).toHaveValue('••••••••1234')
  })

  test('a refused save keeps the dialog open with the reason', async () => {
    routes['POST /api/admin/llm-providers'] = { status: 400, body: { error: 'An API key is required.', code: 'key_required' } }
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Add an instance LLM provider' }))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'X' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add the provider' }))
    await confirmWithPassword()
    expect(await screen.findByText(/key_required/)).toBeInTheDocument()
  })

  test('delete: confirmed through useAlertModal first; cancel sends nothing', async () => {
    alerts.dangerConfirm.mockResolvedValueOnce(false)
    renderPanel()
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Shared OpenAI' }))
    await waitFor(() => expect(alerts.dangerConfirm).toHaveBeenCalledTimes(1))
    expect(screen.queryByLabelText('Your password')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Delete Shared OpenAI' }))
    await confirmWithPassword()
    await waitFor(() => expect(calls('DELETE', '/api/admin/llm-providers/inst-1')).toHaveLength(1))
    expect(bodyOf(calls('DELETE', '/api/admin/llm-providers/inst-1')[0])).toEqual({ stepUpPassword: 'root-password' })
  })

  test('the bring-your-own policy: ticked, saved with the password', async () => {
    renderPanel()
    const box = await screen.findByLabelText('Only accounts allowed to add their own providers keep them')
    const save = screen.getByRole('button', { name: 'Save the policy' })
    expect(save).toBeDisabled()
    fireEvent.click(box)
    fireEvent.click(save)
    await confirmWithPassword()
    await waitFor(() => expect(calls('PUT', '/api/admin/llm-providers/policy')).toHaveLength(1))
    expect(bodyOf(calls('PUT', '/api/admin/llm-providers/policy')[0])).toEqual({ byoLlmForbidden: true, stepUpPassword: 'root-password' })
  })
})

describe('the body of a save', () => {
  test('only the fields of its kind', () => {
    const base = { id: null, name: ' N ', apiKey: 'k', baseUrl: ' https://e/v1 ', modelIdentifier: ' m ', awsRegion: 'eu-west-1',
      awsAccessKeyId: 'a', awsSecretKey: 's', awsBearerToken: 'b', setIds: ['x'] }
    expect(providerBody({ ...base, providerType: 'openai' })).toEqual({ providerType: 'openai', name: 'N', apiKey: 'k', setIds: ['x'] })
    expect(providerBody({ ...base, providerType: 'openai_compatible' })).toEqual({
      providerType: 'openai_compatible', name: 'N', apiKey: 'k', baseUrl: 'https://e/v1', modelIdentifier: 'm', setIds: ['x'] })
    expect(providerBody({ ...base, providerType: 'bedrock' })).toEqual({
      providerType: 'bedrock', name: 'N', awsRegion: 'eu-west-1', awsAccessKeyId: 'a', awsSecretKey: 's', awsBearerToken: 'b', setIds: ['x'] })
  })
})
