/**
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'

const toastSuccess = vi.fn()
const toastError = vi.fn()

vi.mock('@/components/ui', () => ({
  useToast: () => ({ success: toastSuccess, error: toastError }),
  // The form also reaches for the alert modal; mocking the module wholesale
  // means every hook it uses has to be listed here or the render throws.
  useAlertModal: () => ({
    alert: vi.fn(async () => {}),
    alertError: vi.fn(async () => {}),
    alertWarning: vi.fn(async () => {}),
    confirm: vi.fn(async () => true),
    dangerConfirm: vi.fn(async () => true),
  }),
}))

import { LlmProviderForm } from './LlmProviderForm'
import type { ProviderData } from './LlmProviderForm'

/** The form preflights the agent (issue #184), so fetch is no longer called
 *  once per interaction. Route by URL and let each test answer the health probe
 *  independently of the call it actually cares about. */
function mockFetch(opts: {
  agentOnline?: boolean
  agentError?: string
  provider?: Partial<Response> & { json?: () => Promise<unknown> }
}) {
  const { agentOnline = true, agentError, provider } = opts
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === '/api/agent/health') {
      return agentOnline
        ? ({ ok: true, status: 200, json: async () => ({ status: 'healthy' }) } as Response)
        : ({ ok: false, status: 503, json: async () => ({ error: agentError ?? 'agent down' }) } as Response)
    }
    return (provider ?? { ok: true, status: 200, json: async () => ({}) }) as Response
  })
}

/** The single non-health call, i.e. the provider save/test the test is asserting on. */
function providerCalls(fetchMock: ReturnType<typeof mockFetch>) {
  return fetchMock.mock.calls.filter(([input]) => String(input) !== '/api/agent/health')
}

const PROVIDER: ProviderData = {
  id: 'ollama-provider',
  providerType: 'openai_compatible',
  name: 'Ollama Gemma 4',
  apiKey: '',
  baseUrl: 'http://host.docker.internal:11434/v1',
  modelIdentifier: 'gemma4:latest',
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

describe('LlmProviderForm Ollama reasoning control', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })

  test('enables the effort selector and persists the selected level', async () => {
    const fetchMock = mockFetch({})
    const onSave = vi.fn()

    render(
      <LlmProviderForm
        userId="user-1"
        provider={PROVIDER}
        onSave={onSave}
        onCancel={vi.fn()}
      />,
    )

    const toggle = screen.getByRole('checkbox', { name: 'Enable reasoning effort' })
    const effort = screen.getByRole('combobox', { name: 'Reasoning effort' })
    expect(toggle).not.toBeChecked()
    expect(effort).toBeDisabled()

    fireEvent.click(toggle)
    expect(effort).toBeEnabled()
    fireEvent.change(effort, { target: { value: 'medium' } })
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(1))
    const request = providerCalls(fetchMock)[0][1] as RequestInit
    const body = JSON.parse(request.body as string)
    expect(body.reasoningEnabled).toBe(true)
    expect(body.reasoningEffort).toBe('medium')
    expect(onSave).toHaveBeenCalled()
  })
})

// Issue #173: the save failed with a server-side reason the form threw away,
// leaving the user with an unactionable "Failed to save provider".
describe('LlmProviderForm save errors', () => {
  beforeEach(() => {
    // Auto-cleanup is off (vitest globals are not enabled), so an earlier
    // render would leave a second "Update Provider" button in the document.
    cleanup()
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })
  afterEach(cleanup)

  test('surfaces the API error message instead of the blanket one', async () => {
    mockFetch({
      provider: {
        ok: false,
        status: 404,
        json: async () => ({ error: 'User not found. Log out and back in.' }),
      },
    })
    const onSave = vi.fn()

    render(
      <LlmProviderForm userId="ghost" provider={PROVIDER} onSave={onSave} onCancel={vi.fn()} />,
    )
    // Save stays disabled until the form is dirty (useDirtyState).
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('User not found. Log out and back in.'))
    expect(onSave).not.toHaveBeenCalled()
  })

  test('a non-JSON error body still yields a message with the status code', async () => {
    mockFetch({
      provider: {
        ok: false,
        status: 502,
        json: async () => { throw new SyntaxError('Unexpected token <') },
      },
    })

    render(
      <LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Failed to save provider (HTTP 502)'))
  })
})

// Issue #184: the Test button proxies through the agent container. When that
// container is down the call dies inside RedAmon, and the resulting error was
// rendered under the Base URL field - so an infrastructure outage read as "your
// endpoint is wrong". The form must say so BEFORE the operator clicks.
describe('LlmProviderForm agent preflight', () => {
  beforeEach(() => {
    cleanup()
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })
  afterEach(cleanup)

  test('Test Connection stays enabled while the agent is healthy', async () => {
    mockFetch({ agentOnline: true })
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)

    const button = screen.getByRole('button', { name: 'Test Connection' })
    await waitFor(() => expect(button).toBeEnabled())
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  test('warns and disables Test when the agent is unreachable', async () => {
    mockFetch({
      agentOnline: false,
      agentError: 'Cannot reach the RedAmon agent service at http://agent:8080: the agent container is not running.',
    })
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)

    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('agent container is not running')
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Test Connection' })).toBeDisabled(),
    )
  })

  test('Test is NOT disabled while the probe is still in flight', () => {
    // A never-resolving probe: gating on 'unknown' would lock out a working stack.
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => new Promise(() => {}))
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)

    expect(screen.getByRole('button', { name: 'Test Connection' })).toBeEnabled()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  test('saving is unaffected by a dead agent - only testing needs it', async () => {
    const fetchMock = mockFetch({ agentOnline: false })
    const onSave = vi.fn()
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={onSave} onCancel={vi.fn()} />)

    await screen.findByRole('status')
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(onSave).toHaveBeenCalled())
    expect(providerCalls(fetchMock)).toHaveLength(1)
  })

  test('the Re-check control is reachable and operable from the keyboard', async () => {
    const fetchMock = mockFetch({ agentOnline: false })
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)

    await screen.findByRole('status')
    const recheck = screen.getByRole('button', { name: /Re-check/ })

    // A real <button type=button>: focusable, and Enter/Space activate it. A
    // div-with-onClick would pass a click test and strand keyboard users.
    expect(recheck.tagName).toBe('BUTTON')
    expect(recheck).toHaveAttribute('type', 'button')
    recheck.focus()
    expect(recheck).toHaveFocus()

    fireEvent.keyDown(recheck, { key: 'Enter', code: 'Enter' })
    fireEvent.click(recheck)  // what the browser synthesises for Enter on a button
    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(0))
  })

  test('the disabled Test button explains itself rather than failing silently', async () => {
    mockFetch({ agentOnline: false })
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)

    await screen.findByRole('status')
    const test = screen.getByRole('button', { name: 'Test Connection' })
    await waitFor(() => expect(test).toBeDisabled())
    expect(test).toHaveAttribute('title', expect.stringContaining('offline'))
  })

  test('Re-check re-probes and re-enables Test once the agent is back', async () => {
    const fetchMock = mockFetch({ agentOnline: false })
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)

    await screen.findByRole('status')
    fetchMock.mockImplementation(async () =>
      ({ ok: true, status: 200, json: async () => ({ status: 'healthy' }) }) as Response,
    )
    fireEvent.click(screen.getByRole('button', { name: /Re-check/ }))

    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Test Connection' })).toBeEnabled()
  })
})
