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

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('User not found. Log out and back in. (HTTP 404)'))
    expect(onSave).not.toHaveBeenCalled()
  })

  test('a server failure shows its code beside the route\'s sentence', async () => {
    mockFetch({
      provider: {
        ok: false,
        status: 500,
        json: async () => ({ error: 'Failed to update LLM provider', code: 'P2000' }),
      },
    })
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Failed to update LLM provider (P2000 · HTTP 500)'))
  })

  test('a non-JSON error body still yields a message with the status code', async () => {
    mockFetch({
      provider: {
        ok: false,
        status: 502,
        // A proxy's error page, as nginx sends it while the webapp restarts.
        text: async () => '<html><body>502 Bad Gateway</body></html>',
        json: async () => { throw new SyntaxError('Unexpected token <') },
      },
    })

    render(
      <LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />,
    )
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable reasoning effort' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Failed to save provider (non_json_response · HTTP 502)'))
  })
})

describe('LlmProviderForm Test Connection failures', () => {
  beforeEach(() => {
    cleanup()
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })
  afterEach(cleanup)

  async function runTest() {
    render(<LlmProviderForm userId="user-1" provider={PROVIDER} onSave={vi.fn()} onCancel={vi.fn()} />)
    const button = screen.getByRole('button', { name: 'Test Connection' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
  }

  test('the agent failing (not the provider) shows the route\'s code and both statuses', async () => {
    mockFetch({
      provider: {
        ok: false,
        status: 502,
        json: async () => ({
          success: false, error: 'The agent could not test this provider', code: 'agent_error', upstreamStatus: 401,
        }),
      },
    })
    await runTest()
    expect(await screen.findByText('The agent could not test this provider (agent_error · HTTP 502 · upstream HTTP 401)'))
      .toBeInTheDocument()
  })

  test('a non-JSON answer names its status instead of a SyntaxError', async () => {
    mockFetch({
      provider: {
        ok: false,
        status: 504,
        text: async () => '<html>504 Gateway Time-out</html>',
        json: async () => { throw new SyntaxError('Unexpected token <') },
      },
    })
    await runTest()
    expect(await screen.findByText('The provider test failed (non_json_response · HTTP 504)')).toBeInTheDocument()
    expect(screen.queryByText(/SyntaxError/)).not.toBeInTheDocument()
  })

  test('a test the agent ran keeps the provider\'s own answer', async () => {
    mockFetch({
      provider: { ok: true, status: 200, json: async () => ({ success: false, error: 'Error code: 401 - invalid api key' }) },
    })
    await runTest()
    expect(await screen.findByText('Error code: 401 - invalid api key')).toBeInTheDocument()
  })

  test('a failed test with no reason still says it failed', async () => {
    mockFetch({ provider: { ok: true, status: 200, json: async () => ({ success: false }) } })
    await runTest()
    expect(await screen.findByText('The provider test failed')).toBeInTheDocument()
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

// TypeSafe Jev: a non-chat provider, reachable only from its own section.
describe('LlmProviderForm Jev branch', () => {
  beforeEach(() => {
    cleanup()
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })
  afterEach(cleanup)

  const JEV_ROW: ProviderData = {
    ...PROVIDER,
    id: 'jev-row',
    providerType: 'jev',
    name: 'TypeSafe AI (Jev)',
    apiKey: '••••••••abcd',
    baseUrl: '',
    modelIdentifier: 'jev-1.13.0',
  }

  test('the generic type picker never lists Jev', () => {
    mockFetch({})
    render(<LlmProviderForm userId="user-1" onSave={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByText('Choose Provider Type')).toBeInTheDocument()
    expect(screen.queryByText(/TypeSafe/)).not.toBeInTheDocument()
    expect(screen.queryByText('OpenRouter (Jev)')).not.toBeInTheDocument()
    expect(screen.getByText('OpenAI')).toBeInTheDocument()
  })

  test('locked to Jev: key and pinned model only, no picker and no chat fields', () => {
    mockFetch({})
    render(<LlmProviderForm userId="user-1" lockedType="jev" onSave={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.queryByText('Choose Provider Type')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Change type' })).not.toBeInTheDocument()
    expect(screen.getByPlaceholderText('apikey_...')).toBeInTheDocument()
    expect(screen.getByTestId('jev-model')).toHaveTextContent('jev-1.13.0')
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Jev backend' })).toBeEnabled()
    expect(screen.queryByText(/Base URL/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Temperature/)).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Get API key/ })).toHaveAttribute(
      'href', 'https://console.typesafe.ai/keys')
  })

  test('Save stays disabled until a key is typed, then POSTs only the key and the pinned model', async () => {
    const fetchMock = mockFetch({})
    const onSave = vi.fn()
    render(<LlmProviderForm userId="user-1" lockedType="jev" onSave={onSave} onCancel={vi.fn()} />)

    const save = screen.getByRole('button', { name: 'Save Provider' })
    expect(save).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText('apikey_...'), { target: { value: 'apikey_abc_def' } })
    expect(save).toBeEnabled()
    fireEvent.click(save)

    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(1))
    const [url, init] = providerCalls(fetchMock)[0] as [string, RequestInit]
    expect(url).toBe('/api/users/user-1/llm-providers')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({
      providerType: 'jev', name: 'TypeSafe AI (Jev)', apiKey: 'apikey_abc_def',
    })
    await waitFor(() => expect(onSave).toHaveBeenCalled())
  })

  test('editing a saved Jev row sends no base URL or headers, and Test does the same', async () => {
    const fetchMock = mockFetch({ provider: { ok: true, status: 200, json: async () => ({ success: true }) } })
    render(<LlmProviderForm userId="user-1" provider={JEV_ROW} onSave={vi.fn()} onCancel={vi.fn()} />)

    fireEvent.change(screen.getByPlaceholderText('apikey_...'), { target: { value: 'apikey_new_key' } })
    fireEvent.click(screen.getByRole('button', { name: 'Check key (free)' }))
    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(1))
    fireEvent.click(screen.getByRole('button', { name: 'Update Provider' }))
    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(2))

    const [testUrl, testInit] = providerCalls(fetchMock)[0] as [string, RequestInit]
    const [saveUrl, saveInit] = providerCalls(fetchMock)[1] as [string, RequestInit]
    expect(testUrl).toBe('/api/users/user-1/llm-providers/jev-row/test')
    expect(saveUrl).toBe('/api/users/user-1/llm-providers/jev-row')
    expect(saveInit.method).toBe('PUT')
    for (const init of [testInit, saveInit]) {
      const body = JSON.parse(init.body as string)
      expect(body).toEqual({
        providerType: 'jev', name: 'TypeSafe AI (Jev)', apiKey: 'apikey_new_key',
      })
    }
  })
})

// Embedded in the project form (the Target AI panel), this form sits INSIDE a <form>.
// A <button> with no type is a submit button there, and Enter in a text input
// submits too: either would save the whole project from the token input.
describe('LlmProviderForm inside another <form>', () => {
  beforeEach(() => {
    cleanup()
    vi.restoreAllMocks()
    toastSuccess.mockReset()
    toastError.mockReset()
  })
  afterEach(cleanup)

  function inOuterForm(props: Partial<React.ComponentProps<typeof LlmProviderForm>> = {}) {
    const outerSubmit = vi.fn((e: React.FormEvent) => e.preventDefault())
    render(
      <form onSubmit={outerSubmit}>
        <LlmProviderForm userId="user-1" lockedType="jev" embedded onSave={vi.fn()} onCancel={vi.fn()} {...props} />
      </form>,
    )
    return outerSubmit
  }

  test('REGRESSION (untyped buttons submitted the enclosing form): Test and Save never submit it', async () => {
    const fetchMock = mockFetch({ provider: { ok: true, status: 200, json: async () => ({ success: true }) } })
    const outerSubmit = inOuterForm()
    fireEvent.change(screen.getByPlaceholderText('apikey_...'), { target: { value: 'apikey_abc_def' } })
    fireEvent.click(screen.getByRole('button', { name: 'Check key (free)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Save token' }))
    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(2))
    expect(outerSubmit).not.toHaveBeenCalled()
    for (const button of screen.getAllByRole('button')) expect(button).toHaveAttribute('type', 'button')
  })

  test('REGRESSION: Enter in the key field does not submit the enclosing form', () => {
    mockFetch({})
    const outerSubmit = inOuterForm()
    const input = screen.getByPlaceholderText('apikey_...')
    fireEvent.change(input, { target: { value: 'apikey_abc_def' } })
    const notCancelled = fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
    expect(notCancelled).toBe(false)             // default prevented: no implicit submit
    expect(outerSubmit).not.toHaveBeenCalled()
  })

  test('embedded: no frame title, no Cancel, no pinned-model block; Save sits beside Test', () => {
    mockFetch({})
    inOuterForm()
    expect(screen.queryByText(/Add TypeSafe AI \(Jev\) Provider/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument()
    expect(screen.queryByTestId('jev-model')).not.toBeInTheDocument()
    const test = screen.getByRole('button', { name: 'Check key (free)' })
    expect(test.parentElement).toContainElement(screen.getByRole('button', { name: 'Save token' }))
  })

  test('not embedded (Global Settings) is unchanged: title, Cancel and the model line are there', () => {
    mockFetch({})
    render(<LlmProviderForm userId="user-1" lockedType="jev" onSave={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByText(/Add TypeSafe AI \(Jev\) Provider/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
    expect(screen.getByTestId('jev-model')).toHaveTextContent('jev-1.13.0')
  })
})

describe('Jev named OpenRouter forms', () => {
  beforeEach(cleanup)
  afterEach(cleanup)
  test('create picker changes backend, resets key and submits the edited name', async () => {
    const fetchMock = mockFetch({})
    render(<LlmProviderForm userId="user-1" lockedType="jev" onSave={vi.fn()} onCancel={vi.fn()} />)
    fireEvent.change(screen.getByPlaceholderText('apikey_...'), { target: { value: 'typesafe-key' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Jev backend' }), { target: { value: 'jev_openrouter' } })
    expect(screen.getByLabelText('OpenRouter Jev API key')).toHaveValue('')
    expect(screen.getByTestId('jev-model')).toHaveTextContent('typesafe/jev-1.13')
    expect(screen.getByRole('link', { name: /Get API key/ })).toHaveAttribute('href', 'https://openrouter.ai/settings/keys')
    fireEvent.change(screen.getByRole('textbox', { name: 'Display Name' }), { target: { value: 'Recon staging' } })
    fireEvent.change(screen.getByLabelText('OpenRouter Jev API key'), { target: { value: 'openrouter-key' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save Provider' }))
    await waitFor(() => expect(providerCalls(fetchMock)).toHaveLength(1))
    expect(JSON.parse(String(providerCalls(fetchMock)[0][1]?.body))).toEqual({ providerType: 'jev_openrouter', name: 'Recon staging', apiKey: 'openrouter-key' })
  })
  test('saved backend is locked but name stays editable', () => {
    mockFetch({})
    render(<LlmProviderForm userId="user-1" provider={{ ...PROVIDER, providerType: 'jev_openrouter' }} onSave={vi.fn()} onCancel={vi.fn()} />)
    expect(screen.getByRole('combobox', { name: 'Jev backend' })).toBeDisabled()
    expect(screen.getByRole('textbox', { name: 'Display Name' })).toBeEnabled()
    expect(screen.getByText(/does not prove billed Jev decision access/)).toBeInTheDocument()
  })
})
