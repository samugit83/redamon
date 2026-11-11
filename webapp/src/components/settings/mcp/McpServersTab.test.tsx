/**
 * Settings > MCP Tool Plugins: every failure says its cause.
 *
 * Before: a list that failed read as "nothing saved", the Enable toggle did
 * nothing on a refused write, a save whose agent reload failed read as applied,
 * and the Test panel crashed on a FastAPI `{detail}` body (no `warnings`) or
 * showed a SyntaxError on a proxy's HTML page.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'

const ui = vi.hoisted(() => ({
  toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn(), info: vi.fn() },
  alerts: {
    alert: vi.fn(async () => {}),
    alertError: vi.fn(async () => {}),
    alertWarning: vi.fn(async () => {}),
    confirm: vi.fn(async () => true),
    dangerConfirm: vi.fn(async () => true),
  },
}))
vi.mock('@/components/ui', () => ({
  useToast: () => ui.toast,
  useAlertModal: () => ui.alerts,
  // StepUpModal is built on Modal (ID-25: re-pointing asks for the password).
  Modal: ({ isOpen, title, children }: { isOpen: boolean; title?: string; children: React.ReactNode }) =>
    isOpen ? <div role="dialog" aria-label={title}>{children}</div> : null,
}))

import McpServersTab from './McpServersTab'

const SERVER = {
  id: 'probe', name: 'Probe', description: '', enabled: true, transport: 'stdio',
  default_phases: ['informational', 'exploitation', 'post_exploitation'], tags: [],
  headers: {}, connect_timeout: 60, read_timeout: 600,
  command: 'echo', args: [], env: {}, cwd: '', encoding: 'utf-8', tools: [],
}

type Answer = Response | (() => Response)
let answers: { list: Answer; put: Answer; test: Answer }
const fetchMock = vi.fn()

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status })
const resolve = (a: Answer) => (typeof a === 'function' ? a() : a)

beforeEach(() => {
  vi.clearAllMocks()
  answers = {
    list: json(200, { servers: [SERVER] }),
    put: json(200, { server: SERVER, servers: [SERVER] }),
    test: json(200, { ok: true, discovered_tools: [], warnings: [], elapsed_ms: 12, error: null }),
  }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url === '/api/mcp/test') return resolve(answers.test).clone()
    if (method === 'PUT') return resolve(answers.put).clone()
    return resolve(answers.list).clone()
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function openEdit() {
  render(<McpServersTab userId="u1" />)
  fireEvent.click(await screen.findByTitle('Edit'))
  await screen.findByText('Edit MCP Tool Plugin: probe')
}

describe('list', () => {
  test('a failed load shows its cause with a Retry, not "nothing saved"', async () => {
    answers.list = json(500, { error: 'Failed to list MCP servers', code: 'P1001' })
    render(<McpServersTab userId="u1" />)
    expect((await screen.findByRole('alert')).textContent)
      .toContain("Couldn't load your MCP Tool Plugins (P1001 · HTTP 500).")
    expect(screen.queryByText(/No saved MCP Tool Plugins yet/)).toBeNull()

    answers.list = json(200, { servers: [SERVER] })
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Probe')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})

describe('Enable toggle', () => {
  test('a refused write is a toast with the code and status', async () => {
    answers.put = json(500, { error: 'Failed to update MCP server', code: 'P2034' })
    render(<McpServersTab userId="u1" />)
    fireEvent.click(await screen.findByRole('checkbox'))
    await waitFor(() => expect(ui.toast.error)
      .toHaveBeenCalledWith('Disable failed: Failed to update MCP server (P2034 · HTTP 500)'))
  })

  test('a save whose agent reload failed warns that it is not live yet', async () => {
    answers.put = json(200, {
      server: SERVER, servers: [SERVER],
      warnings: [{ service: 'agent', message: 'The agent did not reload its MCP Tool Plugins', code: 'agent_unreachable', cause: 'ECONNREFUSED' }],
    })
    render(<McpServersTab userId="u1" />)
    fireEvent.click(await screen.findByRole('checkbox'))
    await waitFor(() => expect(ui.toast.warning).toHaveBeenCalledWith(
      'The agent did not reload its MCP Tool Plugins (agent_unreachable · ECONNREFUSED)', 'Saved, but not live yet'))
  })
})

describe('Save', () => {
  test('a database failure shows the code and status in the banner', async () => {
    answers.put = json(500, { error: 'Failed to update MCP server', code: 'P2034' })
    await openEdit()
    fireEvent.change(screen.getByPlaceholderText('My MCP Tool Plugin'), { target: { value: 'Probe 2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Failed to update MCP server (P2034 · HTTP 500)')).toBeInTheDocument()
  })

  test('a proxy error page names its status instead of a SyntaxError', async () => {
    answers.put = new Response('<html>502 Bad Gateway</html>', { status: 502 })
    await openEdit()
    fireEvent.change(screen.getByPlaceholderText('My MCP Tool Plugin'), { target: { value: 'Probe 2' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Failed to update the MCP Tool Plugin (non_json_response · HTTP 502)')).toBeInTheDocument()
  })
})

describe('Test (Discover)', () => {
  test('the agent failing shows the route\'s code and both statuses, and the panel survives', async () => {
    answers.test = json(502, {
      ok: false, error: 'The agent could not run the MCP test', code: 'agent_error', upstreamStatus: 401,
      discovered_tools: [], warnings: [], elapsed_ms: 0,
    })
    await openEdit()
    fireEvent.click(screen.getByRole('button', { name: /Discover and add new tools/ }))
    expect(await screen.findByText('- The agent could not run the MCP test (agent_error · HTTP 502 · upstream HTTP 401)', { exact: false }))
      .toBeInTheDocument()
  })

  test('a proxy error page names its status', async () => {
    answers.test = new Response('<html>504 Gateway Time-out</html>', { status: 504 })
    await openEdit()
    fireEvent.click(screen.getByRole('button', { name: /Discover and add new tools/ }))
    expect(await screen.findByText(/The MCP test failed \(non_json_response · HTTP 504\)/)).toBeInTheDocument()
  })

  test('a 200 missing its lists does not crash the panel', async () => {
    answers.test = json(200, { ok: false, error: 'server is disabled — enable it before testing' })
    await openEdit()
    fireEvent.click(screen.getByRole('button', { name: /Discover and add new tools/ }))
    expect(await screen.findByText(/server is disabled/)).toBeInTheDocument()
  })
})

describe('HD-24: a new URL with the masked token or header asks for it again', () => {
  const HTTP_SERVER = {
    ...SERVER, transport: 'streamable_http', command: '', url: 'https://mcp.example.com/mcp',
    auth: { type: 'bearer', token: '••••••••1234' }, headers: { 'X-Api-Key': '••••••••9999' },
  }
  const refusal = (field: string) => json(400, {
    error: 'The server URL changed: type the bearer token again, or clear it. A stored secret is never sent to a new address unless it is entered again.',
    code: 'secret_reentry_required', field, fields: [field], endpoint: 'url',
  })

  async function changeUrl() {
    answers.list = json(200, { servers: [HTTP_SERVER] })
    await openEdit()
    fireEvent.change(screen.getByPlaceholderText(/my-mcp:8080/), { target: { value: 'https://elsewhere.example.net/mcp' } })
  }

  test('Save: the token field shows the message and takes the focus', async () => {
    answers.put = refusal('auth.token')
    await changeUrl()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('type the bearer token again')
    await waitFor(() => expect(screen.getByLabelText('bearer token')).toHaveFocus())
    expect(screen.getByText(/\(secret_reentry_required · HTTP 400\)/)).toBeInTheDocument()
  })

  test('Save: a header value named by the refusal focuses the headers box', async () => {
    answers.put = refusal('headers.X-Api-Key')
    await changeUrl()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await screen.findByRole('alert')
    await waitFor(() => expect(screen.getByPlaceholderText(/X-Organization-ID/)).toHaveFocus())
  })

  test('Test (Discover): the same refusal focuses the token field', async () => {
    answers.test = refusal('auth.token')
    await changeUrl()
    fireEvent.click(screen.getByRole('button', { name: /Discover and add new tools/ }))
    await waitFor(() => expect(screen.getByLabelText('bearer token')).toHaveFocus())
    expect(screen.getByRole('alert')).toHaveTextContent('type the bearer token again')
  })
})

describe('review of 1.6: a new stdio command with masked env values asks for them again', () => {
  const STDIO = { ...SERVER, command: 'npx', env: { SHODAN_API_KEY: '••••••••5555' } }

  test('Save: the env box shows the message and takes the focus', async () => {
    answers.list = json(200, { servers: [STDIO] })
    answers.put = json(400, {
      error: 'The command changed: type the value of the environment variable "SHODAN_API_KEY" again, or clear it. A stored secret is never sent to a new address unless it is entered again.',
      code: 'secret_reentry_required', field: 'env.SHODAN_API_KEY', fields: ['env.SHODAN_API_KEY'], endpoint: 'command',
    })
    await openEdit()
    fireEvent.change(screen.getByPlaceholderText('uvx, npx, python, ...'), { target: { value: 'sh' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('environment variable "SHODAN_API_KEY"')
    await waitFor(() => expect(screen.getByPlaceholderText(/SHODAN_API_KEY=/)).toHaveFocus())
  })
})

describe('ID-25: re-pointing a saved server asks for the password (review of 1.6)', () => {
  const HTTP_SERVER = {
    ...SERVER, transport: 'streamable_http', command: '', url: 'https://mcp.example.com/mcp',
    auth: { type: 'bearer', token: '••••••••1234' },
  }

  test('the refused save opens the password dialog; the password goes with the same save', async () => {
    answers.list = json(200, { servers: [HTTP_SERVER] })
    const puts: Record<string, unknown>[] = []
    const queue = [
      json(403, { error: 'Enter your password to confirm this action.', code: 'step_up_required' }),
      json(200, { server: HTTP_SERVER, servers: [HTTP_SERVER] }),
    ]
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'PUT') {
        puts.push(JSON.parse(String(init!.body)))
        return queue.shift()!
      }
      return resolve(answers.list).clone()
    })
    await openEdit()
    fireEvent.change(screen.getByPlaceholderText(/my-mcp:8080/), { target: { value: 'https://elsewhere.example.net/mcp' } })
    fireEvent.change(screen.getByLabelText('bearer token'), { target: { value: 'typed-token' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('new address')
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(puts).toHaveLength(2))
    expect(puts[0].stepUpPassword).toBeUndefined()
    expect(puts[1]).toMatchObject({ url: 'https://elsewhere.example.net/mcp', stepUpPassword: 'my-password' })
    await waitFor(() => expect(screen.queryByText('Edit MCP Tool Plugin: probe')).toBeNull())
  })
})
