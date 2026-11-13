/**
 * The settings form opened by a Read + Write collaborator (step 5.7, SH-26; SH-08):
 *   - the options that come from an account (models, the Jev configuration, the user skills, MCP
 *     servers, which keys are set) are the project OWNER's, read once from GET
 *     /api/projects/[id]/owner-catalog (names and presence only), never the collaborator's own;
 *   - picking from that catalog needs Manage: below it the model picker, the Jev selection, the
 *     owner's skills and MCP tools are disabled with the reason; a co-owner picks and saves;
 *   - a change the access does not reach (a gate loosened, the owner's secret) is refused where it
 *     is made, with the reason; a gate tightened is an editor's;
 *   - nothing offers to save a key: the owner's keys are the owner's;
 *   - the owner's form, and the form with RBAC_SHARING_ENABLED off (no `myAccess`), are unchanged.
 *
 * The real form and sections; fetch, the scan hooks and the project context are doubles.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/ProjectForm.collaborator.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AlertProvider, ToastProvider } from '@/components/ui'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { shareSecretFields } from '@/lib/reconSettings/registry'

const h = vi.hoisted(() => ({ userId: 'bob', catalogAnswer: null as null | (() => Response | Promise<Response>) }))

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }) }))
// Every dynamic view renders nothing, except the workflow view, which offers two single-field auto-saves.
vi.mock('next/dynamic', () => ({
  default: () => (props: { onAutoSaveField?: (field: string, value: unknown) => void; updateField?: (field: string, value: unknown) => void }) =>
    props.onAutoSaveField ? (
      <>
        <button type="button" onClick={() => { props.updateField!('agentRequireToolConfirmation', false); props.onAutoSaveField!('agentRequireToolConfirmation', false) }}>auto-save-gate</button>
        <button type="button" onClick={() => { props.updateField!('naabuRateLimit', 25); props.onAutoSaveField!('naabuRateLimit', 25) }}>auto-save-ordinary</button>
      </>
    ) : null,
}))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: h.userId }),
  useOptionalProject: () => ({ userId: h.userId }),
}))
vi.mock('@/hooks/useReconStatus', () => ({ default: () => ({ state: null }) }))
vi.mock('@/hooks/useScanControls', () => ({
  useScanControls: () => ({ otherScansOpen: false, gvm: {}, githubHunt: {}, trufflehog: { runs: [] }, supplyChain: {} }),
}))
vi.mock('@/components/scans/ScanActions', () => ({ ScanActions: () => null }))
vi.mock('@/app/graph/components/OtherScansModal/OtherScansModal', () => ({ OtherScansModal: () => null }))
vi.mock('@/hooks/useMultiPartialReconStatus', () => ({ useMultiPartialReconStatus: () => ({ runs: [], activeRuns: [], refetch: vi.fn() }) }))
vi.mock('@/hooks/useScanStartFailure', () => ({ useScanStartFailure: () => ({ handleStartFailure: vi.fn() }) }))
vi.mock('@/hooks/useDrawerOffsets', () => ({ useDrawerOffsets: () => {} }))
vi.mock('@/hooks/useMultiPartialReconSSE', () => ({ useMultiPartialReconSSE: () => ({ logsMap: {}, phaseMap: {}, clearLogsForRun: vi.fn() }) }))
vi.mock('@/hooks/useDetectedHostIp', () => ({ useDetectedHostIp: () => '' }))
// The plugin skill-version rows are the plugin platform's (their own tests); not this step's.
vi.mock('@/components/plugins/skills/PluginSkillRow', () => ({ PluginSkillRow: () => null }))
vi.mock('@/components/plugins/skills/usePluginSkillOverrides', () => ({
  usePluginSkillOverrides: () => ({ bySkill: new Map(), rowActions: {}, reload: vi.fn(), error: null }),
}))

import { ProjectForm } from './ProjectForm'
import { MINIMAL_DEFAULTS } from './formDefaults'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const writeAccess = (manage: boolean): MyAccess => ({
  level: 'write', via: 'share', owner: OWNER,
  toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage },
})
const EDITOR = writeAccess(false)
const CO_OWNER = writeAccess(true)
const OWNS: MyAccess = { level: 'owner', via: 'owner', owner: OWNER, toggles: { rawData: true } }

const CATALOG = {
  providers: [{ id: 'op1', name: "Alice's OpenAI", type: 'openai', hasKey: true }],
  jevProviders: [{ id: 'jev1', name: 'Alice Jev', type: 'jev', hasKey: true }],
  attackSkills: [{ id: 'sk1', name: 'Alice recon playbook', quarantined: false }],
  tradecraftResources: [{ id: 'tr1', name: 'Alice notes', enabled: true }],
  mcpServers: [{ id: 'mcp1', name: 'Alice MCP', enabled: true, default_phases: [], tools: [{ name: 'alice_tool', default_phases: [] }] }],
  keys: { githubAccessToken: true, tavilyApiKey: false, shodanApiKey: true, serpApiKey: true, wpscanApiToken: true, urlscanApiKey: true, pdcpApiKey: true },
}
const OWNER_MODELS = {
  'OpenAI (owner)': [
    { id: 'openai/gpt-owner', name: 'GPT Owner', context_length: 128000, description: '' },
    { id: 'openai/gpt-owner-mini', name: 'GPT Owner Mini', context_length: 128000, description: '' },
  ],
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
let fetchMock: ReturnType<typeof vi.fn>
const asked = () => fetchMock.mock.calls.map(c => String(c[0]))

beforeEach(() => {
  h.userId = 'bob'
  h.catalogAnswer = null
  window.history.replaceState({}, '', '/projects/p1/settings')
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/projects/p1' && init?.method === 'PUT') return json(200, { updatedAt: '2026-11-13T11:00:00.000Z' })
    if (url === '/api/projects/p1/owner-catalog?models=1') return json(200, { ...CATALOG, models: OWNER_MODELS })
    if (url === '/api/projects/p1/owner-catalog') return h.catalogAnswer ? h.catalogAnswer() : json(200, CATALOG)
    // Each account's own data, under its own name, so a leak into the form shows.
    const own = /^\/api\/users\/(\w+)\/(\w[\w-]*)/.exec(url)
    if (own) {
      const [, who, what] = own
      if (what === 'settings') return json(200, { tavilyApiKey: '', githubAccessToken: '' })
      if (what === 'mcp') return json(200, { servers: [{ id: `${who}mcp`, name: `${who} own MCP`, description: '', enabled: true, default_phases: [], tools: [{ name: `${who}_tool` }] }] })
      if (what === 'attack-skills') return json(200, [{ id: `${who}sk`, name: `${who} own skill`, createdAt: '2026-10-10T10:00:00.000Z' }])
      if (what === 'llm-providers') {
        return who === h.userId
          ? json(200, [{ id: `${who}jev`, name: `${who} own Jev`, providerType: 'jev', apiKey: '••••abcd', modelIdentifier: '' }])
          : json(403, { error: 'Forbidden', code: 'forbidden' })
      }
      return json(200, [])
    }
    if (url === '/api/models') return json(200, { 'Own providers': [{ id: 'own/model', name: 'Own Model', context_length: null, description: '' }] })
    return json(200, [])
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function providers({ children }: { children: ReactNode }) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider><AlertProvider>{children}</AlertProvider></ToastProvider>
    </QueryClientProvider>
  )
}

const onSubmit = vi.fn(async () => ({}))

function draw(myAccess: MyAccess | undefined, ownerId = 'alice', { workflow = false } = {}) {
  onSubmit.mockClear()
  const initialData = {
    ...MINIMAL_DEFAULTS, id: 'p1', userId: ownerId, name: 'ACME lab', targetDomain: 'acme-lab.test',
    updatedAt: '2026-11-13T10:00:00.000Z',
    agentOpenaiModel: 'openai/gpt-owner', aiInPipeline: true, aiPipelineModel: 'openai/gpt-owner',
    agentRequireToolConfirmation: true, agentGuardrailEnabled: false,
    agentToolPhaseMap: { web_search: ['informational'], alice_tool: ['informational'] },
    attackSkillConfig: { builtIn: {}, user: {} },
    ...(myAccess ? { myAccess } : {}),
  } as never
  render(
    <ProjectForm mode="edit" initialData={initialData} onSubmit={onSubmit as never} onCancel={vi.fn()} projectIdFromRoute="p1" />,
    { wrapper: providers },
  )
  if (!workflow) fireEvent.click(screen.getByTitle('Tab view'))
}

const tab = (label: string) => fireEvent.click(screen.getAllByRole('button').find(b => b.textContent?.trim() === label)!)
const toggleRow = (label: string) => within(screen.getByText(label).parentElement!.parentElement!).getByRole('switch')
const llmPicker = () => screen.getByText('LLM Model').parentElement!.querySelector('[aria-disabled], [class*="modelSelectorInput"]') as HTMLElement
const catalogRead = (models: boolean) => asked().filter(u => u === `/api/projects/p1/owner-catalog${models ? '?models=1' : ''}`).length

describe('ProjectForm opened by a collaborator', () => {
  test("collaborator sees the owner's providers", async () => {
    draw(CO_OWNER)
    await waitFor(() => expect(catalogRead(false)).toBe(1))
    await waitFor(() => expect(catalogRead(true)).toBe(1))

    tab('Agent Behaviour')
    await waitFor(() => expect(llmPicker()).toHaveTextContent('GPT Owner'))
    fireEvent.click(llmPicker())
    expect(screen.getByText('GPT Owner Mini')).toBeInTheDocument()
    expect(screen.queryByText('Own Model')).toBeNull()

    tab('Tool Matrix')
    expect(await screen.findByText('Alice MCP')).toBeInTheDocument()
    expect(screen.getByText('alice_tool')).toBeInTheDocument()
    expect(screen.queryByText('bob own MCP')).toBeNull()

    tab('Agent Skills')
    expect(await screen.findByText('Alice recon playbook')).toBeInTheDocument()
    expect(screen.queryByText('bob own skill')).toBeNull()

    tab('Target & Modules')
    const jev = await screen.findByLabelText('Jev provider')
    expect(within(jev).getByRole('option', { name: /Alice Jev/ })).toBeInTheDocument()
    expect(within(jev).queryByRole('option', { name: /bob own Jev/ })).toBeNull()

    // The key warnings of the discovery sections read the owner's keys too.
    tab('Discovery & OSINT')
    await screen.findByText('Shodan Enrichment')

    // Nothing of the collaborator's own account is read, and nothing of the owner's account route.
    const own = asked().filter(u => /^\/api\/users\/(bob|alice)\//.test(u) || u === '/api/models')
    expect(own).toEqual([])
  })

  test('no secret in the catalog response: the form reads names and presence, and its save sends no secret column', async () => {
    draw(CO_OWNER)
    await waitFor(() => expect(catalogRead(true)).toBe(1))
    tab('Other Scans')
    const github = await screen.findByTestId('owner-key-githubAccessToken')
    expect(within(github).getByText('Set')).toBeInTheDocument()
    expect(within(github).queryByRole('textbox')).toBeNull()
    expect(github.querySelector('input')).toBeNull()
    // The routes that would answer a masked key (the owner's providers and settings) are never read.
    expect(asked().some(u => u.startsWith('/api/users/alice/'))).toBe(false)

    tab('Agent Behaviour')
    fireEvent.click(toggleRow('Agent Guardrail'))
    fireEvent.click(screen.getByRole('button', { name: /Update Settings/ }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    const sent = (onSubmit.mock.calls[0] as unknown[])[0] as Record<string, unknown>
    expect(sent.agentGuardrailEnabled).toBe(true)
    for (const { key } of shareSecretFields()) expect(Object.keys(sent)).not.toContain(key)
  })

  test('controls disabled without Manage', async () => {
    draw(EDITOR)
    await waitFor(() => expect(catalogRead(false)).toBe(1))
    expect(screen.getByTestId('write-access-notice')).toHaveTextContent(
      'Read + Write access, shared by Alice (alice@e2e.local). You can change ordinary settings and tighten safety gates.')
    const reason = /Read \+ Write access without Manage, shared by Alice \(alice@e2e\.local\): picking from the owner's models, Jev configurations, skills and MCP tools needs Manage/

    tab('Agent Behaviour')
    const picker = llmPicker()
    expect(picker).toHaveAttribute('aria-disabled', 'true')
    expect(picker.title).toMatch(reason)
    expect(picker).toHaveTextContent('openai/gpt-owner')
    fireEvent.click(picker)
    expect(screen.queryByText('GPT Owner Mini')).toBeNull()

    // Loosening the dangerous-tool confirmation needs Manage and Exploitation & shells: refused in place.
    const confirmation = toggleRow('Require Tool Confirmation')
    fireEvent.click(confirmation)
    expect(confirmation).toHaveAttribute('aria-checked', 'true')
    expect(await screen.findByText(/agentRequireToolConfirmation needs Manage and Exploitation & shells/)).toBeInTheDocument()
    // Tightening a gate is an editor's.
    const guardrail = toggleRow('Agent Guardrail')
    fireEvent.click(guardrail)
    expect(guardrail).toHaveAttribute('aria-checked', 'true')

    tab('Tool Matrix')
    const tool = await screen.findByLabelText('alice_tool: informational')
    expect(tool).toBeDisabled()
    expect(tool.title).toMatch(reason)

    tab('Agent Skills')
    const skill = await screen.findByTestId('user-skill-toggle-sk1')
    expect(within(skill).getByRole('switch')).toBeDisabled()
    expect(skill.title).toMatch(reason)

    tab('Target & Modules')
    const jev = await screen.findByLabelText('Jev provider')
    expect(jev).toBeDisabled()
    expect(jev.title).toMatch(reason)

    // The owner's secret is the owner's: typing into the CypherFix token changes nothing.
    tab('CypherFix')
    const token = screen.getByPlaceholderText('ghp_xxxxxxxxxxxx') as HTMLInputElement
    fireEvent.change(token, { target: { value: 'ghp_typed' } })
    expect(token.value).toBe('')
    expect(await screen.findByText(/cypherfixGithubToken needs the project's owner/)).toBeInTheDocument()
    // Without Manage the owner's models are never listed.
    expect(catalogRead(true)).toBe(0)
  })

  test("a workflow auto-save of a change the access does not reach is never sent; an ordinary one is", async () => {
    draw(EDITOR, 'alice', { workflow: true })
    await waitFor(() => expect(catalogRead(false)).toBe(1))
    const puts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT')
    fireEvent.click(screen.getByRole('button', { name: 'auto-save-gate' }))
    expect(await screen.findByText(/agentRequireToolConfirmation needs Manage and Exploitation & shells/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'auto-save-ordinary' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(JSON.parse(String((puts()[0][1] as RequestInit).body))).toEqual({ naabuRateLimit: 25, updatedAt: '2026-11-13T10:00:00.000Z' })
  })

  test("co-owner picks from the owner's catalog", async () => {
    draw(CO_OWNER)
    await waitFor(() => expect(catalogRead(true)).toBe(1))
    expect(screen.getByTestId('write-access-notice')).toHaveTextContent('Read + Write access with Manage, shared by Alice')

    tab('Agent Behaviour')
    await waitFor(() => expect(llmPicker()).toHaveTextContent('GPT Owner'))
    expect(llmPicker()).not.toHaveAttribute('aria-disabled')
    fireEvent.click(llmPicker())
    fireEvent.click(screen.getByText('GPT Owner Mini'))

    tab('Agent Skills')
    const skill = within(await screen.findByTestId('user-skill-toggle-sk1')).getByRole('switch')
    expect(skill).toBeEnabled()
    fireEvent.click(skill)

    tab('Tool Matrix')
    expect(await screen.findByLabelText('alice_tool: exploitation')).toBeEnabled()

    tab('Target & Modules')
    const jev = await screen.findByLabelText('Jev provider')
    expect(jev).toBeEnabled()
    fireEvent.change(jev, { target: { value: 'jev1' } })

    fireEvent.click(screen.getByRole('button', { name: /Update Settings/ }))
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1))
    const sent = (onSubmit.mock.calls[0] as unknown[])[0] as Record<string, unknown>
    expect(sent).toMatchObject({ agentOpenaiModel: 'openai/gpt-owner-mini', jevProviderId: 'jev1', attackSkillConfig: { user: { sk1: true } } })
    for (const { key } of shareSecretFields()) expect(Object.keys(sent)).not.toContain(key)
  })

  test('save-key hidden', async () => {
    draw(CO_OWNER)
    await waitFor(() => expect(catalogRead(false)).toBe(1))

    tab('Tool Matrix')
    expect(await screen.findByTestId('owner-key-missing-web_search')).toHaveTextContent('The owner has no Tavily key')
    expect(screen.queryByText(/No Tavily key - Add/)).toBeNull()

    tab('Other Scans')
    const github = await screen.findByTestId('owner-key-githubAccessToken')
    expect(github).toHaveTextContent("Only the owner can replace this one, in their Global Settings.")
    expect(within(github).queryByRole('button')).toBeNull()

    tab('Agent Skills')
    await screen.findByText('Alice recon playbook')
    for (const label of ['Upload Skill', 'Upload Batch', 'Import from Community']) {
      expect(screen.queryByRole('button', { name: new RegExp(label) })).toBeNull()
    }
    expect(screen.queryByTitle('Download .md')).toBeNull()

    tab('Target & Modules')
    await screen.findByLabelText('Jev provider')
    expect(screen.queryByText('Add Jev configuration')).toBeNull()

    // The Triage review and CodeFix models are the owner's account settings, not the collaborator's own.
    tab('CypherFix')
    expect(screen.getByTestId('owner-feature-models')).toBeInTheDocument()
    expect(screen.queryByText('Triage review model')).toBeNull()
  })

  test("the owner's catalog loading, failed and retried", async () => {
    let answer: (r: Response) => void = () => {}
    h.catalogAnswer = () => new Promise<Response>(resolve => { answer = resolve })
    draw(EDITOR)
    tab('Tool Matrix')
    expect(await screen.findByText(/Loading the project owner's MCP Tool Plugins/)).toBeInTheDocument()
    answer(json(500, { error: "Could not read the project owner's catalogs", code: 'P2024' }))
    const retry = await screen.findByRole('button', { name: 'Retry' })
    const failed = retry.parentElement!
    expect(failed).toHaveAttribute('role', 'alert')
    expect(failed).toHaveTextContent("Could not read the project owner's catalogs (P2024 · HTTP 500)")
    // The key warnings say they could not be checked rather than guessing.
    expect(screen.getByText(/so a tool may be shown without its missing-key warning/)).toBeInTheDocument()
    h.catalogAnswer = null
    fireEvent.click(retry)
    expect(await screen.findByText('Alice MCP')).toBeInTheDocument()
    expect(catalogRead(false)).toBe(2)
  })

  test('owner unchanged, and switch off (no myAccess) unchanged', async () => {
    for (const access of [OWNS, undefined]) {
      h.userId = 'alice'
      fetchMock.mockClear()
      draw(access, 'alice')
      await waitFor(() => expect(asked()).toContain('/api/users/alice/settings'))
      expect(screen.queryByTestId('write-access-notice')).toBeNull()

      tab('Agent Behaviour')
      await waitFor(() => expect(asked()).toContain('/api/models'))
      fireEvent.click(toggleRow('Require Tool Confirmation'))
      expect(toggleRow('Require Tool Confirmation')).toHaveAttribute('aria-checked', 'false')

      tab('Tool Matrix')
      expect(await screen.findByText('alice own MCP')).toBeInTheDocument()
      expect(await screen.findByText(/No Tavily key - Add/)).toBeInTheDocument()

      tab('Agent Skills')
      expect(await screen.findByText('alice own skill')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Upload Skill/ })).toBeEnabled()

      expect(asked().some(u => u.includes('/owner-catalog'))).toBe(false)
      cleanup()
    }
  })
})
