/**
 * The graph page's own Other Scans modal and AI drawer on a project the person does not own
 * (step 5.7 follow-up, SH-26): scans and runs spend the project OWNER's keys and models, so these
 * screens show the owner's, read from the same owner catalog the settings form reads
 * (hooks/useProjectOwnerCatalog.ts, OwnerCatalogContext), never the viewer's own account:
 *   - Other Scans: the GitHub token and the TruffleHog source keys by the owner's presence, as
 *     "Owner's setting", nothing to type in and no link to the viewer's own settings;
 *   - the drawer: the missing-key warnings from the owner's keys with no "Add", the model picker
 *     listing the owner's models at Manage and locked below it with the reason, the MCP tools and
 *     the user skills of the tooltips from the owner's catalog;
 *   - the owner, and every screen with RBAC_SHARING_ENABLED off (no provider value), read their own
 *     account exactly as before (DV-30).
 * The page's wiring (one catalog read around both surfaces) is checked at source level, as
 * otherScansStartWiring.test.ts does: rendering /graph needs providers, a router and live scan data.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/ownerCatalogSurfaces.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, renderHook, screen, cleanup, fireEvent, within, waitFor, act } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ReactNode } from 'react'
import { OwnerCatalogContext, type OwnerCatalogSource } from '@/hooks/useOwnerCatalog'
import { OWNER_KEY_FIELDS, type OwnerCatalog, type OwnerKeyField } from '@/lib/ownerCatalog'
import { SETTINGS_KEYS_HREF } from '@/lib/settingsLinks'

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'bob' }),
  useOptionalProject: () => ({ userId: 'bob' }),
}))
vi.mock('@/hooks/usePluginContributions', () => ({ usePluginContributions: () => ({ data: [] }) }))
// The tooltips open on hover; render their content inline so it can be read.
vi.mock('@/components/ui/Tooltip/Tooltip', () => ({
  Tooltip: ({ content, children }: { content: ReactNode; children: ReactNode }) => (
    <div>{children}<div data-testid="tooltip-content">{content}</div></div>
  ),
}))
vi.mock('@/components/ui', async (orig) => ({
  ...(await orig<typeof import('@/components/ui')>()),
  useToast: () => ({ success: vi.fn(), info: vi.fn(), error: vi.fn(), warning: vi.fn() }),
  useAlertModal: () => ({ alertError: vi.fn() }),
  Modal: ({ isOpen, children }: { isOpen: boolean; children: ReactNode }) => (isOpen ? <div>{children}</div> : null),
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({
  useAlertModal: () => ({ alertError: vi.fn() }),
  useOptionalAlertModal: () => null,
}))
vi.mock('./components/OtherScansModal/useSupplyChainConfig', () => ({
  useSupplyChainConfig: () => ({
    source: 'upload', sbomFile: 'package-lock.json', repoUrl: '', repoRef: '', org: '',
    loading: false, error: null, ready: true, target: 'package-lock.json', reload: () => {},
  }),
}))

import { OtherScansModal } from './components/OtherScansModal/OtherScansModal'
import { useApiKeyModal } from './components/AIAssistantDrawer/hooks/useApiKeyModal'
import { useModelPicker } from './components/AIAssistantDrawer/hooks/useModelPicker'
import { useAttackSkillData } from './components/AIAssistantDrawer/hooks/useAttackSkillData'
import { PhaseIndicatorBar } from './components/AIAssistantDrawer/PhaseIndicatorBar'
import { ToolExecutionCard } from './components/AIAssistantDrawer/ToolExecutionCard'
import { formatModelDisplay } from './components/AIAssistantDrawer/phaseConfig'

const PICK_REFUSAL = "Read + Write access without Manage, shared by Alice: picking from the owner's models, Jev configurations, skills and MCP tools needs Manage"

const keys = (set: Partial<Record<OwnerKeyField, boolean>>) =>
  ({ ...Object.fromEntries(OWNER_KEY_FIELDS.map(f => [f, false])), ...set }) as Record<OwnerKeyField, boolean>

const CATALOG: OwnerCatalog = {
  providers: [{ id: 'op1', name: "Alice's OpenAI", type: 'openai', hasKey: true }],
  jevProviders: [],
  attackSkills: [{ id: 'sk1', name: 'Alice recon playbook', quarantined: false }],
  tradecraftResources: [],
  mcpServers: [{ id: 'mcp1', name: 'Alice MCP', enabled: true, default_phases: [], tools: [{ name: 'alice_tool', default_phases: [] }] }],
  keys: keys({ githubAccessToken: true, shodanApiKey: true, serpApiKey: true, wpscanApiToken: true, urlscanApiKey: true, pdcpApiKey: true }),
}
const OWNER_MODELS = {
  'OpenAI (owner)': [{ id: 'openai/gpt-owner', name: 'GPT Owner', context_length: 128000, description: '' }],
}

function source(over: Partial<OwnerCatalogSource> = {}): OwnerCatalogSource {
  return {
    catalog: CATALOG, status: 'ready', error: null,
    models: null, modelsStatus: 'off', modelsError: null,
    pickRefusal: PICK_REFUSAL, retry: vi.fn(),
    ...over,
  }
}
const CO_OWNER_SOURCE = () => source({ pickRefusal: null, models: OWNER_MODELS, modelsStatus: 'ready' })

const within_ = (value: OwnerCatalogSource | null) =>
  function Wrapper({ children }: { children: ReactNode }) {
    return <OwnerCatalogContext.Provider value={value}>{children}</OwnerCatalogContext.Provider>
  }

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
let fetchMock: ReturnType<typeof vi.fn>
const asked = () => fetchMock.mock.calls.map(c => String(c[0]))
const ownAccountReads = () => asked().filter(u => u.startsWith('/api/users/'))
const settle = () => new Promise(r => setTimeout(r, 30))

beforeEach(() => {
  fetchMock = vi.fn(async (input: string) => {
    const url = String(input)
    // The viewer's own account: every key set, its own MCP server and skill, so a leak shows.
    if (url === '/api/users/bob/settings') {
      return json({ githubAccessToken: '••••bob1', tavilyApiKey: '••••bob2', shodanApiKey: '', serpApiKey: '', wpscanApiToken: '', urlscanApiKey: '', pdcpApiKey: '' })
    }
    if (url === '/api/users/bob/mcp') return json({ servers: [{ id: 'bobmcp', name: 'Bob MCP', enabled: true, tools: [{ name: 'bob_tool' }] }] })
    if (url === '/api/users/bob/attack-skills/available') {
      return json({ builtIn: [{ id: 'xss', name: 'Cross-Site Scripting' }], user: [{ id: 'bobsk', name: 'Bob own skill' }] })
    }
    if (url === '/api/projects/p1') return json({ id: 'p1', attackSkillConfig: { builtIn: { xss: true }, user: { sk1: true, bobsk: true } } })
    if (url === '/api/models') return json({ 'Bob providers': [{ id: 'bob/model', name: 'Bob Model', context_length: null, description: '' }] })
    return json({})
  })
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

// ─── Other Scans ────────────────────────────────────────────────────────────

const TRUFFLE_PROFILES = [{
  id: 'p-docker', source: 'docker', label: '', config: { images: ['nginx:1.25'] },
  missingCredentials: [{ settingsKey: 'trufflehogDockerToken', label: 'Docker token' }],
}]

function otherScans(value: OwnerCatalogSource | null, hasGithubToken = false) {
  return render(
    <OwnerCatalogContext.Provider value={value}>
      <OtherScansModal
        isOpen onClose={() => {}} projectId="p1" hasReconData hasGithubToken={hasGithubToken}
        githubHuntStatus="idle" supplyChainStatus="idle"
        trufflehogProfiles={TRUFFLE_PROFILES} trufflehogRunsBySource={{}}
        onStartGithubHunt={vi.fn()} onStartTrufflehog={vi.fn()} onStartSupplyChain={vi.fn()}
      />
    </OwnerCatalogContext.Provider>,
  )
}
const card = (title: string) => screen.getByRole('heading', { name: title }).closest('.card') as HTMLElement
const startOf = (scope: HTMLElement) =>
  within(scope).getAllByRole('button').find(b => b.textContent?.includes('Start')) as HTMLButtonElement

describe('Other Scans on a shared project', () => {
  test("the GitHub card answers from the owner's token, and the viewer's account is not read", async () => {
    otherScans(source())
    await settle()
    const github = card('GitHub Secret Hunt')
    expect(startOf(github).disabled).toBe(false)
    expect(within(github).queryByTestId('owner-key-githubAccessToken')).toBeNull()
    expect(ownAccountReads()).toEqual([])
  })

  test("a token the owner has not set: Owner's setting, nothing to type in, Start disabled", async () => {
    otherScans(source({ catalog: { ...CATALOG, keys: keys({}) } }))
    await settle()
    const github = card('GitHub Secret Hunt')
    expect(within(github).getByTestId('owner-key-githubAccessToken')).toHaveTextContent("Owner's setting")
    expect(within(github).queryByRole('textbox')).toBeNull()
    expect(startOf(github).disabled).toBe(true)
    expect(startOf(github).title).toBe('GitHub token required')
  })

  test("a TruffleHog source missing an owner key says the owner has not set it, without a link to the viewer's settings", async () => {
    otherScans(source())
    await settle()
    const truffle = card('Secret Multiscanner')
    const start = startOf(truffle)
    expect(start.disabled).toBe(true)
    expect(start.title).toBe("The project owner has not set Docker token")
    expect(within(truffle).getByText('Docker token required')).toBeInTheDocument()
    expect(within(truffle).queryAllByRole('link').map(a => a.getAttribute('href'))).not.toContain(`${SETTINGS_KEYS_HREF}#trufflehog-keys`)
    expect(within(truffle).getByTestId('owner-key-trufflehogDockerToken')).toBeInTheDocument()
  })

  test("the owner's modal (no owner catalog) reads the person's own keys and links their settings, as before", async () => {
    otherScans(null)
    await waitFor(() => expect(ownAccountReads()).toEqual(['/api/users/bob/settings']))
    const github = card('GitHub Secret Hunt')
    await waitFor(() => expect(startOf(github).disabled).toBe(false))
    const truffle = card('Secret Multiscanner')
    expect(startOf(truffle).title).toBe('Set Docker token in Global Settings > API Keys')
    expect(within(truffle).getByRole('link', { name: 'Docker token required' })).toHaveAttribute('href', `${SETTINGS_KEYS_HREF}#trufflehog-keys`)
  })
})

// ─── The AI drawer ──────────────────────────────────────────────────────────

describe('the AI drawer: missing-key warnings', () => {
  test("from the owner's keys, read-only: nothing to add, nothing read from the viewer's account", async () => {
    const { result } = renderHook(() => useApiKeyModal('bob'), { wrapper: within_(source()) })
    await settle()
    expect([...result.current.missingApiKeys].sort()).toEqual(['web_search'])
    expect(result.current.apiKeysReadOnly).toBe(true)
    act(() => result.current.openApiKeyModal('web_search'))
    expect(result.current.apiKeyModal).toBeNull()
    expect(ownAccountReads()).toEqual([])
  })

  test('while the owner catalog loads, no key is called missing', async () => {
    const { result } = renderHook(() => useApiKeyModal('bob'), { wrapper: within_(source({ catalog: null, status: 'loading' })) })
    await settle()
    expect(result.current.missingApiKeys.size).toBe(0)
    expect(ownAccountReads()).toEqual([])
  })

  test("the owner's drawer reads the person's own keys and can add one, as before", async () => {
    const { result } = renderHook(() => useApiKeyModal('bob'), { wrapper: within_(null) })
    await waitFor(() => expect(result.current.missingApiKeys.size).toBeGreaterThan(0))
    expect(ownAccountReads()).toEqual(['/api/users/bob/settings'])
    expect([...result.current.missingApiKeys].sort()).toEqual(['cve_intel', 'execute_gau', 'execute_wpscan', 'google_dork', 'shodan'])
    expect(result.current.apiKeysReadOnly).toBe(false)
    act(() => result.current.openApiKeyModal('shodan'))
    expect(result.current.apiKeyModal).toBe('shodan')
  })

  test('a missing key with nothing to add says so, without "Add" and without a button', () => {
    const item = { type: 'tool_execution', id: 't1', timestamp: new Date(), tool_name: 'web_search', tool_args: {}, status: 'success', output_chunks: [] }
    const { container } = render(
      <ToolExecutionCard item={item as never} isExpanded={false} onToggleExpand={() => {}} missingApiKey />,
    )
    const note = container.querySelector('[class*="apiKeyMissing"]') as HTMLElement
    expect(note).toHaveTextContent('No Tavily key')
    expect(note.textContent).not.toMatch(/Add/)
    expect(note.getAttribute('role')).toBeNull()
  })
})

describe('the AI drawer: model picker', () => {
  test("a co-owner's picker lists the owner's models, and /api/models is not asked", async () => {
    const { result } = renderHook(() => useModelPicker('bob'), { wrapper: within_(CO_OWNER_SOURCE()) })
    act(() => result.current.setShowModelModal(true))
    await settle()
    expect(result.current.showModelModal).toBe(true)
    expect(result.current.modelRefusal).toBeNull()
    expect(Object.keys(result.current.filteredModels)).toEqual(['OpenAI (owner)'])
    expect(result.current.modelsLoading).toBe(false)
    expect(asked()).not.toContain('/api/models')
  })

  test('below Manage the picker does not open and says why; nothing is asked', async () => {
    const { result } = renderHook(() => useModelPicker('bob'), { wrapper: within_(source()) })
    act(() => result.current.setShowModelModal(true))
    await settle()
    expect(result.current.showModelModal).toBe(false)
    expect(result.current.modelRefusal).toBe(PICK_REFUSAL)
    expect(asked()).toEqual([])
  })

  test("the owner's picker reads the person's models, as before", async () => {
    const { result } = renderHook(() => useModelPicker('bob'), { wrapper: within_(null) })
    act(() => result.current.setShowModelModal(true))
    await waitFor(() => expect(Object.keys(result.current.filteredModels)).toEqual(['Bob providers']))
    expect(result.current.modelRefusal).toBeNull()
    expect(asked()).toContain('/api/models')
  })
})

describe('the AI drawer: the user skills of the tooltip', () => {
  test("are the owner's, by name", async () => {
    const { result } = renderHook(() => useAttackSkillData('bob', 'p1'), { wrapper: within_(source()) })
    await waitFor(() => expect(result.current.skillData).not.toBeNull())
    expect(result.current.skillData?.user).toEqual([{ id: 'sk1', name: 'Alice recon playbook' }])
    expect(result.current.skillData?.builtIn).toEqual([{ id: 'xss', name: 'Cross-Site Scripting' }])
  })

  test("the owner's tooltip lists the person's own skills, as before", async () => {
    const { result } = renderHook(() => useAttackSkillData('bob', 'p1'), { wrapper: within_(null) })
    await waitFor(() => expect(result.current.skillData).not.toBeNull())
    expect(result.current.skillData?.user).toEqual([{ id: 'bobsk', name: 'Bob own skill' }])
  })
})

describe('the AI drawer: the phase bar', () => {
  type Props = React.ComponentProps<typeof PhaseIndicatorBar>
  function bar(value: OwnerCatalogSource | null, over: Partial<Props> = {}) {
    const props: Props = {
      currentPhase: 'informational', toolPhaseMap: {}, attackPathType: '', skillData: null, iterationCount: 0,
      stealthMode: false, settingsDropdownRef: { current: null }, showSettingsDropdown: false,
      setShowSettingsDropdown: vi.fn(), setSettingsModal: vi.fn(), setShowModelModal: vi.fn(),
      modelName: 'openai/gpt-owner', projectId: 'p1', ...over,
    }
    render(<OwnerCatalogContext.Provider value={value}><PhaseIndicatorBar {...props} /></OwnerCatalogContext.Provider>)
    return props
  }
  const toolsTooltip = () => screen.getAllByTestId('tooltip-content').find(el => el.textContent?.includes('Phase Tools'))

  test("the MCP tools are the owner's, and the viewer's servers are not read", async () => {
    bar(source())
    await settle()
    expect(toolsTooltip()).toHaveTextContent('alice_tool')
    expect(toolsTooltip()).not.toHaveTextContent('bob_tool')
    expect(ownAccountReads()).toEqual([])
  })

  test('below Manage the model badge is locked with the reason', async () => {
    const p = bar(source())
    const badge = screen.getByRole('button', { name: formatModelDisplay('openai/gpt-owner') })
    expect(badge).toHaveAttribute('aria-disabled', 'true')
    expect(badge).toHaveAttribute('title', PICK_REFUSAL)
    fireEvent.click(badge)
    expect(p.setShowModelModal).not.toHaveBeenCalled()
  })

  test('a co-owner opens the picker', () => {
    const p = bar(CO_OWNER_SOURCE())
    const badge = screen.getByRole('button', { name: formatModelDisplay('openai/gpt-owner') })
    expect(badge).not.toHaveAttribute('aria-disabled')
    fireEvent.click(badge)
    expect(p.setShowModelModal).toHaveBeenCalledWith(true)
  })

  test("the owner's bar reads the person's MCP servers and opens the picker, as before", async () => {
    const p = bar(null)
    await waitFor(() => expect(toolsTooltip()).toHaveTextContent('bob_tool'))
    expect(ownAccountReads()).toEqual(['/api/users/bob/mcp'])
    const badge = screen.getByRole('button', { name: formatModelDisplay('openai/gpt-owner') })
    expect(badge).not.toHaveAttribute('title')
    fireEvent.click(badge)
    expect(p.setShowModelModal).toHaveBeenCalledWith(true)
  })
})

// ─── The page's wiring (source level) ───────────────────────────────────────

describe("the graph page provides one owner catalog around both surfaces", () => {
  const pageSrc = readFileSync(join(process.cwd(), 'src/app/graph/page.tsx'), 'utf8')
  const drawerSrc = readFileSync(join(process.cwd(), 'src/app/graph/components/AIAssistantDrawer/AIAssistantDrawer.tsx'), 'utf8')

  /** The JSX between `<OwnerCatalogContext.Provider value={ownerCatalog}>` and its closing tags. */
  const provided = () => {
    const spans: string[] = []
    let at = 0
    for (;;) {
      const open = pageSrc.indexOf('<OwnerCatalogContext.Provider value={ownerCatalog}>', at)
      if (open === -1) return spans
      const close = pageSrc.indexOf('</OwnerCatalogContext.Provider>', open)
      spans.push(pageSrc.slice(open, close))
      at = close
    }
  }

  test('one read, by the shared rule, with the person\'s access to the open project; models only while the drawer is open', () => {
    expect(pageSrc.match(/useProjectOwnerCatalog\(/g)).toHaveLength(1)
    expect(pageSrc).toContain('useProjectOwnerCatalog(projectId, useProjectAccess(projectId), { models: isAIOpen })')
    expect(pageSrc).not.toMatch(/useOwnerCatalog\(/)
  })

  test('Other Scans and the AI drawer sit inside it', () => {
    const spans = provided()
    expect(spans.some(s => s.includes('<OtherScansModal'))).toBe(true)
    expect(spans.some(s => s.includes('<AgentDrawer'))).toBe(true)
  })

  test("the page's own GitHub token check is skipped while the owner's catalog answers it", () => {
    const at = pageSrc.indexOf('fetch(`/api/users/${userId}/settings`)')
    const effect = pageSrc.slice(pageSrc.lastIndexOf('useEffect(', at), pageSrc.indexOf('}, [', at) + 60)
    expect(effect).toContain('readsOwnerCatalog')
    expect(pageSrc).toContain('hasGithubToken={githubTokenSet}')
    expect(pageSrc).toMatch(/const githubTokenSet = ownerCatalog\s*\?\s*ownerCatalog\.catalog\?\.keys\.githubAccessToken === true\s*:\s*hasGithubToken/)
  })

  test('the drawer offers no key editor when the keys are the owner\'s', () => {
    expect(drawerSrc).toContain('openApiKeyModal={apiKeysReadOnly ? undefined : openApiKeyModal}')
  })
})
