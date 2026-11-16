/**
 * The project's Tradecraft Resources accordion (§3.4, T4.7): the third accordion of the Agent Skills
 * tab, read-only except the per-project switch, details for the owner, locked rows, links to Global
 * Settings (a new tab from the chat drawer).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within, waitFor } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'owner-1' }) }))
vi.mock('@/components/ui/AlertModal', () => ({ useAlertModal: () => ({ alert: vi.fn(), alertError: vi.fn(), confirm: vi.fn() }) }))

import { ToastProvider } from '@/components/ui/Toast/Toast'
import { TradecraftResourcesAccordion, editInGlobalHref } from './TradecraftResourcesAccordion'
import { AttackSkillsSection } from './AttackSkillsSection'
import type { ProjectTradecraftView } from '@/lib/tradecraft/projectView'

const ROWS = [
  {
    id: 'r1', name: 'HackTricks', type: 'mkdocs-wiki', storageMode: 'stored', pages: 1240, lastRefreshedAt: '2026-11-13T10:00:00.000Z',
    enabledGlobally: true, offInProject: false, ownerOnly: false, locked: false,
    details: {
      url: 'https://wiki.tc-fixture.test/', mapVersion: 3, stale: true, focus: {}, summary: 'Offensive wiki.', summarySource: 'generated',
      report: { visited: 40, kept: 31, skipped: { excluded: 0, outOfScope: 0, tooLittleText: 0, robots: 0, outsideFocus: 0 }, stopReason: 'frontier_empty', llmCalls: 9, durationSec: 61, stored: { pages: 31, bytes: 1, notStoredQuota: 0, notStoredSize: 0 }, focus: {}, readiness: {}, errors: [] },
      ingestedWith: {
        'content.removeSelectors': ['nav', '.ads'], 'crawl.maxPages': 150, 'crawl.respectRobots': false, 'crawl.includePaths': [],
        'fetching.userAgent': 'RedAmon-Tradecraft/1.0', 'legacy.retiredKey': 3,
      },
      hasLogin: false, lastError: '',
    },
  },
  {
    id: 'r2', name: 'PayloadsAllTheThings', type: 'github-repo', storageMode: 'stored', pages: 410, lastRefreshedAt: null,
    enabledGlobally: true, offInProject: true, ownerOnly: false, locked: false,
    details: { url: 'https://github.com/org/patt', mapVersion: 2, stale: false, focus: {}, summary: '', summarySource: 'generated', report: null, ingestedWith: {}, hasLogin: false, lastError: '' },
  },
  { id: 'r3', name: 'Sigma rules', type: null, storageMode: null, pages: null, lastRefreshedAt: null, enabledGlobally: false, offInProject: false, ownerOnly: false, locked: true },
]
const VIEW = (over: Partial<ProjectTradecraftView> = {}): ProjectTradecraftView => ({
  v2: true, viewerIsOwner: true, resources: ROWS as ProjectTradecraftView['resources'], counts: null, ...over,
})

let view: ProjectTradecraftView
const onChange = vi.fn()
beforeEach(() => {
  vi.clearAllMocks()
  view = VIEW()
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(url === '/api/projects/p1/tradecraft' ? view : []), { status: 200 })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const draw = (offIds: string[] = ['r2'], inDrawer = false) =>
  render(<TradecraftResourcesAccordion projectId="p1" offIds={offIds} onChange={onChange} inDrawer={inDrawer} />)
const row = (id: string) => within(document.querySelector(`[data-resource="${id}"]`) as HTMLElement)

describe('TradecraftResourcesAccordion', () => {
  test('renders_in_tab: the third accordion, below Built-in and User Agent Skills', async () => {
    render(<ToastProvider><AttackSkillsSection data={{ hydraEnabled: false, tradecraftOff: [] } as never} updateField={vi.fn()} projectId="p1" /></ToastProvider>)
    await screen.findByTestId('tradecraft-accordion')
    const titles = screen.getAllByRole('heading', { level: 2 }).map(h => h.textContent ?? '')
    expect(titles.findIndex(t => t.includes('Tradecraft Resources'))).toBeGreaterThan(titles.findIndex(t => t.includes('User Agent Skills')))
    expect(titles.findIndex(t => t.includes('User Agent Skills'))).toBeGreaterThan(titles.findIndex(t => t.includes('Built-in Agent Skills')))
  })

  test('a project not saved yet has no accordion: every resource starts on', async () => {
    render(<AttackSkillsSection data={{ hydraEnabled: false } as never} updateField={vi.fn()} projectId={null} />)
    await screen.findByRole('switch', { name: 'SQL Injection' })
    expect(screen.queryByTestId('tradecraft-accordion')).toBeNull()
  })

  test('the switch writes tradecraftOff through the form\'s updateField', async () => {
    const updateField = vi.fn()
    render(<ToastProvider><AttackSkillsSection data={{ hydraEnabled: false, tradecraftOff: [] } as never} updateField={updateField} projectId="p1" /></ToastProvider>)
    fireEvent.click(await screen.findByRole('switch', { name: 'HackTricks in this project' }))
    expect(updateField).toHaveBeenCalledWith('tradecraftOff', ['r1'])
  })

  test('header: how many are active here, the link to Global Settings, Turn all on and off (locked rows kept)', async () => {
    draw(['r2', 'r3'])
    expect(await screen.findByTestId('tradecraft-active-count')).toHaveTextContent('1 of 3 active in this project')
    expect(screen.getByRole('link', { name: 'Global Settings > Tradecraft' })).toHaveAttribute('href', '/settings?tab=tradecraft')
    fireEvent.click(screen.getByRole('button', { name: 'Turn all on' }))
    expect(onChange).toHaveBeenLastCalledWith(['r3'])
    fireEvent.click(screen.getByRole('button', { name: 'Turn all off' }))
    expect(onChange).toHaveBeenLastCalledWith(['r1', 'r2', 'r3'])
  })

  test('rows: the switch, name, type, storage mode, pages, last refreshed', async () => {
    draw()
    await screen.findByText('HackTricks')
    const r1 = row('r1')
    expect(r1.getByRole('switch', { name: 'HackTricks in this project' })).toHaveAttribute('aria-checked', 'true')
    for (const text of ['mkdocs-wiki', 'Stored', '1,240 pages']) expect(r1.getByText(text)).toBeInTheDocument()
    expect(row('r2').getByRole('switch', { name: 'PayloadsAllTheThings in this project' })).toHaveAttribute('aria-checked', 'false')
    fireEvent.click(row('r2').getByRole('switch'))
    expect(onChange).toHaveBeenLastCalledWith([])
  })

  test('expanded_read_only: URL, source, stale, focus, summary, report, settings, login; no input', async () => {
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    const d = within(screen.getByTestId('details-r1'))
    for (const text of ['https://wiki.tc-fixture.test/', 'ingested by 2.0', 'Ingested with older settings', 'Everything', 'Offensive wiki.', 'No login']) {
      expect(d.getByText(text)).toBeInTheDocument()
    }
    expect(d.getByText(/40 visited, 31 kept, 9 LLM calls, 61 s, stopped: frontier_empty/)).toBeInTheDocument()
    // The values themselves, in the spec's order, by their labels; unknown keys last, by name (R-044).
    expect(d.getByText('6 settings, 2 changed from the defaults')).toBeInTheDocument()
    expect([...screen.getByTestId('ingested-with-r1').querySelectorAll('li')].map(li => li.textContent)).toEqual([
      'User-Agent (fetching.userAgent): RedAmon-Tradecraft/1.0',
      'Max pages visited (crawl.maxPages): 150 pages (changed)',
      'Include paths (crawl.includePaths): none',
      'Respect robots.txt (crawl.respectRobots): off',
      'Remove elements (content.removeSelectors): nav, .ads (changed)',
      'legacy.retiredKey: 3',
    ])
    expect(screen.getByTestId('details-r1').querySelectorAll('input, textarea, select')).toHaveLength(0)
  })

  test('edit_link: "Edit in Global Settings" opens that resource\'s Edit form', async () => {
    draw()
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    expect(screen.getByRole('link', { name: /Edit in Global Settings/ })).toHaveAttribute('href', '/settings?tab=tradecraft&edit=r1')
    expect(editInGlobalHref('a b')).toBe('/settings?tab=tradecraft&edit=a%20b')
  })

  test('no_resource_controls: no Refresh, Delete, Edit or Enabled control; only switches, Turn all, details and links (R-047)', async () => {
    draw()
    await screen.findByText('HackTricks')
    const acc = within(screen.getByTestId('tradecraft-accordion'))
    const buttons = acc.getAllByRole('button').map(b => b.getAttribute('aria-label') ?? b.textContent)
    expect(buttons).toEqual(['Turn all on', 'Turn all off', 'Details of HackTricks', 'Details of PayloadsAllTheThings'])
    expect(acc.getAllByRole('switch')).toHaveLength(3)
  })

  test('links_new_tab_in_drawer: in the chat drawer every link opens a new tab', async () => {
    draw(['r2'], true)
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    for (const link of screen.getAllByRole('link')) {
      expect(link).toHaveAttribute('target', '_blank')
      expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    }
    cleanup()
    draw()
    expect((await screen.findAllByRole('link'))[0]).not.toHaveAttribute('target')
  })

  test('locked_disabled_globally: the switch is locked, with a link to Global Settings (R-061)', async () => {
    draw()
    await screen.findByText('Sigma rules')
    const r3 = row('r3')
    expect(r3.getByRole('switch', { name: 'Sigma rules in this project' })).toBeDisabled()
    expect(r3.getByText(/Disabled in/)).toBeInTheDocument()
    expect(r3.getByRole('link', { name: 'Global Settings' })).toHaveAttribute('href', '/settings?tab=tradecraft')
    fireEvent.click(r3.getByRole('switch'))
    expect(onChange).not.toHaveBeenCalled()
  })

  test('owner_only_locked: a collaborator sees names and on/off, a login resource Owner only and locked (R-066)', async () => {
    view = VIEW({
      viewerIsOwner: false,
      resources: [
        { id: 'r1', name: 'HackTricks', type: null, storageMode: null, pages: null, lastRefreshedAt: null, enabledGlobally: true, offInProject: false, ownerOnly: false, locked: false },
        { id: 'r4', name: 'Company wiki', type: null, storageMode: null, pages: null, lastRefreshedAt: null, enabledGlobally: true, offInProject: false, ownerOnly: true, locked: true },
      ],
    })
    draw([])
    await screen.findByText('Company wiki')
    expect(row('r4').getByText('Owner only')).toBeInTheDocument()
    expect(row('r4').getByRole('switch')).toBeDisabled()
    expect(row('r4').getByRole('switch')).toHaveAttribute('aria-checked', 'false')
    expect(screen.queryByRole('button', { name: /Details of/ })).toBeNull()
    expect(screen.getByTestId('tradecraft-active-count')).toHaveTextContent('1 of 2 active in this project')
  })

  test('label_unchanged_when_v2_off: with the owner\'s switch off there is no accordion', async () => {
    view = VIEW({ v2: false, resources: [] })
    const { container } = draw()
    await waitFor(() => expect(vi.mocked(fetch)).toHaveBeenCalled())
    await waitFor(() => expect(container.querySelector('[data-testid="tradecraft-accordion"]')).toBeNull())
  })
})
