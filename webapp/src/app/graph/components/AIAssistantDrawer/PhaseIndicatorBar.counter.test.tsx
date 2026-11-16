/**
 * The counter badge in the chat's top bar (§3.4, T4.8, R-052 - R-058): three numbers after the
 * wrench, a dimmed 0, the tooltip of §3.4, a click opening the Agent Skills & Tradecraft window,
 * numbers read again when a window saves the switches; with the owner's 2.0 off the bar is as it was.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, act, within } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/hooks/usePluginContributions', () => ({ usePluginContributions: () => ({ data: [] }) }))
vi.mock('@/components/ui/Tooltip/Tooltip', () => ({
  Tooltip: ({ content, children }: { content: React.ReactNode; children: React.ReactNode }) => (
    <div>
      {children}
      <div data-testid="tooltip-content">{content}</div>
    </div>
  ),
}))

import { PhaseIndicatorBar } from './PhaseIndicatorBar'
import { postTradecraftCountsChanged } from '@/lib/tradecraft/channels'
import type { ActiveCounts } from '@/lib/tradecraft/activeCounts'

type Props = React.ComponentProps<typeof PhaseIndicatorBar>

const COUNTS: ActiveCounts = {
  builtIn: { active: 9, total: 14, names: ['SQL injection', 'XSS', 'SSRF', 'RCE', 'XXE'] },
  user: { active: 0, names: [] },
  tradecraft: { active: 12, total: 15, names: ['HackTricks', 'PayloadsAllTheThings'], offInProject: 2, disabledGlobally: 1, ownerOnlyHidden: 1 },
}
let answer: { v2: boolean; counts: ActiveCounts | null }
let reads = 0

beforeEach(() => {
  answer = { v2: true, counts: COUNTS }
  reads = 0
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url === '/api/projects/p1/tradecraft') {
      reads += 1
      return new Response(JSON.stringify({ v2: answer.v2, viewerIsOwner: true, resources: [], counts: answer.counts }), { status: 200 })
    }
    return new Response(JSON.stringify({ servers: [] }), { status: 200 })
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function draw(over: Partial<Props> = {}) {
  const setSettingsModal = vi.fn()
  const props: Props = {
    currentPhase: 'exploitation', toolPhaseMap: {}, attackPathType: '', skillData: null, iterationCount: 0, stealthMode: false,
    settingsDropdownRef: { current: null }, showSettingsDropdown: false, setShowSettingsDropdown: vi.fn(), setSettingsModal,
    setShowModelModal: vi.fn(), projectId: 'p1', sessionId: 's1', conversationId: 'c1', ...over,
  }
  const view = render(<PhaseIndicatorBar {...props} />)
  return { setSettingsModal, view, props }
}
const badge = () => screen.findByRole('button', { name: /^Active in this project/ })
const tooltip = () => screen.getByTestId('active-counts-tooltip')

describe('the counter badge', () => {
  test('three_numbers: built-in skills, user skills, tradecraft resources, after the wrench', async () => {
    draw()
    const b = await badge()
    expect(b).toHaveAccessibleName('Active in this project: 9 built-in skills, 0 user skills, 12 tradecraft resources')
    expect(['builtIn', 'user', 'tradecraft'].map(k => b.querySelector(`[data-count="${k}"]`)!.textContent)).toEqual(['9', '0', '12'])
  })

  test('dimmed_zero: a group with nothing active shows a dimmed 0', async () => {
    draw()
    const b = await badge()
    expect((b.querySelector('[data-count="user"]') as HTMLElement).style.opacity).toBe('0.4')
    expect((b.querySelector('[data-count="builtIn"]') as HTMLElement).style.opacity).toBe('')
  })

  test('tooltip: the numbers, the names, what is not active and why, the owner-only line', async () => {
    draw()
    await badge()
    const t = within(tooltip())
    for (const text of [
      'Active in this project', '9 of 14 built-in agent skills', 'SQL injection, XSS, SSRF, RCE, ...', '0 user agent skills',
      '12 of 15 tradecraft resources', 'HackTricks, PayloadsAllTheThings', '2 turned off in this project · 1 disabled in Global Settings',
      '1 owner-only resource is not used in your chats', 'Click to change them',
    ]) expect(t.getByText(text)).toBeInTheDocument()
  })

  test('click_opens_window: the Agent Skills & Tradecraft window', async () => {
    const { setSettingsModal } = draw()
    fireEvent.click(await badge())
    expect(setSettingsModal).toHaveBeenCalledWith('attack')
  })

  test("updates_on_channel_message: a save in another window reads the numbers again; another project's does not", async () => {
    draw()
    await badge()
    expect(reads).toBe(1)
    answer = { v2: true, counts: { ...COUNTS, tradecraft: { ...COUNTS.tradecraft, active: 11 } } }
    act(() => postTradecraftCountsChanged({ projectId: 'p2' }))
    act(() => postTradecraftCountsChanged({ projectId: 'p1' }))
    await waitFor(() => expect(screen.getByRole('button', { name: /^Active in this project/ })).toHaveAccessibleName(/11 tradecraft resources/))
    expect(reads).toBe(2)
  })

  test('the drawer reading the project again (new skill data) reads the numbers again', async () => {
    const { view, props } = draw()
    await badge()
    view.rerender(<PhaseIndicatorBar {...props} skillData={{ builtIn: [], user: [], config: { builtIn: {}, user: {} } }} />)
    await waitFor(() => expect(reads).toBe(2))
  })

  test('the menu item reads "Agent Skills & Tradecraft"', async () => {
    draw({ showSettingsDropdown: true })
    await badge()
    expect(screen.getByRole('button', { name: 'Agent Skills & Tradecraft' })).toBeInTheDocument()
  })

  test('unchanged_when_v2_off: no badge, and the menu item keeps its name', async () => {
    answer = { v2: false, counts: null }
    draw({ showSettingsDropdown: true })
    await waitFor(() => expect(reads).toBe(1))
    expect(screen.queryByRole('button', { name: /^Active in this project/ })).toBeNull()
    expect(screen.getByRole('button', { name: 'Agent Skills' })).toBeInTheDocument()
  })

  test('active_skill_badge_unchanged: the active attack skill still shows as before (R-058)', async () => {
    draw({ attackPathType: 'sql_injection', skillData: { builtIn: [{ id: 'sql_injection', name: 'SQL Injection' }], user: [], config: { builtIn: { sql_injection: true }, user: {} } } })
    await badge()
    const skills = screen.getAllByTestId('tooltip-content').find(el => el.textContent?.includes('Agent Skills'))!
    expect(within(skills).getByText('SQL Injection')).toBeInTheDocument()
  })
})
