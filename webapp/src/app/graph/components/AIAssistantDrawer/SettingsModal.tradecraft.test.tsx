/**
 * The drawer's Agent Skills window (§3.4, T4.7): named "Agent Skills & Tradecraft" when the project
 * owner has Tradecraft 2.0 on, with the same accordion as the project form; its links open Global
 * Settings in a new tab, so the chat stays open (R-048, R-049).
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'alice' }) }))
vi.mock('@/hooks/useDetectedHostIp', () => ({ useDetectedHostIp: () => null }))

import { SettingsModal } from './SettingsModal'
import type { ProjectFormData } from './hooks/useSettingsModal'

const ROW = {
  id: 'r1', name: 'HackTricks', type: 'mkdocs-wiki', storageMode: 'live', pages: 3, lastRefreshedAt: null,
  enabledGlobally: true, offInProject: false, ownerOnly: false, locked: false,
  details: { url: 'https://wiki.tc-fixture.test/', mapVersion: 3, stale: false, focus: {}, summary: 's', summarySource: 'generated', report: null, ingestedWith: {}, hasLogin: false, lastError: '' },
}

function draw(v2: boolean, modal: 'attack' | 'agent' = 'attack') {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(
    url === '/api/projects/p1/tradecraft' ? { v2, viewerIsOwner: true, resources: v2 ? [ROW] : [], counts: null } : [],
  ), { status: 200 })))
  const updateProjectField = vi.fn()
  const data = { attackSkillConfig: { builtIn: { xss: true }, user: {} }, tradecraftOff: [] } as unknown as ProjectFormData
  render(
    <ToastProvider>
      <AlertProvider>
        <SettingsModal settingsModal={modal} setSettingsModal={vi.fn()} projectFormData={data} updateProjectField={updateProjectField} projectId="p1" />
      </AlertProvider>
    </ToastProvider>,
  )
  return { updateProjectField }
}

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('SettingsModal and Tradecraft', () => {
  test('tradecraft_window: the window title and the accordion when the owner has 2.0 on', async () => {
    const { updateProjectField } = draw(true)
    expect(await screen.findByRole('heading', { name: 'Agent Skills & Tradecraft' })).toBeInTheDocument()
    expect(await screen.findByTestId('tradecraft-accordion')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('switch', { name: 'HackTricks in this project' }))
    expect(updateProjectField).toHaveBeenCalledWith('tradecraftOff', ['r1'])
  })

  test('links_new_tab_in_drawer: Global Settings opens in a new tab', async () => {
    draw(true)
    fireEvent.click(await screen.findByRole('button', { name: 'Details of HackTricks' }))
    const links = within(screen.getByTestId('tradecraft-accordion')).getAllByRole('link')
    expect(links.map(l => l.getAttribute('href'))).toEqual(['/settings?tab=tradecraft', '/settings?tab=tradecraft&edit=r1'])
    for (const l of links) expect(l).toHaveAttribute('target', '_blank')
  })

  test('label_unchanged_when_v2_off: "Agent Skills", and no accordion', async () => {
    draw(false)
    await waitFor(() => expect(vi.mocked(fetch).mock.calls.some(c => c[0] === '/api/projects/p1/tradecraft')).toBe(true))
    expect(screen.getByRole('heading', { name: 'Agent Skills' })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByTestId('tradecraft-accordion')).toBeNull())
  })

  test('the other windows keep their names and read nothing of tradecraft', async () => {
    draw(true, 'agent')
    expect(screen.getByRole('heading', { name: 'Agent Behaviour' })).toBeInTheDocument()
    expect(vi.mocked(fetch).mock.calls.some(c => c[0] === '/api/projects/p1/tradecraft')).toBe(false)
  })
})
