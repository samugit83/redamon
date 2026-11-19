/**
 * The counter badge's librarian warning (Q10 "Moments without a model", T7.5): the tooltip says
 * "Librarian model not set" to the owner and "The owner hasn't chosen a librarian model" to anyone
 * else; nothing when a model is set or the owner uses Search only.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/hooks/usePluginContributions', () => ({ usePluginContributions: () => ({ data: [] }) }))
vi.mock('@/components/ui/Tooltip/Tooltip', () => ({
  Tooltip: ({ content, children }: { content: React.ReactNode; children: React.ReactNode }) => <div>{children}<div>{content}</div></div>,
}))

import { PhaseIndicatorBar } from './PhaseIndicatorBar'
import type { ActiveCounts } from '@/lib/tradecraft/activeCounts'

const COUNTS: ActiveCounts = {
  builtIn: { active: 1, total: 14, names: ['XSS'] }, user: { active: 0, names: [] },
  tradecraft: { active: 2, total: 2, names: ['A', 'B'], offInProject: 0, disabledGlobally: 0, ownerOnlyHidden: 0 },
}
let view: Record<string, unknown>
beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => new Response(JSON.stringify(url === '/api/projects/p1/tradecraft' ? view : { servers: [] }), { status: 200 })))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const draw = () => render(<PhaseIndicatorBar
  currentPhase="exploitation" toolPhaseMap={{}} attackPathType="" skillData={null} iterationCount={0} stealthMode={false}
  settingsDropdownRef={{ current: null }} showSettingsDropdown={false} setShowSettingsDropdown={vi.fn()} setSettingsModal={vi.fn()}
  setShowModelModal={vi.fn()} projectId="p1" sessionId="s1" conversationId="c1"
/>)

describe('the badge\'s librarian warning', () => {
  test('badge_warning: the owner and anyone else, each in their words', async () => {
    view = { v2: true, viewerIsOwner: true, resources: [], counts: COUNTS, librarian: { use: 'agent', set: false, model: null } }
    draw()
    expect(await screen.findByTestId('active-counts-librarian')).toHaveTextContent('Librarian model not set')
    cleanup()
    view = { ...view, viewerIsOwner: false }
    draw()
    expect(await screen.findByTestId('active-counts-librarian')).toHaveTextContent("The owner hasn't chosen a librarian model")
  })

  test('no warning with a model, with Search only, or from a view without the field', async () => {
    for (const librarian of [{ use: 'agent', set: true, model: 'm' }, { use: 'search_only', set: false, model: null }, undefined]) {
      view = { v2: true, viewerIsOwner: true, resources: [], counts: COUNTS, ...(librarian ? { librarian } : {}) }
      draw()
      await screen.findByRole('button', { name: /^Active in this project/ })
      expect(screen.queryByTestId('active-counts-librarian')).toBeNull()
      cleanup()
    }
  })
})
