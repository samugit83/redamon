/**
 * The RedAmon Terminal tab (step 3.12, UI-03): the raw Kali terminal is a shared sandbox, so its
 * tab shows only to whoever holds platform:kali_terminal (its ticket route decides; step 1.14).
 * With the REDAMON_SHARED_TOOLS_COMPAT escape hatch on, an account older than the upgrade may
 * still open it without the permission, so the tab stays and the ticket route answers.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/ViewTabs/ViewTabs.terminal.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

const h = vi.hoisted(() => ({ granted: new Set<string>(), compat: false }))
vi.mock('../GraphCanvas', () => ({ AUTO_2D_THRESHOLD: 5000 }))
vi.mock('@/components/ui', () => ({ Toggle: () => null }))
vi.mock('@/hooks/useCan', () => ({
  useCan: (p: string) => h.granted.has(p),
  useRbacFlags: () => ({ sharedToolsCompat: h.compat, identity: false, permissions: false, sharing: false, sharingWrite: false, governance: false }),
}))

import { ViewTabs } from './ViewTabs'

beforeEach(() => {
  h.granted = new Set()
  h.compat = false
})
afterEach(() => cleanup())

const terminalTab = () => screen.queryByRole('tab', { name: /RedAmon Terminal/ })

function tabs() {
  const onViewChange = vi.fn()
  render(<ViewTabs activeView="graph" onViewChange={onViewChange} />)
  return onViewChange
}

describe('the RedAmon Terminal tab', () => {
  test('hidden without platform:kali_terminal; the other tabs stay', () => {
    tabs()
    expect(terminalTab()).toBeNull()
    expect(screen.getByRole('tab', { name: /Reverse Shell/ })).toBeInTheDocument()
  })

  test('shown with the permission, and it opens the terminal view', () => {
    h.granted = new Set(['platform:kali_terminal'])
    const onViewChange = tabs()
    fireEvent.click(terminalTab()!)
    expect(onViewChange).toHaveBeenCalledWith('terminal')
  })

  test('shown while the shared-tools escape hatch is on: the ticket route decides', () => {
    h.compat = true
    tabs()
    expect(terminalTab()).not.toBeNull()
  })
})
