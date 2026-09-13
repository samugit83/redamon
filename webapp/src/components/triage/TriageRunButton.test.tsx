/**
 * The one triage button: its label, in all three places it appears.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/components/triage/TriageRunButton.test.tsx
 *
 * This component exists because triage used to be three buttons with three
 * names and three looks. Two ways that comes back, both pinned here:
 *
 *  - the LABEL was only decided from the preflight response, which is fetched
 *    on CLICK. So a project triaged last week still read "Start Triage" until
 *    you opened the dialog once, and reverted on every reload.
 *  - the COLOUR came from a class each call site passed, so the Priority
 *    Board's button was a plain secondary control and CypherFix's was the
 *    accent one. The component owns it now; no call site may re-skin it.
 */

import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ confirm: vi.fn(), alertError: vi.fn() }),
}))

import { TriageRunButton } from './TriageRunButton'

afterEach(cleanup)

describe('the label says what pressing it will do', () => {
  test('a project that has never been triaged offers to start', () => {
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} />)
    expect(screen.getByRole('button')).toHaveTextContent('Start Triage')
  })

  test('a project that has been triaged offers to re-triage, before any click', () => {
    // THE BUG: this used to need a click first, because the only source of the
    // answer was the preflight fetch inside the click handler.
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} hasPreviousRun />)
    expect(screen.getByRole('button')).toHaveTextContent('Re-triage')
  })

  test('a run in flight outranks both', () => {
    render(<TriageRunButton projectId="p1" onConfirm={vi.fn()} hasPreviousRun running />)
    expect(screen.getByRole('button')).toHaveTextContent('Triage running...')
    expect(screen.getByRole('button')).toBeDisabled()
  })

  test('it is disabled with no project, so it cannot be pressed into a 400', () => {
    render(<TriageRunButton projectId={null} onConfirm={vi.fn()} />)
    expect(screen.getByRole('button')).toBeDisabled()
  })
})

describe('the component owns its appearance', () => {
  test('it always carries its own class, whatever the caller passes', () => {
    const { container } = render(
      <TriageRunButton projectId="p1" onConfirm={vi.fn()} className="layout-only" />)
    const button = container.querySelector('button')!
    // vitest.config maps CSS modules to non-scoped names, so this is the
    // component's own `.button` rule, not a caller's skin.
    expect(button.className).toContain('button')
    expect(button.className).toContain('layout-only')
  })
})
