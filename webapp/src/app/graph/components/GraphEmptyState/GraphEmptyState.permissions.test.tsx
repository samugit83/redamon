/**
 * The empty graph's Start / Resume Recon button is a scan start too (step 3.16b, E2E-P3-01, UI-12):
 * without `recon:scan` (what the start and resume routes ask) it is disabled and the card says why
 * with the ForbiddenNotice. With the permissions switch off the card is as before (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/GraphEmptyState/GraphEmptyState.permissions.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import type { EmptyGraphState } from '../../utils/emptyGraph'
import { GraphEmptyState } from './GraphEmptyState'

const props = { onStartRecon: vi.fn(), onResumeRecon: vi.fn() }

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function card(value: AuthContextValue | null, state: EmptyGraphState) {
  return render(
    <AuthContext.Provider value={value}>
      <GraphEmptyState state={state} {...props} />
    </AuthContext.Provider>,
  )
}

describe('GraphEmptyState and recon:scan', () => {
  test.each([
    ['start', 'Start Recon Pipeline'],
    ['paused', 'Resume Recon'],
  ] as const)('switch on, without recon:scan: %s is disabled and the card shows the notice', (state, label) => {
    card(fakeAuth(FLAGS_ON, ['recon:read', 'graph:read']), state)
    const button = screen.getByRole('button', { name: label }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(button.title).toBe(forbiddenNoticeText('recon:scan'))
    fireEvent.click(button)
    expect(props.onStartRecon).not.toHaveBeenCalled()
    expect(props.onResumeRecon).not.toHaveBeenCalled()
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('You do not have the permission this needs.')
    expect(notice).toHaveTextContent('recon:scan')
    expect(notice).toHaveTextContent('Ask an administrator to grant it to you.')
  })

  test('switch on, with recon:scan: the card is as before, no notice', () => {
    card(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan']), 'start')
    fireEvent.click(screen.getByRole('button', { name: 'Start Recon Pipeline' }))
    expect(props.onStartRecon).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('switch off, an empty set: the card is as before (DV-30)', () => {
    card(fakeAuth(FLAGS_OFF, []), 'paused')
    fireEvent.click(screen.getByRole('button', { name: 'Resume Recon' }))
    expect(props.onResumeRecon).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('a running scan or a saved version shows no notice: there is nothing to start', () => {
    card(fakeAuth(FLAGS_ON, []), 'running')
    expect(screen.queryByRole('alert')).toBeNull()
    cleanup()
    card(fakeAuth(FLAGS_ON, []), 'readOnly')
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
