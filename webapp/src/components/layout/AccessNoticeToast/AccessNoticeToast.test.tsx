/**
 * What the stale-access poll found reaches the person once, as a toast (step 4.11, SH-11, P4-05):
 * ProjectProvider sits above the toast layer, so this component, under it, shows the notice and
 * dismisses it. No notice, or no ProjectProvider, shows nothing.
 *
 * Run: npx vitest run --no-file-parallelism src/components/layout/AccessNoticeToast/AccessNoticeToast.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, cleanup } from '@testing-library/react'

const h = vi.hoisted(() => ({
  project: null as null | { accessNotice: unknown; dismissAccessNotice: () => void },
  toast: { warning: vi.fn(), info: vi.fn(), success: vi.fn(), error: vi.fn() },
}))
vi.mock('@/providers/ProjectProvider', () => ({ useOptionalProject: () => h.project }))
vi.mock('@/components/ui', () => ({ useToast: () => h.toast }))

import { AccessNoticeToast } from './AccessNoticeToast'

beforeEach(() => vi.clearAllMocks())
afterEach(cleanup)

describe('AccessNoticeToast', () => {
  test('access ended: a warning naming the project, then the notice is dismissed', () => {
    const dismiss = vi.fn()
    h.project = { accessNotice: { kind: 'ended', projectName: 'Shared project' }, dismissAccessNotice: dismiss }
    render(<AccessNoticeToast />)
    expect(h.toast.warning).toHaveBeenCalledWith(
      'Your access to "Shared project" has ended: the share was revoked or expired, or you left it.', 'Access ended')
    expect(dismiss).toHaveBeenCalledTimes(1)
  })

  test('access changed: the level now in force', () => {
    const dismiss = vi.fn()
    h.project = {
      accessNotice: { kind: 'changed', projectName: 'Shared project',
        myAccess: { level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: 'Alice', email: null } } },
      dismissAccessNotice: dismiss,
    }
    render(<AccessNoticeToast />)
    expect(h.toast.info).toHaveBeenCalledWith('Your access to "Shared project" is now Read.', 'Access changed')
    expect(dismiss).toHaveBeenCalled()
  })

  test('no notice, or no ProjectProvider: nothing shown', () => {
    h.project = { accessNotice: null, dismissAccessNotice: vi.fn() }
    render(<AccessNoticeToast />)
    cleanup()
    h.project = null
    render(<AccessNoticeToast />)
    expect(h.toast.warning).not.toHaveBeenCalled()
    expect(h.toast.info).not.toHaveBeenCalled()
  })
})
