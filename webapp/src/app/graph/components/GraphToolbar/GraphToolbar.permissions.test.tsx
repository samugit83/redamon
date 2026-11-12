/**
 * E2E-P3-01's UI half (step 3.16b, PE-29, UI-12): someone whose set lacks the permission a scan's
 * start route asks (`recon:scan`, `scan:gvm`, route manifest) sees that scan's toolbar button
 * disabled, with the permission notice as its title, instead of a button that answers 403. The AI
 * Agent button stays: the drawer it opens shows the refusal. With the permissions switch off the
 * toolbar is as before whatever the set holds (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/GraphToolbar/GraphToolbar.permissions.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import type { ReconStatus, GvmStatus } from '@/lib/recon-types'
import { GraphToolbar } from './GraphToolbar'

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

const handlers = {
  onStartRecon: vi.fn(), onResumeRecon: vi.fn(), onStartGvm: vi.fn(), onResumeGvm: vi.fn(), onToggleAI: vi.fn(),
}

function toolbar(value: AuthContextValue | null, status: { recon?: ReconStatus; gvm?: GvmStatus } = {}) {
  return render(
    <AuthContext.Provider value={value}>
      <GraphToolbar
        projectId="p1" is3D={false} showLabels onToggle3D={() => {}} onToggleLabels={() => {}}
        hasReconData gvmAvailable reconStatus={status.recon ?? 'idle'} gvmStatus={status.gvm ?? 'idle'}
        {...handlers}
      />
    </AuthContext.Provider>,
  )
}

const button = (label: string) =>
  screen.getAllByRole('button').find(b => b.textContent?.includes(label)) as HTMLButtonElement

describe('GraphToolbar scan starts and the viewer permissions', () => {
  test('switch on, Read-only analyst: Start Recon and GVM disabled with the notice naming each permission', () => {
    toolbar(fakeAuth(FLAGS_ON, ['recon:read', 'graph:read', 'agent:assistants']))
    const recon = button('Start Recon Pipeline')
    const gvm = button('GVM Scan')
    expect(recon.disabled).toBe(true)
    expect(recon.title).toBe(forbiddenNoticeText('recon:scan'))
    expect(gvm.disabled).toBe(true)
    expect(gvm.title).toBe(forbiddenNoticeText('scan:gvm'))
    fireEvent.click(recon)
    fireEvent.click(gvm)
    expect(handlers.onStartRecon).not.toHaveBeenCalled()
    expect(handlers.onStartGvm).not.toHaveBeenCalled()
  })

  test('switch on: a paused scan cannot be resumed without the permission either (resume asks it)', () => {
    toolbar(fakeAuth(FLAGS_ON, ['recon:read']), { recon: 'paused', gvm: 'paused' })
    const resumes = screen.getAllByRole('button').filter(b => b.textContent?.includes('Resume')) as HTMLButtonElement[]
    expect(resumes).toHaveLength(2)
    for (const b of resumes) expect(b.disabled).toBe(true)
    expect(resumes.map(b => b.title)).toEqual([forbiddenNoticeText('recon:scan'), forbiddenNoticeText('scan:gvm')])
  })

  test('switch on: each button follows its own permission', () => {
    toolbar(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan']))
    expect(button('Start Recon Pipeline').disabled).toBe(false)
    expect(button('Start Recon Pipeline').title).toBe('Start Reconnaissance')
    expect(button('GVM Scan').disabled).toBe(true)
    fireEvent.click(button('Start Recon Pipeline'))
    expect(handlers.onStartRecon).toHaveBeenCalledTimes(1)
  })

  test('switch on, with both permissions: the toolbar is as before', () => {
    toolbar(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan', 'scan:gvm']))
    expect(button('Start Recon Pipeline').disabled).toBe(false)
    expect(button('GVM Scan').disabled).toBe(false)
    expect(button('GVM Scan').title).toBe('Start GVM Vulnerability Scan')
  })

  test('switch off: as before whatever the set holds (DV-30); no provider: as before', () => {
    toolbar(fakeAuth(FLAGS_OFF, []))
    expect(button('Start Recon Pipeline').disabled).toBe(false)
    expect(button('GVM Scan').disabled).toBe(false)
    cleanup()
    toolbar(null)
    expect(button('Start Recon Pipeline').title).toBe('Start Reconnaissance')
    expect(button('GVM Scan').disabled).toBe(false)
  })

  test('the AI Agent button stays: the drawer it opens shows the refusal', () => {
    toolbar(fakeAuth(FLAGS_ON, ['recon:read']))
    const ai = screen.getByRole('button', { name: 'Toggle AI Agent' }) as HTMLButtonElement
    expect(ai.disabled).toBe(false)
    fireEvent.click(ai)
    expect(handlers.onToggleAI).toHaveBeenCalledTimes(1)
  })
})
