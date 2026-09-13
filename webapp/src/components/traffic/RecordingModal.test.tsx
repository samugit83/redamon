/**
 * RecordingModal — closing the modal must END the recording.
 *
 * Row 6 of the test strategy. Without this, closing (Esc / backdrop / X) reset
 * only client state: the session stayed active server-side for its 30-minute
 * TTL, the proxy kept tagging the operator's browsing, and every other project
 * was refused the single global recording slot — with nothing in the UI saying so.
 *
 * @vitest-environment jsdom
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'

const alertError = vi.fn()

// Stand-ins for the shared UI kit: this test exercises the modal's lifecycle,
// not the design system. Modal exposes its onClose as a button so the test can
// trigger the same path Esc/backdrop use.
vi.mock('@/components/ui', () => ({
  useAlertModal: () => ({ alertError }),
  WikiInfoButton: () => null,
  Modal: ({ isOpen, onClose, children }: { isOpen: boolean; onClose: () => void; children: React.ReactNode }) =>
    isOpen ? (
      <div>
        <button onClick={onClose}>close-modal</button>
        {children}
      </div>
    ) : null,
}))

import { RecordingModal } from './RecordingModal'

function mockRecordingApi() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((async (url: string, init?: RequestInit) => {
    const u = String(url)
    if (u.endsWith('/recording/start')) {
      return {
        ok: true,
        json: async () => ({
          session: {
            id: 'rec1', state: 'active', scopeHosts: ['t.test'],
            expiresAt: '2099-01-01T00:00:00.000Z', observedCount: 0, lastError: null,
          },
        }),
      } as Response
    }
    if (u.endsWith('/recording/status')) {
      return { ok: true, json: async () => ({ session: null, summary: null, otherProjectRecording: false }) } as Response
    }
    if (u.endsWith('/recording/stop')) {
      return { ok: true, json: async () => ({ session: null, summary: null }) } as Response
    }
    return { ok: true, json: async () => ({}) } as Response
  }) as typeof fetch)
}

beforeEach(() => { vi.clearAllMocks() })
afterEach(() => { cleanup(); vi.restoreAllMocks() })

test('closing while recording POSTs /recording/stop', async () => {
  const fetchMock = mockRecordingApi()
  const onClose = vi.fn()
  render(<RecordingModal isOpen onClose={onClose} projectId="p1" />)

  fireEvent.click(screen.getByText('Start recording'))
  await waitFor(() => expect(screen.getByText(/Recording/)).toBeTruthy())

  fireEvent.click(screen.getByText('close-modal'))

  await waitFor(() => {
    const stopCalls = fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/recording/stop'))
    expect(stopCalls.length).toBe(1)
    expect((stopCalls[0][1] as RequestInit).method).toBe('POST')
  })
  expect(onClose).toHaveBeenCalled()
})

test('closing when idle does NOT call stop', async () => {
  const fetchMock = mockRecordingApi()
  const onClose = vi.fn()
  render(<RecordingModal isOpen onClose={onClose} projectId="p1" />)

  fireEvent.click(screen.getByText('close-modal'))

  expect(fetchMock.mock.calls.filter(c => String(c[0]).endsWith('/recording/stop')).length).toBe(0)
  expect(onClose).toHaveBeenCalled()
})
