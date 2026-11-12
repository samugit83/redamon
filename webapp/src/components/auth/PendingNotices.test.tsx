/**
 * The notices an account finds at sign-in (step 2.10, ID-19; feature document §7.1 "your password
 * was reset by Laura on 12 Nov"): the sign-in answer carries the pending ones, shown here once,
 * each in the app's own dialog (never window.alert), one after the other; the caller goes on when
 * the person has read them all. Anything the answer carries that is not a notice is ignored.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { useEffect, useRef } from 'react'
import { AlertProvider } from '@/components/ui'
import { noticeMessage, readNoticeViews, showPendingNotices, usePendingNotices } from './PendingNotices'

const notice = (over: Record<string, unknown> = {}) => ({
  id: 'n1', type: 'credentials_reset', at: '2026-11-12T10:00:00.000Z',
  by: { name: 'Laura', email: 'laura@e2e.local' }, reason: 'Locked out', mode: 'link', ...over,
})

/** A page that signs the person in: it shows the notices once, then goes on. */
function Harness({ notices, onDone }: { notices: unknown; onDone: () => void }) {
  const show = usePendingNotices()
  const started = useRef(false)
  useEffect(() => {
    if (started.current) return
    started.current = true
    void show(notices).then(onDone)
  }, [show, notices, onDone])
  return null
}

afterEach(() => cleanup())

describe('what a notice says', () => {
  test('who reset it, when, why, and how', () => {
    const text = noticeMessage(readNoticeViews([notice()])[0])
    expect(text).toContain('Laura (laura@e2e.local)')
    expect(text).toContain(new Date('2026-11-12T10:00:00.000Z').toLocaleString())
    expect(text).toContain('Reason: Locked out')
    expect(text).toMatch(/reset link/)
    expect(text).toMatch(/tell your administrator/i)
  })

  test('a temporary password says so; no reason says none was given', () => {
    const text = noticeMessage(readNoticeViews([notice({ mode: 'temporary', reason: null })])[0])
    expect(text).toMatch(/temporary password/)
    expect(text).toContain('No reason was given')
  })

  test('only well-formed notices are read', () => {
    expect(readNoticeViews(undefined)).toEqual([])
    expect(readNoticeViews('x')).toEqual([])
    expect(readNoticeViews([null, 1, { type: 'other' }, notice({ by: null }), notice()])).toHaveLength(1)
  })
})

describe('shown once, after sign-in, in the app dialog', () => {
  test('notice shown once: each in turn, then the caller goes on', async () => {
    const onDone = vi.fn()
    render(
      <AlertProvider>
        <Harness notices={[notice(), notice({ id: 'n2', reason: 'Second reset', mode: 'temporary' })]} onDone={onDone} />
      </AlertProvider>,
    )
    const first = await screen.findByRole('dialog', { name: 'Your password was reset' })
    expect(first).toHaveTextContent('Reason: Locked out')
    expect(onDone).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(screen.getByRole('dialog')).toHaveTextContent('Reason: Second reset'))
    expect(onDone).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  test('the dialog closes with the keyboard (Escape) too', async () => {
    const onDone = vi.fn()
    render(<AlertProvider><Harness notices={[notice()]} onDone={onDone} /></AlertProvider>)
    const dialog = await screen.findByRole('dialog')
    fireEvent.keyDown(dialog, { key: 'Escape' })
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1))
  })

  test('no notice: no dialog, the caller goes on at once', async () => {
    const onDone = vi.fn()
    render(<AlertProvider><Harness notices={undefined} onDone={onDone} /></AlertProvider>)
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  test('outside the app dialog provider nothing blocks the sign-in', async () => {
    await expect(showPendingNotices(null, [notice()])).resolves.toBeUndefined()
  })
})

describe('the email change notice (step 2.11, ID-30)', () => {
  const changed = (over: Record<string, unknown> = {}) => ({
    id: 'e1', type: 'email_changed', at: '2026-11-12T10:00:00.000Z',
    by: { name: 'Laura', email: 'laura@e2e.local' }, from: 'old@e2e.local', to: 'new@e2e.local', self: false, ...over,
  })

  test('who changed the sign-in address, from what to what, and what to do if unexpected', () => {
    const [view] = readNoticeViews([changed()])
    const text = noticeMessage(view)
    expect(text).toContain('Laura (laura@e2e.local)')
    expect(text).toContain('old@e2e.local')
    expect(text).toContain('new@e2e.local')
    expect(text).toMatch(/tell your administrator/i)
  })

  test('a change the account made itself says so', () => {
    const text = noticeMessage(readNoticeViews([changed({ self: true })])[0])
    expect(text).toMatch(/^You changed your sign-in email/)
    expect(text).not.toContain('Laura')
  })

  test('only well-formed ones are read', () => {
    expect(readNoticeViews([changed({ from: 1 }), changed({ self: 'no' }), changed()])).toHaveLength(1)
  })

  test('shown in the app dialog under its own title', async () => {
    const onDone = vi.fn()
    render(<AlertProvider><Harness notices={[changed()]} onDone={onDone} /></AlertProvider>)
    const dialog = await screen.findByRole('dialog', { name: 'Your sign-in email was changed' })
    expect(dialog).toHaveTextContent('new@e2e.local')
    fireEvent.click(screen.getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1))
  })
})

describe('the act-as notice (step 3.14, IM-10)', () => {
  const actedAs = (over: Record<string, unknown> = {}) => ({
    id: 'a1', type: 'acted_as', at: '2026-11-12T10:00:00.000Z',
    by: { name: 'Laura', email: 'laura@e2e.local' }, reason: 'ticket #42', durationMinutes: 35, ...over,
  })

  test('target notice: who acted as the person, when, for how long, why, and what to do if unexpected', () => {
    const text = noticeMessage(readNoticeViews([actedAs()])[0])
    expect(text).toContain('Laura (laura@e2e.local) acted as you')
    expect(text).toContain('35 min')
    expect(text).toContain('Reason: ticket #42.')
    expect(text).toMatch(/tell your administrator/i)
    expect(noticeMessage(readNoticeViews([actedAs({ reason: null })])[0])).toContain('No reason was given.')
  })

  test('only well-formed ones are read', () => {
    expect(readNoticeViews([actedAs({ durationMinutes: 0 }), actedAs({ reason: 3 }), actedAs()])).toHaveLength(1)
  })

  test('shown in the app dialog under its own title', async () => {
    const onDone = vi.fn()
    render(<AlertProvider><Harness notices={[actedAs()]} onDone={onDone} /></AlertProvider>)
    const dialog = await screen.findByRole('dialog', { name: 'An administrator acted as you' })
    expect(dialog).toHaveTextContent('ticket #42')
    fireEvent.click(screen.getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1))
  })
})
