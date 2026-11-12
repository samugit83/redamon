/**
 * The overwrite mode of a recon start asks `recon:overwrite` on top of `recon:scan` (the start route's
 * requireAlso, route manifest). Someone holding only `recon:scan` (step 3.16b, UI-12) can still start
 * a new version, while the Overwrite option is disabled with the permission notice and never reaches
 * the caller. With the permissions switch off the choice is as before (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/ReconConfirmModal/ReconConfirmModal.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import { ReconConfirmModal } from './ReconConfirmModal'

const onConfirm = vi.fn()
const withData = { totalNodes: 120, nodesByType: { IP: 40, Port: 80 } }

beforeEach(() => vi.clearAllMocks())
afterEach(cleanup)

function dialog(value: AuthContextValue | null) {
  return render(
    <AuthContext.Provider value={value}>
      <ReconConfirmModal isOpen onClose={() => {}} onConfirm={onConfirm} projectName="Acme" targetDomain="acme.tld"
        isLoading={false} stats={withData} />
    </AuthContext.Provider>,
  )
}

const overwrite = () => (screen.getAllByRole('radio') as HTMLInputElement[]).find(r => r.value === 'overwrite')!

describe('ReconConfirmModal and recon:overwrite', () => {
  test('switch on, recon:scan without recon:overwrite: Overwrite disabled with the notice, the start stays a new version', () => {
    dialog(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan']))
    expect(overwrite().disabled).toBe(true)
    expect(overwrite().closest('label')?.title).toBe(forbiddenNoticeText('recon:overwrite'))
    expect(screen.getByRole('alert')).toHaveTextContent('recon:overwrite')
    // jsdom delivers a synthetic click (and React its change) even to a disabled radio, which a
    // browser never does; the refused mode must not become the mode either way.
    fireEvent.click(overwrite())
    expect(screen.queryByText('Discard & Start')).toBeNull()
    fireEvent.click(screen.getByText('Save Version & Start'))
    expect(onConfirm).toHaveBeenCalledWith('new')
  })

  test('switch on, with recon:overwrite: the choice is as before', () => {
    dialog(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan', 'recon:overwrite']))
    expect(overwrite().disabled).toBe(false)
    expect(screen.queryByRole('alert')).toBeNull()
    fireEvent.click(overwrite())
    fireEvent.click(screen.getByText('Discard & Start'))
    expect(onConfirm).toHaveBeenCalledWith('overwrite')
  })

  test('switch off, an empty set: the choice is as before (DV-30)', () => {
    dialog(fakeAuth(FLAGS_OFF, []))
    expect(overwrite().disabled).toBe(false)
    expect(overwrite().closest('label')?.title).toBe('')
    fireEvent.click(overwrite())
    fireEvent.click(screen.getByText('Discard & Start'))
    expect(onConfirm).toHaveBeenCalledWith('overwrite')
  })
})
