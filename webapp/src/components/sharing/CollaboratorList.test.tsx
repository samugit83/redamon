/**
 * The list of a project's shares in the share dialog (steps 4.12, 5.14; UI-07, ID-31, OQ-34): each
 * person as an IdentityLabel with their level, toggles, end date, who granted it and the note; change
 * (only what changed is sent; with write sharing in force the toggles too, within what the person may
 * grant) and revoke, whose confirmation goes through useAlertModal (the real AlertProvider).
 *
 * Run: npx vitest run --no-file-parallelism src/components/sharing/CollaboratorList.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { CollaboratorList } from './CollaboratorList'
import { WRITE_PRESETS_COMING, endOfDayIso } from './sharePresets'

const ALICE = { id: 'alice', name: 'Alice Owner', email: 'alice@example.test', accountType: 'member' as const }
const share = (over: Record<string, unknown> = {}) => ({
  user: { id: 'bob', name: 'Bob Reader', email: 'bob@example.test', status: 'active', accountType: 'member' as const },
  access: 'read', rawData: false, expiresAt: null as string | null, expired: false, note: null as string | null,
  grantedById: 'alice', grantedBy: ALICE as typeof ALICE | null,
  createdAt: '2026-11-13T10:00:00.000Z', updatedAt: '2026-11-13T10:00:00.000Z', ...over,
})
type Share = ReturnType<typeof share>

function renderList(shares: Share[], over: Partial<Parameters<typeof CollaboratorList>[0]> = {}) {
  const onChange = vi.fn(async () => {})
  const onRevoke = vi.fn(async () => {})
  render(
    <AlertProvider>
      <CollaboratorList
        projectName="Alpha recon"
        shares={shares as never}
        viewerId="alice"
        writeRefusal={WRITE_PRESETS_COMING}
        onChange={onChange}
        onRevoke={onRevoke}
        {...over}
      />
    </AlertProvider>,
  )
  return { onChange, onRevoke }
}
const item = (name: string) => within(screen.getByRole('listitem', { name }))

afterEach(cleanup)

describe('what each share shows', () => {
  test('the person, the level and toggles, no end date, granted by you', () => {
    renderList([share()])
    const bob = item('Bob Reader')
    expect(bob.getByRole('group', { name: 'Bob Reader, bob@example.test, Member' })).toBeInTheDocument()
    expect(bob.getByText('Viewer (Read)')).toBeInTheDocument()
    expect(bob.getByText('Toggles: none')).toBeInTheDocument()
    expect(bob.getByText('No end date')).toBeInTheDocument()
    expect(bob.getByText('Granted by you')).toBeInTheDocument()
  })

  test('Raw data, an end date, a note, granted by someone else (named by email and type)', () => {
    renderList([share({ rawData: true, expiresAt: '2027-01-31T22:59:59.000Z', note: 'Q1 pentest' })], { viewerId: 'someone-else' })
    const bob = item('Bob Reader')
    expect(bob.getByText('Analyst (Read + Raw data & files)')).toBeInTheDocument()
    expect(bob.getByText('Toggles: Raw data & files')).toBeInTheDocument()
    expect(bob.getByText(/^Ends /)).toBeInTheDocument()
    expect(bob.getByText('Q1 pentest')).toBeInTheDocument()
    expect(bob.getByText('Granted by Alice Owner (alice@example.test, Member)')).toBeInTheDocument()
  })

  test('an expired share, a disabled account and a granter whose account is gone are said plainly', () => {
    renderList([share({
      expired: true, expiresAt: '2026-11-01T00:00:00.000Z', grantedById: 'gone-account', grantedBy: null,
      user: { id: 'bob', name: 'Bob Reader', email: 'bob@example.test', status: 'disabled', accountType: 'member' },
    })])
    const bob = item('Bob Reader')
    expect(bob.getByText(/^Expired .*: it gives no access/)).toBeInTheDocument()
    expect(bob.getByText(/This account is disabled: the share gives no access/)).toBeInTheDocument()
    expect(bob.getByText('Granted by an account that no longer exists')).toBeInTheDocument()
  })

  test('a person without a name is listed by email', () => {
    renderList([share({ user: { id: 'bob', name: null, email: 'bob@example.test', status: 'active', accountType: 'member' } })])
    expect(screen.getByRole('listitem', { name: 'bob@example.test' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Revoke access for bob@example.test' })).toBeInTheDocument()
  })
})

describe('revoke confirmation', () => {
  test('cancel revokes nothing; confirm revokes', async () => {
    const { onRevoke } = renderList([share()])
    fireEvent.click(screen.getByRole('button', { name: 'Revoke access for Bob Reader' }))
    let confirm = await screen.findByRole('dialog', { name: 'Revoke access' })
    expect(confirm).toHaveTextContent(/Bob Reader \(bob@example\.test\) loses access to "Alpha recon" now/)
    fireEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Revoke access' })).toBeNull())
    expect(onRevoke).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Revoke access for Bob Reader' }))
    confirm = await screen.findByRole('dialog', { name: 'Revoke access' })
    fireEvent.click(within(confirm).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(onRevoke).toHaveBeenCalledTimes(1))
    expect(onRevoke).toHaveBeenCalledWith(expect.objectContaining({ user: expect.objectContaining({ id: 'bob' }) }))
  })
})

describe('change', () => {
  const open = () => {
    fireEvent.click(screen.getByRole('button', { name: 'Change access for Bob Reader' }))
    return within(screen.getByRole('form', { name: 'Change access for Bob Reader' }))
  }

  test('nothing changed: nothing sent, the editor closes', async () => {
    const { onChange } = renderList([share({ expiresAt: '2027-01-31T22:59:59.000Z', note: 'kept' })])
    fireEvent.click(open().getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('form', { name: 'Change access for Bob Reader' })).toBeNull())
    expect(onChange).not.toHaveBeenCalled()
  })

  test('a new end date, Raw data through Custom, a new note: each sent once', async () => {
    const { onChange } = renderList([share()])
    const form = open()
    fireEvent.click(form.getByRole('radio', { name: /^Custom/ }))
    fireEvent.click(form.getByRole('checkbox', { name: /Raw data & files/ }))
    fireEvent.change(form.getByLabelText(/Ends on/), { target: { value: '2027-03-01' } })
    fireEvent.change(form.getByLabelText(/Note/), { target: { value: 'extended' } })
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledTimes(1))
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ user: expect.objectContaining({ id: 'bob' }) }), {
      rawData: true, expiresAt: endOfDayIso('2027-03-01'), note: 'extended',
    })
  })

  test('clearing the end date and the note sends null for each', async () => {
    const { onChange } = renderList([share({ expiresAt: '2027-01-31T22:59:59.000Z', note: 'old' })])
    const form = open()
    fireEvent.change(form.getByLabelText(/Ends on/), { target: { value: '' } })
    fireEvent.change(form.getByLabelText(/Note/), { target: { value: '' } })
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(expect.anything(), { expiresAt: null, note: null }))
  })

  test('a refused change keeps the editor open with the reason', async () => {
    const onChange = vi.fn(async () => { throw new Error('expiresAt must be in the future (invalid_field · HTTP 400)') })
    renderList([share()], { onChange })
    const form = open()
    fireEvent.click(form.getByRole('radio', { name: /^Analyst/ }))
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    expect(await form.findByRole('alert')).toHaveTextContent('expiresAt must be in the future (invalid_field · HTTP 400)')
    expect(screen.getByRole('form', { name: 'Change access for Bob Reader' })).toBeInTheDocument()
  })

  test('the write presets are offered disabled with the reason', () => {
    renderList([share()])
    const form = open()
    expect(form.getByRole('radio', { name: /^Editor/ })).toBeDisabled()
    expect(form.getByText(WRITE_PRESETS_COMING)).toBeInTheDocument()
  })

  test('read only (acting as the owner): neither change nor revoke is offered', () => {
    renderList([share()], { readOnly: true })
    expect(screen.queryByRole('button', { name: 'Change access for Bob Reader' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Revoke access for Bob Reader' })).toBeNull()
    expect(item('Bob Reader').getByText('Viewer (Read)')).toBeInTheDocument()
  })
})


// Step 5.14: write sharing in force (writeRefusal null), the list's `grantable` answer.
describe('Read + Write shares (step 5.14)', () => {
  const OK = { grantable: true as const }
  const writeShare = (over: Record<string, unknown> = {}) =>
    share({ access: 'write', rawData: true, runScans: true, useAgent: false, exploit: false, manage: false, ...over })
  const grantable = (over: Record<string, unknown> = {}) => ({
    grantor: 'owner', ownerConsent: true, toggles: { runScans: OK, useAgent: OK, exploit: OK, manage: OK }, ...over,
  }) as never

  test('a write share shows its preset and toggles; the editor sends only the toggles that changed', async () => {
    const { onChange } = renderList([writeShare()], { writeRefusal: null, grantable: grantable() })
    const bob = item('Bob Reader')
    expect(bob.getByText('Custom (Read + Write + Run scans)')).toBeInTheDocument()
    expect(bob.getByText('Toggles: Raw data & files, Run scans')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Change access for Bob Reader' }))
    const form = within(screen.getByRole('form', { name: 'Change access for Bob Reader' }))
    expect(form.getByRole('checkbox', { name: /^Run scans/ })).toBeChecked()
    expect(form.getByRole('radio', { name: /^Custom/ })).toBeChecked()
    fireEvent.click(form.getByRole('checkbox', { name: /^Use AI agent/ }))
    // Inside Custom a flipped toggle stays Custom (from a preset it would move to Operator).
    expect(form.getByRole('radio', { name: /^Custom/ })).toBeChecked()
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(expect.anything(), { useAgent: true }))
  })

  test('a toggle the person may not grant any more can still be cleared (narrowing is never blocked)', async () => {
    const refused = { grantable: false, code: 'exploit_admins_only', reason: 'Only administrators.' }
    const { onChange } = renderList([writeShare({ exploit: true })], { writeRefusal: null, grantable: grantable({ toggles: { runScans: OK, useAgent: OK, manage: OK, exploit: refused } }) })
    fireEvent.click(screen.getByRole('button', { name: 'Change access for Bob Reader' }))
    const form = within(screen.getByRole('form', { name: 'Change access for Bob Reader' }))
    const exploit = form.getByRole('checkbox', { name: /^Exploitation & shells/ })
    expect(exploit).toBeChecked()
    expect(exploit).toBeEnabled()
    fireEvent.click(exploit)
    expect(exploit).toBeDisabled()
    fireEvent.click(form.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(expect.anything(), { exploit: false }))
  })

  test("a co-owner changes an editor's share but not a co-owner's (OQ-34); the owner changes both", () => {
    const coOwner = writeShare({ manage: true, user: { id: 'dan', name: 'Dan Coowner', email: 'dan@example.test', status: 'active', accountType: 'member' } })
    renderList([writeShare(), coOwner], { writeRefusal: null, grantable: grantable({ grantor: 'co_owner' }) })
    expect(screen.getByRole('button', { name: 'Change access for Bob Reader' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Change access for Dan Coowner' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Revoke access for Dan Coowner' })).toBeNull()
    cleanup()
    renderList([coOwner], { writeRefusal: null, grantable: grantable() })
    expect(screen.getByRole('button', { name: 'Revoke access for Dan Coowner' })).toBeInTheDocument()
  })
})
