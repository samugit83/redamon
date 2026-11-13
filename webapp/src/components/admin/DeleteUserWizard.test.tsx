/**
 * The user-deletion wizard (step 5.13; SH-16, SH-17; DV-06, DV-19, UI-11): the deletion plan shows what
 * deleting the account does (shared projects, the ones deleted with it, its shares elsewhere, its
 * conversations, live work and what ends with it); each shared project is resolved first: offered to an
 * active collaborator with the admin's own password, given now by Root without the acceptance, or deleted
 * anyway after the app's danger dialog. The delete stays disabled until every shared project is resolved;
 * a 409 from the server reloads the plan. Loading, error + Try again and denied states; every control is
 * a labelled native control in a group named after its project.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/DeleteUserWizard.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { DeleteUserWizard, deletionWizardInForce } from './DeleteUserWizard'
import type { DeletionPlan } from '@/lib/authz/userDeletion'

const PLAN: DeletionPlan = {
  account: { id: 'alice', name: 'Alice', email: 'alice@e2e.local', role: 'standard', status: 'active' },
  transfers: { available: true, mayForce: false },
  sharedProjects: [{
    id: 'P1', name: 'Client shared', running: null, offer: null,
    collaborators: [
      { id: 'bob', name: 'Bob', email: 'bob@e2e.local', access: 'write', active: true, expiresAt: null },
      { id: 'dino', name: 'Dino', email: 'dino@e2e.local', access: 'read', active: false, expiresAt: null },
    ],
  }],
  unsharedProjects: [{ id: 'P2', name: 'Alone', running: 'a full recon scan is running' }],
  memberships: [{ project: { id: 'P3', name: "Olga's engagement" }, owner: { id: 'olga', name: 'Olga', email: 'olga@e2e.local' }, access: 'write', expiresAt: null }],
  conversationsReassigned: 2,
  liveWork: { agentRuns: 1, queuedScans: 3, schedules: 0 },
  endsWithAccount: { mcpTokens: 1, deviceSessions: 2, nucleiTemplates: 0 },
}
const OFFERED = {
  id: 't1', project: { id: 'P1', name: 'Client shared' }, from: { id: 'alice', name: 'Alice', email: null },
  to: { id: 'bob', name: 'Bob', email: null }, oldOwnerRole: 'leave', status: 'pending', error: null,
  createdAt: '2026-11-13T10:00:00.000Z', expiresAt: '2026-11-20T10:00:00.000Z', decidedAt: null,
} as const

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
let plan: () => Response
let postAnswer: () => Response
let deleteAnswer: () => Response
let fetchMock: ReturnType<typeof vi.fn>
let onDeleted: ReturnType<typeof vi.fn<() => void>>
let onClose: ReturnType<typeof vi.fn<() => void>>

beforeEach(() => {
  plan = () => json({ plan: PLAN })
  postAnswer = () => json({ offer: OFFERED }, 201)
  deleteAnswer = () => json({ success: true })
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url === '/api/users/alice/deletion-plan' && (!init?.method || init.method === 'GET')) return plan()
    if (url === '/api/users/alice/deletion-plan' && init?.method === 'POST') return postAnswer()
    if (url === '/api/users/alice' && init?.method === 'DELETE') return deleteAnswer()
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  onDeleted = vi.fn<() => void>()
  onClose = vi.fn<() => void>()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const open = (targetIsAdmin = false) => render(
  <AlertProvider>
    <DeleteUserWizard isOpen userId="alice" userName="Alice" targetIsAdmin={targetIsAdmin} onClose={onClose} onDeleted={onDeleted} />
  </AlertProvider>,
)
const sent = (method: string) => fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === method)
const bodyOf = (call: unknown[]) => JSON.parse(String((call[1] as RequestInit).body))
const lastDialog = () => screen.getAllByRole('dialog').at(-1)!
const project = async () => screen.findByRole('group', { name: 'Client shared' })
const deleteButton = () => screen.getByRole('button', { name: 'Delete the account' })

describe('the plan', () => {
  test('loading, then what the deletion does', async () => {
    open()
    expect(screen.getByRole('status')).toHaveTextContent('Reading what this deletion does')
    const group = await project()
    expect(group).toHaveTextContent('Shared with Bob, Dino (inactive)')
    expect(screen.getByText('Alone')).toBeInTheDocument()
    expect(screen.getByText(/running now: a full recon scan is running; it is stopped/)).toBeInTheDocument()
    expect(screen.getByText(/owned by Olga, Read \+ Write\): ends with the account/)).toBeInTheDocument()
    expect(screen.getByText(/2 conversations in other people's projects stay there/)).toBeInTheDocument()
    expect(screen.getByText(/1 agent run stopped, 3 queued scans cancelled, 0 schedules paused/)).toBeInTheDocument()
    expect(screen.getByText(/1 MCP token and 2 device sessions end with the account/)).toBeInTheDocument()
  })

  test('an error with Try again; a refusal says the account cannot be deleted', async () => {
    plan = () => json({ error: 'The database could not be reached', code: 'P1001' }, 500)
    open()
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    plan = () => json({ plan: PLAN })
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await project()).toBeInTheDocument()
    cleanup()
    plan = () => json({ error: 'Forbidden', code: 'forbidden', permission: 'users:delete' }, 403)
    open()
    expect(await screen.findByRole('alert')).toHaveTextContent(/You cannot delete this account/)
  })
})

describe('delete blocked until resolved', () => {
  test('disabled with the reason; "Delete it anyway" enables it; the danger dialog lists the project; the DELETE names it', async () => {
    open()
    const group = await project()
    expect(deleteButton()).toBeDisabled()
    expect(screen.getByText('Resolve each shared project first.')).toBeInTheDocument()
    fireEvent.click(within(group).getByRole('radio', { name: 'Delete it anyway with the account' }))
    expect(deleteButton()).toBeEnabled()
    fireEvent.click(deleteButton())
    const danger = lastDialog()
    expect(danger).toHaveTextContent('Client shared')
    fireEvent.click(within(danger).getByRole('button', { name: 'Delete them with the account' }))
    await waitFor(() => expect(onDeleted).toHaveBeenCalled())
    expect(bodyOf(sent('DELETE')[0])).toEqual({ deleteAnyway: ['P1'] })
  })

  test('cancelling the danger dialog sends nothing', async () => {
    open()
    fireEvent.click(within(await project()).getByRole('radio', { name: 'Delete it anyway with the account' }))
    fireEvent.click(deleteButton())
    fireEvent.click(within(lastDialog()).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.getAllByRole('dialog')).toHaveLength(1))
    expect(sent('DELETE')).toEqual([])
  })

  test('a 409 from the server (shared since the plan was read) reloads the plan and says why', async () => {
    deleteAnswer = () => json({ error: 'This user owns projects shared with other people.', code: 'deletion_plan_unresolved' }, 409)
    open()
    fireEvent.click(within(await project()).getByRole('radio', { name: 'Delete it anyway with the account' }))
    fireEvent.click(deleteButton())
    fireEvent.click(within(lastDialog()).getByRole('button', { name: 'Delete them with the account' }))
    expect(await screen.findByText(/deletion_plan_unresolved/)).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([url, init]) => url === '/api/users/alice/deletion-plan' && !(init as RequestInit)?.method)).toHaveLength(2)
    expect(onDeleted).not.toHaveBeenCalled()
  })

  test("another admin: the delete takes the deleter's own password, sent with the plan's choices", async () => {
    plan = () => json({ plan: { ...PLAN, sharedProjects: [] } })
    open(true)
    await screen.findByText(/no project of this account is shared/)
    fireEvent.click(deleteButton())
    const modal = lastDialog()
    expect(modal).toHaveTextContent('Confirm with your own password')
    fireEvent.change(within(modal).getByLabelText('Your password'), { target: { value: 'my-own-pass' } })
    fireEvent.click(within(modal).getByRole('button', { name: 'Delete the account' }))
    await waitFor(() => expect(onDeleted).toHaveBeenCalled())
    expect(bodyOf(sent('DELETE')[0])).toEqual({ deleteAnyway: [], stepUpPassword: 'my-own-pass' })
  })
})

describe('transferring a shared project', () => {
  test('an offer to an active collaborator, with the own password; the plan then shows it and the delete waits', async () => {
    open()
    const group = await project()
    fireEvent.click(within(group).getByRole('radio', { name: 'Offer it to a collaborator (they accept or decline)' }))
    const select = within(group).getByLabelText('Collaborator')
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['Choose…', 'Bob'])
    const send = within(group).getByRole('button', { name: 'Send the offer' })
    expect(send).toBeDisabled()
    fireEvent.change(select, { target: { value: 'bob' } })
    plan = () => json({ plan: { ...PLAN, sharedProjects: [{ ...PLAN.sharedProjects[0], offer: OFFERED }] } })
    fireEvent.click(send)
    const modal = lastDialog()
    expect(modal).toHaveTextContent('Confirm the offer with your own password')
    fireEvent.change(within(modal).getByLabelText('Your password'), { target: { value: 'pw-1' } })
    fireEvent.click(within(modal).getByRole('button', { name: 'Send the offer' }))
    expect(await screen.findByText(/Client shared was offered to Bob/)).toBeInTheDocument()
    expect(bodyOf(sent('POST')[0])).toEqual({ action: 'offer', projectId: 'P1', toUserId: 'bob', stepUpPassword: 'pw-1' })
    expect(await screen.findByText(/Offered to Bob: waiting for their answer until/)).toBeInTheDocument()
    expect(deleteButton()).toBeDisabled()
  })

  test("withdrawing a member's offer: the app's dialog, no password", async () => {
    plan = () => json({ plan: { ...PLAN, sharedProjects: [{ ...PLAN.sharedProjects[0], offer: OFFERED }] } })
    postAnswer = () => json({ withdrawn: true, status: 'cancelled' })
    open()
    fireEvent.click(within(await project()).getByRole('button', { name: 'Withdraw the offer' }))
    plan = () => json({ plan: PLAN })
    fireEvent.click(within(lastDialog()).getByRole('button', { name: 'Withdraw' }))
    expect(await screen.findByText('The offer of Client shared was withdrawn.')).toBeInTheDocument()
    expect(bodyOf(sent('POST')[0])).toEqual({ action: 'cancel', projectId: 'P1' })
  })

  test('the forced transfer is offered only to the viewer who may force, with Root\'s password', async () => {
    open()
    expect(within(await project()).queryByRole('radio', { name: /without their acceptance/ })).toBeNull()
    cleanup()
    plan = () => json({ plan: { ...PLAN, transfers: { available: true, mayForce: true } } })
    postAnswer = () => json({ transferred: { projectId: 'P1' } })
    open()
    const group = await project()
    fireEvent.click(within(group).getByRole('radio', { name: 'Give it to a collaborator now, without their acceptance (Root)' }))
    fireEvent.change(within(group).getByLabelText('Collaborator'), { target: { value: 'bob' } })
    plan = () => json({ plan: { ...PLAN, sharedProjects: [] } })
    fireEvent.click(within(group).getByRole('button', { name: 'Transfer now' }))
    const modal = lastDialog()
    expect(modal).toHaveTextContent('without their acceptance')
    fireEvent.change(within(modal).getByLabelText('Your password'), { target: { value: 'root-pw' } })
    fireEvent.click(within(modal).getByRole('button', { name: 'Transfer now' }))
    expect(await screen.findByText('Client shared now belongs to Bob.')).toBeInTheDocument()
    expect(bodyOf(sent('POST')[0])).toEqual({ action: 'force', projectId: 'P1', toUserId: 'bob', stepUpPassword: 'root-pw' })
    await waitFor(() => expect(deleteButton()).toBeEnabled())
  })

  test('a refused offer keeps the password dialog open with the code', async () => {
    postAnswer = () => json({ error: 'The agent is busy.', code: 'project_busy' }, 409)
    open()
    const group = await project()
    fireEvent.click(within(group).getByRole('radio', { name: /^Offer it/ }))
    fireEvent.change(within(group).getByLabelText('Collaborator'), { target: { value: 'bob' } })
    fireEvent.click(within(group).getByRole('button', { name: 'Send the offer' }))
    fireEvent.change(within(lastDialog()).getByLabelText('Your password'), { target: { value: 'pw' } })
    fireEvent.click(within(lastDialog()).getByRole('button', { name: 'Send the offer' }))
    expect(await within(lastDialog()).findByText(/project_busy/)).toBeInTheDocument()
  })

  test("Root's policy at Read: no transfer can be chosen, only the deletion, and the plan says why", async () => {
    plan = () => json({ plan: { ...PLAN, transfers: { available: false, mayForce: true } } })
    open()
    const group = await project()
    expect(within(group).getByRole('radio', { name: /^Offer it/ })).toBeDisabled()
    expect(within(group).getByRole('radio', { name: /without their acceptance/ })).toBeDisabled()
    expect(within(group).getByRole('radio', { name: 'Delete it anyway with the account' })).toBeEnabled()
    expect(screen.getByText(/sharing policy is at Read only/)).toBeInTheDocument()
  })
})

describe('the switch', () => {
  test('the wizard replaces the plain confirmation only with write sharing switched on', () => {
    expect(deletionWizardInForce(null)).toBe(false)
    expect(deletionWizardInForce({ identity: true, permissions: true, sharing: true, sharingWrite: false } as never)).toBe(false)
    expect(deletionWizardInForce({ identity: true, permissions: true, sharing: true, sharingWrite: true } as never)).toBe(true)
  })
})
