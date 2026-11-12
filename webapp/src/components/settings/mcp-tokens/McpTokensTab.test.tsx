/**
 * The MCP Server tab.
 *
 * The states pinned here are the ones that, when missed, cause a real support
 * problem rather than a cosmetic one:
 *
 *  - a loading SKELETON, never a flash of the empty state (which reads as "you
 *    have no tokens" and prompts a duplicate mint)
 *  - a fetch error shown INLINE with a retry, never a silent empty list
 *  - create-in-flight disables submit, so a double-click cannot mint two tokens
 *  - permission-denied renders the form DISABLED WITH A REASON, rather than a
 *    button that 403s on click
 *  - the one-time reveal says plainly that it will not be shown again
 *  - every row's actions are reachable behind its kebab menu, Delete really
 *    deletes, and an edit that gives a token MORE power asks for the password
 *    while one that takes power away does not
 *
 * @vitest-environment jsdom
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, fireEvent } from '@testing-library/react'

const h = vi.hoisted(() => ({
  dangerConfirm: vi.fn(), alertError: vi.fn(), confirm: vi.fn(),
}))

vi.mock('@/components/ui', async importActual => ({
  // The REAL Menu, because the row's actions now live behind it: a test that
  // stubbed the dropdown open would stop proving that they are reachable at all.
  ...(await importActual<typeof import('@/components/ui')>()),
  useAlertModal: () => ({
    dangerConfirm: h.dangerConfirm, alertError: h.alertError, confirm: h.confirm,
  }),
  WikiInfoButton: () => null,
  // The Agent Onboarding modal renders through the shared Modal and links out
  // with ExternalLink. Rendered as plain elements so this file keeps testing the
  // TAB rather than the modal's own portal and focus behaviour.
  Modal: ({ isOpen, title, children }: { isOpen: boolean; title?: string; children?: ReactNode }) =>
    isOpen ? <div role="dialog" aria-label={title}>{children}</div> : null,
  ExternalLink: ({ href, children }: { href: string; children?: ReactNode }) =>
    <a href={href}>{children}</a>,
}))
vi.mock('@/hooks/useUnsavedChangesGuard', () => ({
  useUnsavedChangesGuard: () => ({ guardedNavigate: vi.fn() }),
}))

import type { ReactNode } from 'react'
import McpTokensTab from './McpTokensTab'
import type { McpScope } from '@/lib/mcpAuth'
import { PROFILE_IDS, scopesForProfile, type ProfileId } from '@/lib/mcp/profiles'

const TOKEN = {
  id: 't1',
  name: 'ci agent',
  tokenPrefix: 'rdmn_mcp_a3f9c21e',
  scopes: ['recon:read'],
  lastUsedAt: null,
  expiresAt: null,
  revokedAt: null,
  createdAt: '2026-09-01T10:00:00.000Z',
}

/** Route fetch by URL so the component's two parallel loads both resolve. */
function mockFetch(handlers: {
  me?: unknown
  meStatus?: number
  tokens?: unknown
  tokensStatus?: number
  create?: unknown
  createStatus?: number
  onCreate?: () => void
  update?: unknown
  updateStatus?: number
}) {
  return vi.fn(async (url: string, init?: RequestInit) => {
    if (String(url).includes('/api/auth/me')) {
      return {
        ok: (handlers.meStatus ?? 200) < 400,
        status: handlers.meStatus ?? 200,
        json: async () => handlers.me ?? { id: 'owner', role: 'standard' },
      }
    }
    if (init?.method === 'PATCH') {
      return {
        ok: (handlers.updateStatus ?? 200) < 400,
        status: handlers.updateStatus ?? 200,
        json: async () => handlers.update ?? { token: TOKEN },
      }
    }
    if (init?.method === 'POST') {
      handlers.onCreate?.()
      return {
        ok: (handlers.createStatus ?? 201) < 400,
        status: handlers.createStatus ?? 201,
        json: async () => handlers.create ?? { plaintext: 'rdmn_mcp_' + 'a'.repeat(48), token: TOKEN },
      }
    }
    return {
      ok: (handlers.tokensStatus ?? 200) < 400,
      status: handlers.tokensStatus ?? 200,
      json: async () => handlers.tokens ?? { tokens: [] },
    }
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(cleanup)

describe('loading and error states', () => {
  test('shows a skeleton while loading, never the empty state', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})))
    render(<McpTokensTab userId="owner" />)

    expect(screen.getByLabelText('Loading tokens')).toBeTruthy()
    expect(screen.queryByText(/No MCP access tokens yet/)).toBeNull()
  })

  test('a fetch failure is shown inline with a retry, not as an empty list', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokensStatus: 500 }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/Could not load tokens \(HTTP 500\)/)).toBeTruthy())
    expect(screen.getByText('Retry')).toBeTruthy()
    expect(screen.queryByText(/No MCP access tokens yet/)).toBeNull()
  })

  test('an empty list explains what a token is for', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/No MCP access tokens yet/)).toBeTruthy())
  })
})

describe('the list', () => {
  test('renders a token by its masked prefix, never a full token', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    expect(screen.getByText(/rdmn_mcp_a3f9c21e…/)).toBeTruthy()
  })

  test('"Never" and "Never used" are shown rather than blanks', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('Never')).toBeTruthy())
    expect(screen.getByText('Never used')).toBeTruthy()
  })

  test('a revoked token is flagged rather than hidden', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [{ ...TOKEN, revokedAt: '2026-09-02T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('revoked')).toBeTruthy())
  })

  test('an expired token is flagged rather than hidden', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [{ ...TOKEN, expiresAt: '2020-01-01T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('expired')).toBeTruthy())
  })

  test('a dead token can still be deleted, because the row is what is going', async () => {
    // Revoking a revoked token was a no-op, so the action used to be hidden.
    // Deleting one is not: a row nobody needs any more is exactly the row an
    // operator wants gone.
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [{ ...TOKEN, revokedAt: '2026-09-02T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('revoked')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))
    expect(screen.getByText('Delete')).toBeTruthy()
  })
})

describe('permission denied renders a reason, not a button that 403s', () => {
  test('an admin viewing another user cannot open the create form', async () => {
    vi.stubGlobal('fetch', mockFetch({ me: { id: 'admin1', role: 'admin' } }))
    render(<McpTokensTab userId="victim" />)

    await waitFor(() => expect(screen.getByText(/can only be created by its own user/)).toBeTruthy())
    expect(screen.getByText('New token').closest('button')).toBeDisabled()
  })

  test('the owner can open the create form', async () => {
    vi.stubGlobal('fetch', mockFetch({ me: { id: 'owner', role: 'standard' } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    expect(screen.queryByText(/can only be created by its own user/)).toBeNull()
  })

  test('an unresolved session leaves minting disabled (the safe direction)', async () => {
    vi.stubGlobal('fetch', mockFetch({ meStatus: 401 }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/No MCP access tokens yet/)).toBeTruthy())
    expect(screen.getByText('New token').closest('button')).toBeDisabled()
  })

  test('hovering the disabled button explains why, when viewing another user', async () => {
    vi.stubGlobal('fetch', mockFetch({ me: { id: 'admin1', role: 'admin' } }))
    render(<McpTokensTab userId="victim" />)

    await waitFor(() => expect(screen.getByText(/can only be created by its own user/)).toBeTruthy())
    fireEvent.mouseEnter(screen.getByText('New token').closest('button')!)
    const tip = await screen.findByRole('tooltip')
    expect(tip.textContent).toMatch(/account you are logged in with/)
  })

  test('the owner gets no tooltip on the enabled button', async () => {
    vi.stubGlobal('fetch', mockFetch({ me: { id: 'owner', role: 'standard' } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.mouseEnter(screen.getByText('New token').closest('button')!)
    await new Promise(r => setTimeout(r, 300))
    expect(screen.queryByRole('tooltip')).toBeNull()
  })

  test('an unresolved session does not claim another user is being viewed', async () => {
    vi.stubGlobal('fetch', mockFetch({ meStatus: 401 }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/No MCP access tokens yet/)).toBeTruthy())
    fireEvent.mouseEnter(screen.getByText('New token').closest('button')!)
    await new Promise(r => setTimeout(r, 300))
    expect(screen.queryByRole('tooltip')).toBeNull()
  })
})

describe('the create form', () => {
  const openForm = async () => {
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))
  }

  test('only recon:read and kali:exec are ticked by default', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    const read = screen.getByText('recon:read').closest('label')!.querySelector('input')!
    const exec = screen.getByText('kali:exec').closest('label')!.querySelector('input')!
    const scan = screen.getByText('recon:scan').closest('label')!.querySelector('input')!
    expect(read).toBeChecked()
    expect(exec).toBeChecked()
    expect(scan).not.toBeChecked()
  })

  test('recon:overwrite says plainly that it discards the graph', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    expect(screen.getByText(/DISCARDS the current graph/)).toBeTruthy()
  })

  test('the default expiry is 90 days', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    expect((screen.getByLabelText('Expires') as HTMLSelectElement).value).toBe('90')
  })

  test('it asks for the password as a step-up', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    await openForm()

    expect((screen.getByLabelText('Confirm your password') as HTMLInputElement).type).toBe('password')
  })

  test('a create failure keeps the form populated so nothing is retyped', async () => {
    vi.stubGlobal('fetch', mockFetch({ createStatus: 401, create: { error: 'Password is incorrect' } }))
    await openForm()

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci agent' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(screen.getByText('Password is incorrect (HTTP 401)')).toBeTruthy())
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('ci agent')
  })

  test('a create the database refused names its code and status', async () => {
    vi.stubGlobal('fetch', mockFetch({ createStatus: 500, create: { error: 'Could not create the token', code: 'P2024' } }))
    await openForm()

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci agent' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(screen.getByText('Could not create the token (P2024 · HTTP 500)')).toBeTruthy())
  })

  test('a double-click cannot mint two tokens', async () => {
    let creates = 0
    let release: (() => void) | undefined
    const gate = new Promise<void>(r => { release = r })
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      if (String(url).includes('/api/auth/me')) {
        return { ok: true, status: 200, json: async () => ({ id: 'owner', role: 'standard' }) }
      }
      if (init?.method === 'POST') {
        creates++
        await gate
        return { ok: true, status: 201, json: async () => ({ plaintext: 'rdmn_mcp_x', token: TOKEN }) }
      }
      return { ok: true, status: 200, json: async () => ({ tokens: [] }) }
    }))
    await openForm()

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci' } })
    const submit = screen.getByText('Create token').closest('button')!
    fireEvent.click(submit)
    await waitFor(() => expect(submit).toBeDisabled())
    fireEvent.click(submit)

    release!()
    await waitFor(() => expect(creates).toBe(1))
  })
})

describe('the one-time reveal', () => {
  test('warns that the token will not be shown again, and shows a client snippet', async () => {
    const plaintext = 'rdmn_mcp_' + 'b'.repeat(48)
    vi.stubGlobal('fetch', mockFetch({ create: { plaintext, token: TOKEN } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'ci' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(screen.getByText(/will not be able to see it again/)).toBeTruthy())
    expect(screen.getByText(plaintext)).toBeTruthy()
    // The ready-to-paste config, so no hand editing is needed.
    expect(screen.getByText(/"mcpServers"/)).toBeTruthy()
  })
})

describe('deleting asks first, through the modal (never window.confirm)', () => {
  const openDelete = async (fetchMock: ReturnType<typeof mockFetch>) => {
    vi.stubGlobal('fetch', fetchMock)
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))
    fireEvent.click(screen.getByText('Delete'))
  }

  test('a declined confirm deletes nothing', async () => {
    h.dangerConfirm.mockResolvedValue(false)
    const fetchMock = mockFetch({ tokens: { tokens: [TOKEN] } })
    await openDelete(fetchMock)

    await waitFor(() => expect(h.dangerConfirm).toHaveBeenCalled())
    expect(fetchMock.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(false)
  })

  test('a confirmed delete calls DELETE', async () => {
    h.dangerConfirm.mockResolvedValue(true)
    const fetchMock = mockFetch({ tokens: { tokens: [TOKEN] } })
    await openDelete(fetchMock)

    await waitFor(() =>
      expect(fetchMock.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(true)
    )
  })

  test('deleting a token that can mute says its mutes stay, and names the prefix to find them by', async () => {
    h.dangerConfirm.mockResolvedValue(false)
    const muter = { ...TOKEN, scopes: ['recon:read', 'triage:read', 'triage:mute'] }
    await openDelete(mockFetch({ tokens: { tokens: [muter] } }))
    await waitFor(() => expect(h.dangerConfirm).toHaveBeenCalled())
    const [message] = h.dangerConfirm.mock.calls[0]
    expect(message).toMatch(/Findings this token muted stay muted/)
    expect(message).toContain(`Token filter ${TOKEN.tokenPrefix}`)
    expect(message).toMatch(/the prefix is the only record/)
  })

  test('a token without triage:mute is not warned about mutes it cannot make', async () => {
    h.dangerConfirm.mockResolvedValue(false)
    await openDelete(mockFetch({ tokens: { tokens: [TOKEN] } }))
    await waitFor(() => expect(h.dangerConfirm).toHaveBeenCalled())
    expect(h.dangerConfirm.mock.calls[0][0]).not.toMatch(/muted/)
  })

  test('the prompt says the row is going, not that the token is switched off', async () => {
    // The old copy promised a revoke, which left the row on screen. Someone who
    // reads "cannot be undone" and still expects to see the row afterwards is
    // being misled about a destructive action.
    h.dangerConfirm.mockResolvedValue(false)
    await openDelete(mockFetch({ tokens: { tokens: [TOKEN] } }))

    await waitFor(() => expect(h.dangerConfirm).toHaveBeenCalled())
    const [message, title] = h.dangerConfirm.mock.calls[0]
    expect(message).toMatch(/removed from the database/)
    expect(message).toMatch(/audit log keeps a record/)
    expect(message).toMatch(/cannot be undone/)
    expect(title).toMatch(/Delete/)
  })

  test('the list is reloaded after a delete, so the row disappears', async () => {
    h.dangerConfirm.mockResolvedValue(true)
    const fetchMock = mockFetch({ tokens: { tokens: [TOKEN] } })
    await openDelete(fetchMock)

    await waitFor(() =>
      expect(fetchMock.mock.calls.some(c => c[1]?.method === 'DELETE')).toBe(true)
    )
    await waitFor(() => {
      const lists = fetchMock.mock.calls.filter(
        c => String(c[0]).includes('/mcp-tokens') && c[1]?.method === undefined
      )
      expect(lists.length).toBeGreaterThanOrEqual(2)
    })
  })
})

describe('the row actions live behind one kebab', () => {
  test('nothing is shown until the kebab is opened', async () => {
    // The point of the change: three spelled-out buttons per row were the widest
    // thing in the table and pushed the permission tags into wrapping.
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    expect(screen.queryByText('Onboard')).toBeNull()
    expect(screen.queryByText('Edit')).toBeNull()
    expect(screen.queryByText('Delete')).toBeNull()
  })

  test('opening it reveals all three actions', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))

    expect(screen.getByText('Onboard')).toBeTruthy()
    expect(screen.getByText('Edit')).toBeTruthy()
    expect(screen.getByText('Delete')).toBeTruthy()
  })

  test('each row gets its own kebab, named after its token', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [TOKEN, { ...TOKEN, id: 't2', name: 'old agent' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    expect(screen.getByLabelText('Actions for ci agent')).toBeTruthy()
    expect(screen.getByLabelText('Actions for old agent')).toBeTruthy()
  })
})

describe('the two MCP tabs are distinguishable', () => {
  test('the subtitle names this one as INBOUND and the other as outbound', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText(/Inbound:/)).toBeTruthy())
    expect(screen.getByText(/MCP Tool Plugins/)).toBeTruthy()
  })
})

describe('editing a token', () => {
  const ACTIVE = { ...TOKEN, scopes: ['recon:read', 'recon:scan'], expiresAt: '2099-01-01T00:00:00.000Z' }

  const patchBody = (fetchMock: ReturnType<typeof mockFetch>) => {
    const call = fetchMock.mock.calls.find(c => c[1]?.method === 'PATCH')
    return call ? JSON.parse(String(call[1]!.body)) : undefined
  }

  const openEdit = async (fetchMock: ReturnType<typeof mockFetch>, userId = 'owner') => {
    vi.stubGlobal('fetch', fetchMock)
    render(<McpTokensTab userId={userId} />)
    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    // The admin tests depend on the session having resolved before the panel opens.
    await waitFor(() => expect(fetchMock.mock.calls.some(c => String(c[0]).includes('/api/auth/me'))).toBe(true))
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))
    fireEvent.click(screen.getByText('Edit'))
    await waitFor(() => expect(screen.getByText('Edit token')).toBeTruthy())
  }

  const checkbox = (scope: string) =>
    screen.getByText(scope, { selector: 'code' }).closest('label')!.querySelector('input') as HTMLInputElement

  test('a revoked row offers the same actions as a live one', async () => {
    // Revoke used to be hidden on a dead row because revoking it again did
    // nothing. Delete is not the same action: a row nobody needs any more is
    // exactly the one an operator wants gone.
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [ACTIVE, { ...TOKEN, id: 't2', name: 'old', revokedAt: '2026-09-02T00:00:00.000Z' }] },
    }))
    render(<McpTokensTab userId="owner" />)

    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Actions for old'))
    for (const label of ['Onboard', 'Edit', 'Delete']) {
      expect(screen.getByText(label), label).toBeTruthy()
    }
  })

  test('the panel opens with the current name and permissions', async () => {
    await openEdit(mockFetch({ tokens: { tokens: [ACTIVE] } }))

    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('ci agent')
    expect(checkbox('recon:read')).toBeChecked()
    expect(checkbox('recon:scan')).toBeChecked()
    expect(checkbox('recon:overwrite')).not.toBeChecked()
    expect((screen.getByLabelText('Expires') as HTMLSelectElement).value).toBe('keep')
  })

  test('Save stays disabled until something changes', async () => {
    await openEdit(mockFetch({ tokens: { tokens: [ACTIVE] } }))
    expect(screen.getByText('Save changes').closest('button')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'renamed' } })
    expect(screen.getByText('Save changes').closest('button')).not.toBeDisabled()
  })

  test('removing a permission saves without asking for the password', async () => {
    const fetchMock = mockFetch({ tokens: { tokens: [ACTIVE] } })
    await openEdit(fetchMock)

    fireEvent.click(checkbox('recon:scan'))
    expect(screen.queryByLabelText('Confirm your password')).toBeNull()
    fireEvent.click(screen.getByText('Save changes'))

    await waitFor(() => expect(patchBody(fetchMock)).toBeTruthy())
    expect(patchBody(fetchMock)).toEqual({ name: 'ci agent', scopes: ['recon:read'] })
  })

  test('adding a permission asks for the password and sends it', async () => {
    const fetchMock = mockFetch({ tokens: { tokens: [ACTIVE] } })
    await openEdit(fetchMock)

    fireEvent.click(checkbox('graph:cypher'))
    const pw = screen.getByLabelText('Confirm your password') as HTMLInputElement
    expect(pw.type).toBe('password')
    fireEvent.change(pw, { target: { value: 'secret' } })
    fireEvent.click(screen.getByText('Save changes'))

    await waitFor(() => expect(patchBody(fetchMock)).toBeTruthy())
    expect(patchBody(fetchMock).password).toBe('secret')
    expect(patchBody(fetchMock).scopes).toContain('graph:cypher')
  })

  test('"Expire now" on a token that can mute says its mutes stay, by prefix', async () => {
    await openEdit(mockFetch({ tokens: { tokens: [{ ...ACTIVE, scopes: ['recon:read', 'triage:mute'] }] } }))
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'now' } })
    expect(screen.getByText(/Findings this token muted stay muted/).textContent)
      .toContain(`Token filter ${TOKEN.tokenPrefix}`)
  })

  test('"Expire now" on a token that cannot mute says nothing about mutes', async () => {
    await openEdit(mockFetch({ tokens: { tokens: [ACTIVE] } }))
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'now' } })
    expect(screen.queryByText(/Findings this token muted/)).toBeNull()
  })

  test('"Expire now" saves without a password', async () => {
    const fetchMock = mockFetch({ tokens: { tokens: [ACTIVE] } })
    await openEdit(fetchMock)

    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'now' } })
    expect(screen.queryByLabelText('Confirm your password')).toBeNull()
    fireEvent.click(screen.getByText('Save changes'))

    await waitFor(() => expect(patchBody(fetchMock)).toBeTruthy())
    expect(patchBody(fetchMock).expiry).toBe('now')
  })

  test('removing the expiry asks for the password', async () => {
    await openEdit(mockFetch({ tokens: { tokens: [ACTIVE] } }))
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'never' } })
    expect(screen.getByLabelText('Confirm your password')).toBeTruthy()
  })

  test('picking a date shows a date field and sends that date', async () => {
    const fetchMock = mockFetch({ tokens: { tokens: [ACTIVE] } })
    await openEdit(fetchMock)

    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: 'date' } })
    expect(screen.getByText('Save changes').closest('button')).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Expiry date'), { target: { value: '2027-01-15' } })
    fireEvent.click(screen.getByText('Save changes'))

    await waitFor(() => expect(patchBody(fetchMock)).toBeTruthy())
    expect(patchBody(fetchMock).expiry).toBe('2027-01-15')
  })

  test('a server step-up request reveals the password field and keeps the panel open', async () => {
    await openEdit(mockFetch({
      tokens: { tokens: [ACTIVE] },
      updateStatus: 401,
      update: { error: 'Adding a permission or extending the expiry needs your password.', passwordRequired: true },
    }))

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'renamed' } })
    fireEvent.click(screen.getByText('Save changes'))

    await waitFor(() => expect(screen.getByText(/needs your password/)).toBeTruthy())
    expect(screen.getByLabelText('Confirm your password')).toBeTruthy()
    expect((screen.getByLabelText('Name') as HTMLInputElement).value).toBe('renamed')
  })

  test('an admin viewing another user cannot save a widening edit, and is told why', async () => {
    await openEdit(mockFetch({ me: { id: 'admin1', role: 'admin' }, tokens: { tokens: [ACTIVE] } }), 'victim')

    fireEvent.click(checkbox('recon:overwrite'))
    await waitFor(() => expect(screen.getByText(/Only the token's own user can add a permission/)).toBeTruthy())
    expect(screen.getByText('Save changes').closest('button')).toBeDisabled()
  })

  test('an admin can still remove a permission from another user token', async () => {
    await openEdit(mockFetch({ me: { id: 'admin1', role: 'admin' }, tokens: { tokens: [ACTIVE] } }), 'victim')

    fireEvent.click(checkbox('recon:scan'))
    expect(screen.getByText('Save changes').closest('button')).not.toBeDisabled()
  })

  test('a revoked token can be renamed but its permissions and expiry are locked', async () => {
    await openEdit(mockFetch({
      tokens: { tokens: [{ ...ACTIVE, revokedAt: '2026-09-02T00:00:00.000Z' }] },
    }))

    expect(screen.getByText(/only its name can change/)).toBeTruthy()
    expect(screen.getByText('recon:read', { selector: 'code' }).closest('fieldset')).toBeDisabled()
    expect(screen.getByLabelText('Expires')).toBeDisabled()
  })
})

// --- Agent Profiles ---------------------------------------------------------
//
// A profile ticks permissions on the operator's behalf. It must NEVER tick
// recon:overwrite: irreversible graph destruction has to be a deliberate act,
// not a side effect of choosing a job from a dropdown. kali:exec is the
// deliberate opposite: every profile ticks it.

describe('the Agent Profile drives the permissions', () => {
  const openForm = async (fetchMock = mockFetch({})) => {
    vi.stubGlobal('fetch', fetchMock)
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))
    return fetchMock
  }

  const profileSelect = () => screen.getByLabelText('Agent Profile') as HTMLSelectElement
  /**
   * The scope code also appears in the opt-in footnote ("Pentest also suggests
   * project:create"), so a bare code lookup is ambiguous for the profiles that
   * have one. Only a checkbox ROW is a label wrapping an input.
   */
  const box = (scope: McpScope) => {
    const row = screen.getAllByText(scope, { selector: 'code' })
      .map(el => el.closest('label'))
      .find(l => l?.querySelector('input[type=checkbox]'))
    return row!.querySelector('input') as HTMLInputElement
  }

  const pick = (id: ProfileId) => fireEvent.change(profileSelect(), { target: { value: id } })

  test('defaults to Custom, which ticks only recon:read and kali:exec', async () => {
    await openForm()
    expect(profileSelect().value).toBe('custom')
    expect(box('recon:read')).toBeChecked()
    expect(box('kali:exec')).toBeChecked()
    expect(box('recon:scan')).not.toBeChecked()
  })

  test('picking a profile on an untouched form does not ask to discard anything', async () => {
    // The blank form must match Custom's recommendation exactly, or the first
    // pick reads as discarding hand-picked permissions.
    await openForm()
    pick('asm')
    await waitFor(() => expect(box('recon:queue')).toBeChecked())
    expect(h.confirm).not.toHaveBeenCalled()
  })

  test('choosing a job re-ticks exactly that job permissions', async () => {
    await openForm()
    pick('asm')
    await waitFor(() => expect(box('recon:queue')).toBeChecked())
    for (const scope of scopesForProfile('asm')) {
      expect(box(scope), `asm should tick ${scope}`).toBeChecked()
    }
    expect(box('graph:cypher')).not.toBeChecked()
  })

  // Agent in the Loop is the one exception, by design: a driver token holds
  // read scopes only besides agent:loop (the loop tools refuse anything wider).
  test.each(PROFILE_IDS.filter(id => id !== 'agent_in_the_loop'))('%s auto-ticks kali:exec but never recon:overwrite', async id => {
    await openForm()
    pick(id)
    await waitFor(() => expect(profileSelect().value).toBe(id))
    expect(box('kali:exec'), `${id} did not tick kali:exec`).toBeChecked()
    expect(box('recon:overwrite'), `${id} auto-ticked recon:overwrite`).not.toBeChecked()
  })

  test('agent_in_the_loop ticks agent:loop and recon:read only, and is offered only while on', async () => {
    await openForm(mockFetch({ tokens: { tokens: [], features: { agentInTheLoop: true } } }))
    pick('agent_in_the_loop')
    await waitFor(() => expect(profileSelect().value).toBe('agent_in_the_loop'))
    await waitFor(() => expect(box('agent:loop')).toBeChecked())
    expect(box('recon:read')).toBeChecked()
    expect(box('kali:exec')).not.toBeChecked()
    expect(screen.queryByRole('alert')).toBeNull()
    cleanup()
    await openForm()
    expect([...profileSelect().options].map(o => o.value)).not.toContain('agent_in_the_loop')
  })

  test('a profile that wants a dangerous scope says so, with the box still clear', async () => {
    await openForm()
    pick('research') // the only profile recommending recon:overwrite
    await waitFor(() => expect(box('recon:settings')).toBeChecked())
    expect(screen.getAllByText('recommended, tick it yourself')).toHaveLength(1)
    expect(box('recon:overwrite')).not.toBeChecked()
    expect(screen.getByText(/never ticks those for you/)).toBeTruthy()
  })

  test('switching after a hand-edit asks before discarding the choice', async () => {
    h.confirm.mockResolvedValue(true)
    await openForm()
    pick('soc')
    await waitFor(() => expect(box('graph:cypher')).toBeChecked())
    fireEvent.click(box('recon:scan'))
    await waitFor(() => expect(box('recon:scan')).toBeChecked())

    pick('triage')
    await waitFor(() => expect(h.confirm).toHaveBeenCalled())
    expect(String(h.confirm.mock.calls[0][0])).toContain('Triage assistance')
  })

  test('declining that prompt keeps the hand-picked permissions', async () => {
    h.confirm.mockResolvedValue(false)
    await openForm()
    pick('soc')
    await waitFor(() => expect(box('graph:cypher')).toBeChecked())
    fireEvent.click(box('recon:scan'))
    await waitFor(() => expect(box('recon:scan')).toBeChecked())

    pick('triage')
    // The label moves, the permissions do not: a profile is a label, never a grant.
    await waitFor(() => expect(profileSelect().value).toBe('triage'))
    expect(box('recon:scan')).toBeChecked()
    expect(box('triage:write')).not.toBeChecked()
  })

  test('the mint sends the profile alongside the scopes', async () => {
    const f = await openForm()
    pick('asm')
    await waitFor(() => expect(box('recon:queue')).toBeChecked())
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'nightly' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(f.mock.calls.some(c => (c[1] as RequestInit)?.method === 'POST')).toBe(true))
    const post = f.mock.calls.find(c => (c[1] as RequestInit)?.method === 'POST')!
    const body = JSON.parse(String((post[1] as RequestInit).body))
    expect(body.profile).toBe('asm')
    expect(body.scopes).toEqual(scopesForProfile('asm'))
  })

  test('Custom is sent as null, so "no profile" and "chose Custom" stay one thing', async () => {
    const f = await openForm()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'manual' } })
    fireEvent.click(screen.getByText('Create token'))

    await waitFor(() => expect(f.mock.calls.some(c => (c[1] as RequestInit)?.method === 'POST')).toBe(true))
    const post = f.mock.calls.find(c => (c[1] as RequestInit)?.method === 'POST')!
    expect(JSON.parse(String((post[1] as RequestInit).body)).profile).toBeNull()
  })
})

describe('the Agent Profile on an existing token', () => {
  const PROFILED = { ...TOKEN, profile: 'asm', scopes: ['recon:read', 'triage:read'] }

  const openEditOf = async (row: unknown) => {
    const f = mockFetch({ tokens: { tokens: [row] } })
    vi.stubGlobal('fetch', f)
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    await waitFor(() => expect(f.mock.calls.some(c => String(c[0]).includes('/api/auth/me'))).toBe(true))
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))
    fireEvent.click(screen.getByText('Edit'))
    await waitFor(() => expect(screen.getByText('Edit token')).toBeTruthy())
    return f
  }

  test('the stored profile is pre-selected', async () => {
    await openEditOf(PROFILED)
    expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('asm')
  })

  test('a token minted before profiles existed reads as Custom', async () => {
    // Every pre-existing row has profile null; it must not render as blank or crash.
    await openEditOf({ ...TOKEN, profile: null })
    expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('custom')
  })

  test('changing only the profile saves it and asks for no password', async () => {
    h.confirm.mockResolvedValue(true)
    const f = await openEditOf(PROFILED)
    fireEvent.change(screen.getByLabelText('Agent Profile'), { target: { value: 'compliance' } })
    await waitFor(() => expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('compliance'))
    fireEvent.click(screen.getByText('Save changes'))

    await waitFor(() => expect(f.mock.calls.some(c => (c[1] as RequestInit)?.method === 'PATCH')).toBe(true))
    const patch = f.mock.calls.find(c => (c[1] as RequestInit)?.method === 'PATCH')!
    expect(JSON.parse(String((patch[1] as RequestInit).body)).profile).toBe('compliance')
    expect(screen.queryByLabelText('Confirm your password')).toBeNull()
  })

  /**
   * REGRESSION: changeEditProfile diffed against the STORED profile.
   *
   * It measured divergence from `editing.profile` instead of the profile
   * currently selected in the panel, so the second consecutive switch compared
   * the new profile's scopes against the ORIGINAL profile's recommendation and
   * always looked hand-edited. The operator got a prompt accusing them of
   * discarding permissions they had never touched. The mint form got this
   * right; only the edit panel was wrong.
   */
  test('two consecutive profile switches do not raise a spurious prompt', async () => {
    h.confirm.mockResolvedValue(true)
    // Stored as custom with exactly custom's recommendation, so nothing is
    // hand-edited at any point in this flow.
    await openEditOf({ ...TOKEN, profile: null, scopes: scopesForProfile('custom') })

    fireEvent.change(screen.getByLabelText('Agent Profile'), { target: { value: 'soc' } })
    await waitFor(() => expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('soc'))
    expect(h.confirm).not.toHaveBeenCalled()

    fireEvent.change(screen.getByLabelText('Agent Profile'), { target: { value: 'triage' } })
    await waitFor(() => expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('triage'))
    expect(h.confirm, 'switching soc -> triage is not a hand-edit').not.toHaveBeenCalled()
  })

  test('a genuine hand-edit in the panel still raises the prompt', async () => {
    h.confirm.mockResolvedValue(true)
    await openEditOf({ ...TOKEN, profile: null, scopes: scopesForProfile('custom') })
    fireEvent.change(screen.getByLabelText('Agent Profile'), { target: { value: 'soc' } })
    await waitFor(() => expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('soc'))
    // The switch itself was clean; only the tick below may cause the prompt.
    expect(h.confirm).not.toHaveBeenCalled()

    const row = screen.getAllByText('triage:write', { selector: 'code' })
      .map(e => e.closest('label')).find(l => l?.querySelector('input[type=checkbox]'))!
    fireEvent.click(row.querySelector('input')!)

    fireEvent.change(screen.getByLabelText('Agent Profile'), { target: { value: 'triage' } })
    await waitFor(() => expect(h.confirm).toHaveBeenCalled())
  })

  test('hand-editing away from the profile says divergence is allowed', async () => {
    await openEditOf(PROFILED)
    fireEvent.click(
      screen.getByText('graph:cypher', { selector: 'code' }).closest('label')!.querySelector('input')!
    )
    expect(await screen.findByText(/no longer match the/)).toBeTruthy()
    expect(screen.getByText(/never a\s+permission/)).toBeTruthy()
  })
})

describe('the Agent Onboarding entry points', () => {
  test('the tab offers onboarding before any token exists', async () => {
    vi.stubGlobal('fetch', mockFetch({}))
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText(/No MCP access tokens yet/)).toBeTruthy())
    expect(screen.getByText('Agent Onboarding')).toBeTruthy()
  })

  test('a token row opens the modal pre-filled from that token', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [{ ...TOKEN, profile: 'asm' }] } }))
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))
    fireEvent.click(screen.getByText('Onboard'))

    const dialog = await screen.findByRole('dialog')
    expect(dialog.getAttribute('aria-label')).toContain('ci agent')
    expect((screen.getByLabelText('Agent Profile') as HTMLSelectElement).value).toBe('asm')
  })

  test('the modal says plainly that it grants nothing', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [TOKEN] } }))
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('ci agent')).toBeTruthy())
    fireEvent.click(screen.getByLabelText('Actions for ci agent'))
    fireEvent.click(screen.getByText('Onboard'))
    // Without this a user ticking a permission in the modal believes they just
    // widened their token.
    expect(
      await screen.findByText(/previews what the instructions would say, and grants nothing/)
    ).toBeTruthy()
  })
})

describe('scopes the owner cannot grant (step 3.10, permissions switch on)', () => {
  // The row's own label wraps its checkbox; the scope code is the row's <code>.
  const box = (scope: string) =>
    [...document.querySelectorAll('label')]
      .find(l => l.querySelector('code')?.textContent === scope)!.querySelector('input') as HTMLInputElement

  test('a new token never ticks one, and its box is disabled with the reason', async () => {
    vi.stubGlobal('fetch', mockFetch({
      tokens: { tokens: [], features: { agentInTheLoop: false }, ungrantableScopes: { 'kali:exec': ['agent:kali_exec'] } },
    }))
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))

    expect(box('recon:read').checked).toBe(true)
    expect(box('kali:exec').checked).toBe(false)
    expect(box('kali:exec').disabled).toBe(true)
    expect(box('kali:exec').closest('label')!.textContent).toContain('agent:kali_exec')
  })

  test('without limits (switch off) the default ticks are today\'s', async () => {
    vi.stubGlobal('fetch', mockFetch({ tokens: { tokens: [] } }))
    render(<McpTokensTab userId="owner" />)
    await waitFor(() => expect(screen.getByText('New token').closest('button')).not.toBeDisabled())
    fireEvent.click(screen.getByText('New token'))

    expect(box('kali:exec').checked).toBe(true)
    expect(box('kali:exec').disabled).toBe(false)
    expect(screen.queryByText(/limited by your permissions/i)).toBeNull()
  })
})
