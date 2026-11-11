/**
 * The custom template manager says whose each template is (HD-08): "yours",
 * "instance", or, for an admin, the owner of another account's file. A member's
 * delete is disabled, with the reason, on a file they do not own; another account's
 * template cannot be checked into the project (the save would refuse it), though a
 * stored selection can still be cleared; an admin gets a "Make instance" control.
 *
 * Run: npx vitest run --no-file-parallelism src/components/projects/ProjectForm/sections/NucleiSection.ownership.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'

import { NucleiSection } from './NucleiSection'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const MINE = { id: 'mine', name: 'Mine', severity: 'low', file: 'mine.yaml', path: 'mine.yaml', size: 10, ownership: 'own' }
const SHIPPED = { id: 'shipped', name: 'Shipped', severity: 'high', file: 'shipped.yaml', path: 'shipped.yaml', size: 10, ownership: 'instance' }
const THEIRS = { id: 'theirs', name: 'Theirs', severity: 'info', file: 'theirs.yaml', path: 'theirs.yaml', size: 10, ownership: 'other', owner: 'member-b@e2e.local' }

let listing: { templates: unknown[]; canManageAll: boolean }
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === '/api/nuclei-templates' && !init?.method) return json(200, listing)
    if (url === '/api/nuclei-templates' && init?.method === 'PATCH') {
      listing = { ...listing, templates: listing.templates.map(t => ({ ...(t as object), ownership: 'instance', owner: undefined })) }
      return json(200, { ...listing, promoted: true })
    }
    return json(200, [])
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const mount = (selected: string[] = [], updateField = vi.fn()) => {
  render(<NucleiSection data={{ nucleiEnabled: true, nucleiSeverity: [], nucleiSelectedCustomTemplates: selected } as never} updateField={updateField as never} />)
  return updateField
}
const row = async (file: string) => (await screen.findByText(file.replace('.yaml', ''))).closest('div') as HTMLElement

describe('a member', () => {
  beforeEach(() => { listing = { templates: [MINE, SHIPPED], canManageAll: false } })

  test('sees "yours" and "instance" on the templates', async () => {
    mount()
    expect(await within(await row('mine.yaml')).findByText('· yours')).toBeInTheDocument()
    expect(within(await row('shipped.yaml')).getByText('· instance')).toBeInTheDocument()
  })

  test('deletes their own; delete is disabled with the reason on an instance template', async () => {
    mount()
    expect(await screen.findByTitle('Delete mine.yaml')).toBeEnabled()
    const blocked = screen.getByLabelText('Cannot delete shipped.yaml: Instance template: only an administrator can delete it')
    expect(blocked).toBeDisabled()
    expect(blocked).toHaveAttribute('title', 'Instance template: only an administrator can delete it')
    fireEvent.click(blocked)
    expect(fetchMock.mock.calls.some(c => String(c[0]).startsWith('/api/nuclei-templates?path='))).toBe(false)
  })

  test('selects an instance template like their own, and sees no promote control', async () => {
    const updateField = mount()
    fireEvent.click(await screen.findByLabelText('Use shipped.yaml in this project'))
    expect(updateField).toHaveBeenCalledWith('nucleiSelectedCustomTemplates', ['shipped.yaml'])
    expect(screen.queryByText('Make instance')).toBeNull()
  })
})

describe('an admin', () => {
  beforeEach(() => { listing = { templates: [MINE, SHIPPED, THEIRS], canManageAll: true } })

  test("sees another account's template with its owner, and may delete it", async () => {
    mount()
    expect(await within(await row('theirs.yaml')).findByText('· owner: member-b@e2e.local')).toBeInTheDocument()
    expect(screen.getByTitle('Delete theirs.yaml')).toBeEnabled()
    expect(screen.getByTitle('Delete shipped.yaml')).toBeEnabled()
  })

  test("cannot check another account's template into the project, but can clear a stored one", async () => {
    mount()
    const box = await screen.findByLabelText('Use theirs.yaml in this project')
    expect(box).toBeDisabled()
    cleanup()
    const updateField = mount(['theirs.yaml'])
    const stored = await screen.findByLabelText('Use theirs.yaml in this project')
    expect(stored).toBeEnabled()
    fireEvent.click(stored)
    expect(updateField).toHaveBeenCalledWith('nucleiSelectedCustomTemplates', [])
  })

  test('makes a template an instance template', async () => {
    mount()
    const theirs = await row('theirs.yaml')
    fireEvent.click(within(theirs).getByText('Make instance'))
    await waitFor(() => expect(fetchMock.mock.calls.some(c => c[1]?.method === 'PATCH')).toBe(true))
    const patch = fetchMock.mock.calls.find(c => c[1]?.method === 'PATCH')!
    expect(JSON.parse(String(patch[1].body))).toEqual({ path: 'theirs.yaml', promote: true })
    expect(await within(await row('theirs.yaml')).findByText('· instance')).toBeInTheDocument()
    // An instance template offers no promotion.
    expect(within(await row('shipped.yaml')).queryByText('Make instance')).toBeNull()
  })

  test('a deleted owner is named as such', async () => {
    listing = { templates: [{ ...THEIRS, owner: null }], canManageAll: true }
    mount()
    expect(await screen.findByText('· owner: deleted account')).toBeInTheDocument()
  })
})

test('an upload refused because the name is taken shows why', async () => {
  listing = { templates: [], canManageAll: false }
  fetchMock.mockImplementation(async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === '/api/nuclei-templates' && init?.method === 'POST') {
      return json(409, { error: 'A template named x.yaml already exists and belongs to another account. Rename your file or upload it to another folder.', code: 'template_owned_by_other' })
    }
    return json(200, listing)
  })
  const { container } = render(<NucleiSection data={{ nucleiEnabled: true, nucleiSeverity: [], nucleiSelectedCustomTemplates: [] } as never} updateField={vi.fn() as never} />)
  const input = container.querySelector('input[type="file"][accept=".yaml,.yml"]') as HTMLInputElement
  fireEvent.change(input, { target: { files: [new File(['id: x'], 'x.yaml')] } })
  expect(await screen.findByText(/belongs to another account\. Rename your file or upload it to another folder\. \(template_owned_by_other · HTTP 409\)/)).toBeInTheDocument()
})
