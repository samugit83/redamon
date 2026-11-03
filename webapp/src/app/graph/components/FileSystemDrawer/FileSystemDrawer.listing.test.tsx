/**
 * The agent caps a directory listing (2000 entries by default) and says how
 * many it left out; the drawer shows that, instead of pretending the folder is
 * complete.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { FileSystemDrawer } from './FileSystemDrawer'

vi.mock('@/components/ui/Drawer', () => ({
  Drawer: ({ children }: { children: React.ReactNode }) => <div data-testid="drawer">{children}</div>,
}))
vi.mock('@/components/ui', async (orig) => {
  const real = (await orig()) as Record<string, unknown>
  return {
    ...real,
    useAlertModal: () => ({
      alert: vi.fn(), alertError: vi.fn(), alertWarning: vi.fn(),
      confirm: vi.fn(async () => true), dangerConfirm: vi.fn(async () => true),
    }),
  }
})

let listBody: Record<string, unknown>

beforeEach(() => {
  listBody = { entries: [] }
  global.fetch = vi.fn(async (url: string | URL | Request) => {
    const u = String(url)
    if (u.includes('/api/agent/workspace/list')) return new Response(JSON.stringify(listBody), { status: 200 })
    if (u.includes('/api/agent/workspace/jobs')) return new Response(JSON.stringify({ jobs: [] }), { status: 200 })
    return new Response(JSON.stringify({ ok: true }), { status: 200 })
  }) as unknown as typeof fetch
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

const entry = (i: number) => ({
  name: `f${i}.txt`, path: `uploads/big/f${i}.txt`, isDir: false, isSymlink: false, size: 1,
  mtime: '2026-11-03T00:00:00+00:00',
})

describe('FileSystemDrawer truncated listing', () => {
  test('shows truncated notice with counts', async () => {
    listBody = { entries: [entry(1), entry(2), entry(3)], total: 12500, truncated: true }
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    const notice = await screen.findByRole('status')
    expect(notice.textContent).toMatch(/Showing the first 3 of 12,500 entries/)
    expect(notice.textContent).toMatch(/filter searches only the entries shown/)
  })

  test('no notice when the listing is complete', async () => {
    listBody = { entries: [entry(1)], total: 1, truncated: false }
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('f1.txt')).toBeTruthy())
    expect(screen.queryByText(/Showing the first/)).toBeNull()
  })

  test('an older agent without total still lists normally', async () => {
    listBody = { entries: [entry(1)] }
    render(<FileSystemDrawer isOpen={true} onClose={() => {}} projectId="p1" />)
    await waitFor(() => expect(screen.getByText('f1.txt')).toBeTruthy())
    expect(screen.queryByText(/Showing the first/)).toBeNull()
  })
})
