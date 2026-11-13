/**
 * The workspace drawer on a project shared with Raw data & files (step 4.11, UI-05): the collaborator
 * lists, previews and downloads the owner's files (workspace:read is `R*`) and changes none: upload,
 * new folder, clean all, rename, delete and the bulk delete are disabled with "Read access, shared by
 * <owner>", a note says so, and a drop uploads nothing. The owner's drawer is unchanged.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/FileSystemDrawer/FileSystemDrawer.readOnly.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
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

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ_RAW: MyAccess = { level: 'read', toggles: { rawData: true }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

let calls: string[]
beforeEach(() => {
  calls = []
  global.fetch = vi.fn(async (url: string | URL | Request) => {
    const u = String(url)
    calls.push(u)
    if (u.includes('/api/agent/workspace/list')) {
      return new Response(JSON.stringify({ entries: [
        { name: 'report.txt', path: 'notes/report.txt', isDir: false, isSymlink: false, size: 3, mtime: '2026-11-03T00:00:00+00:00' },
      ] }), { status: 200 })
    }
    if (u.includes('/api/agent/workspace/jobs')) return new Response(JSON.stringify({ jobs: [] }), { status: 200 })
    return new Response(JSON.stringify({ ok: true }), { status: 200 })
  }) as unknown as typeof fetch
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

function drawer(access: MyAccess | null) {
  return render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
      <FileSystemDrawer isOpen onClose={() => {}} projectId="p1" />
    </ProjectAccessContext.Provider>,
  )
}

describe('FileSystemDrawer at read with Raw data & files', () => {
  test('controls disabled with the reason at read; listing and download stay', async () => {
    drawer(READ_RAW)
    await screen.findByText('report.txt')
    expect(screen.getByRole('note')).toHaveTextContent(`${NOTICE}: you can open and download these files, not change them.`)
    const refused = screen.getAllByTitle(NOTICE) as HTMLButtonElement[]
    // New folder, upload, clean all, and the row's rename and delete.
    expect(refused.length).toBe(5)
    expect(refused.every(b => b.disabled)).toBe(true)
    expect(screen.queryByTitle('Delete')).toBeNull()
    expect(screen.queryByTitle('Rename')).toBeNull()
    expect((screen.getByTitle('Refresh') as HTMLButtonElement).disabled).toBe(false)
  })

  test('a drop is refused at read (the drag over is not accepted) and uploads nothing; the owner\'s is accepted', async () => {
    drawer(READ_RAW)
    await screen.findByText('report.txt')
    const before = calls.length
    const dataTransfer = { types: ['Files'], files: [new File(['x'], 'x.txt')], items: [], dropEffect: 'none' }
    const root = () => screen.getByTestId('drawer').firstElementChild as Element
    // fireEvent answers false when a handler prevented the default, which is how a drop is accepted.
    expect(fireEvent.dragOver(root(), { dataTransfer })).toBe(true)
    fireEvent.drop(root(), { dataTransfer })
    await new Promise(r => setTimeout(r, 0))
    expect(calls.slice(before).some(u => u.includes('/upload'))).toBe(false)
    cleanup()
    drawer(OWNS)
    await screen.findByText('report.txt')
    expect(fireEvent.dragOver(root(), { dataTransfer })).toBe(false)
  })

  test('owner unchanged, and switch off (no myAccess) unchanged', async () => {
    drawer(OWNS)
    await screen.findByText('report.txt')
    expect(screen.queryByRole('note')).toBeNull()
    expect((screen.getByTitle('Delete') as HTMLButtonElement).disabled).toBe(false)
    expect((screen.getByTitle('New folder in current directory') as HTMLButtonElement).disabled).toBe(false)
    cleanup()
    drawer(null)
    await screen.findByText('report.txt')
    expect((screen.getByTitle('Rename') as HTMLButtonElement).disabled).toBe(false)
  })
})
