/**
 * The RedAmon Terminal tab on a shared project (step 4.11): the terminal's ticket asks the owner
 * level of the open project (step 4.3, the kali-terminal branch of POST /api/agent/ws-ticket answers
 * 403 owner_only to anyone else), so a project reached through a share never offers it, even to a
 * holder of platform:kali_terminal. The owner's tab, and the tab with RBAC_SHARING_ENABLED off (no
 * `myAccess`), are as before.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/ViewTabs/ViewTabs.readOnly.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { ProjectAccessContext } from '@/providers/projectAccessContext'

vi.mock('../GraphCanvas', () => ({ AUTO_2D_THRESHOLD: 5000 }))
vi.mock('@/components/ui', () => ({ Toggle: () => null }))
vi.mock('@/hooks/useCan', () => ({
  useCan: (p: string) => p === 'platform:kali_terminal',
  useRbacFlags: () => ({ sharedToolsCompat: false, identity: true, permissions: true, sharing: true, sharingWrite: false, governance: false }),
}))

import { ViewTabs } from './ViewTabs'

afterEach(() => cleanup())

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ_RAW: MyAccess = { level: 'read', toggles: { rawData: true }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }

function tabs(access: MyAccess | null) {
  render(
    <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
      <ViewTabs activeView="graph" onViewChange={vi.fn()} />
    </ProjectAccessContext.Provider>,
  )
  return screen.queryByRole('tab', { name: /RedAmon Terminal/ })
}

describe('the RedAmon Terminal tab and the project level', () => {
  test('a shared project never offers it, even with Raw data & files and the permission', () => {
    expect(tabs(READ_RAW)).toBeNull()
    expect(screen.getByRole('tab', { name: /Reverse Shell/ })).toBeInTheDocument()
  })

  test('owner unchanged, and switch off (no myAccess) unchanged', () => {
    expect(tabs(OWNS)).not.toBeNull()
    cleanup()
    expect(tabs(null)).not.toBeNull()
  })
})
