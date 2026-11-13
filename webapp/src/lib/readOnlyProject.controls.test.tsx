/**
 * Every control of a shared project's screens that its route would refuse a read collaborator is
 * disabled with "Read access, shared by <owner>" (step 4.11, UI-05, P4-03), and the owner sees the
 * same controls as before. The step 3.16b gates (empty graph, recon dialog, agent drawer, Workflow
 * play) read the level through the same hooks; the rest are the stops of a running scan or triage
 * run, the Priority Board's mutes, the version manager, the scan schedules and the workspace upload.
 * The provider of the level is ProjectAccessContext, which ProjectProvider fills from the project
 * read (readOnlyProject.test.tsx covers the provider and the poll).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/readOnlyProject.controls.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import type { NodeProps } from '@xyflow/react'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { ProjectAccessContext } from '@/providers/projectAccessContext'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider, ToastProvider } from '@/components/ui'

vi.mock('@xyflow/react', () => ({ Handle: () => null, Position: { Left: 'left', Right: 'right' } }))
vi.mock('@/app/graph/components/AIAssistantDrawer/AIAssistantDrawer', () => ({
  AIAssistantDrawer: () => <div data-testid="chat">chat</div>,
}))

import { GraphEmptyState } from '@/app/graph/components/GraphEmptyState/GraphEmptyState'
import { ReconConfirmModal } from '@/app/graph/components/ReconConfirmModal/ReconConfirmModal'
import { AgentDrawer } from '@/app/graph/components/AIAssistantDrawer/AgentDrawer'
import { ToolNode } from '@/components/projects/ProjectForm/WorkflowView/ToolNode'
import { PartialReconBadges } from '@/components/PartialReconBadges/PartialReconBadges'
import { TriageRunButton } from '@/components/triage/TriageRunButton'
import { TriageRunBanner } from '@/components/triage/TriageRunBanner'
import { MuteNodeProvider, GraphNodeMuteButton } from '@/app/graph/components/MuteNode'
import { VersionManager } from '@/app/graph/components/VersionManager/VersionManager'
import { UploadMenu } from '@/app/graph/components/FileSystemDrawer/UploadMenu'
import type { PartialReconState } from '@/lib/recon-types'

const OWNER = { name: 'Alice', email: 'alice@e2e.local' }
const READ: MyAccess = { level: 'read', toggles: { rawData: false }, via: 'share', owner: OWNER }
const OWNS: MyAccess = { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: OWNER }
const NOTICE = 'Read access, shared by Alice (alice@e2e.local)'

// Every permission these controls ask, so only the level can refuse.
const HELD = [
  'recon:scan', 'recon:overwrite', 'recon:partial', 'agent:chat', 'triage:run', 'triage:mute',
  'scan:versions', 'scan:versions_delete', 'workspace:write',
] as const

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false, status: 404, json: async () => ({}) }) as unknown as Response))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function within(access: MyAccess | null, children: ReactNode) {
  return render(
    <AuthContext.Provider value={fakeAuth(FLAGS_ON, [...HELD])}>
      <ProjectAccessContext.Provider value={{ projectId: 'p1', myAccess: access }}>
        <ToastProvider><AlertProvider>{children}</AlertProvider></ToastProvider>
      </ProjectAccessContext.Provider>
    </AuthContext.Provider>,
  )
}

const buttonByText = (label: string) =>
  screen.getAllByRole('button').find(b => b.textContent?.includes(label)) as HTMLButtonElement

describe('the step 3.16b gates read the level', () => {
  test('controls disabled with the reason at read: the empty graph\'s start, with the read notice', () => {
    const onStart = vi.fn()
    within(READ, <GraphEmptyState state="start" onStartRecon={onStart} onResumeRecon={vi.fn()} />)
    const start = buttonByText('Start Recon Pipeline')
    expect(start.disabled).toBe(true)
    expect(start.title).toBe(NOTICE)
    expect(screen.getByRole('status')).toHaveTextContent(`${NOTICE}.`)
    expect(screen.queryByText(/You do not have the permission/)).toBeNull()
  })

  test('the recon dialog\'s Overwrite, with the read notice', () => {
    within(READ, <ReconConfirmModal isOpen onClose={() => {}} onConfirm={vi.fn()} projectName="Acme" targetDomain="acme.tld"
      isLoading={false} stats={{ totalNodes: 3, nodesByType: { IP: 3 } }} />)
    const overwrite = (screen.getAllByRole('radio') as HTMLInputElement[]).find(r => r.value === 'overwrite')!
    expect(overwrite.disabled).toBe(true)
    expect(overwrite.closest('label')?.title).toBe(NOTICE)
  })

  test('the agent drawer holds the read notice and no chat', () => {
    within(READ, <AgentDrawer isOpen onClose={() => {}} projectId="p1" userId="bob" sessionId="s1" onResetSession={() => 's2'} />)
    expect(screen.queryByTestId('chat')).toBeNull()
    expect(screen.getByRole('status')).toHaveTextContent(`${NOTICE}.`)
  })

  test('the Workflow play, with the read notice', () => {
    const onRunPartial = vi.fn()
    const data = {
      toolId: 'Naabu', label: 'Naabu', enabled: true, enabledField: 'naabuEnabled', group: 3, chainBroken: false,
      starvedInputs: [], groupColor: '#888', onRunPartial, onNodeClick: vi.fn(), partialReconSupported: true,
    }
    within(READ, <ToolNode {...({ id: 'tool-Naabu', data } as unknown as NodeProps)} />)
    const play = screen.getByTitle(NOTICE)
    expect(play.getAttribute('aria-disabled')).toBe('true')
    fireEvent.click(play)
    expect(onRunPartial).not.toHaveBeenCalled()
  })

  test('owner unchanged: the same controls enabled, the chat mounted', () => {
    within(OWNS, <>
      <GraphEmptyState state="start" onStartRecon={vi.fn()} onResumeRecon={vi.fn()} />
      <AgentDrawer isOpen onClose={() => {}} projectId="p1" userId="bob" sessionId="s1" onResetSession={() => 's2'} />
    </>)
    expect(buttonByText('Start Recon Pipeline').disabled).toBe(false)
    expect(screen.getByTestId('chat')).toBeTruthy()
  })
})

describe('the stops of the owner\'s running work', () => {
  const run: PartialReconState = {
    project_id: 'p1', run_id: 'r1', tool_id: 'Naabu', status: 'running', container_id: null,
    started_at: null, completed_at: null, error: null, stats: null,
  }

  test('controls disabled with the reason at read: a partial recon\'s stop', () => {
    const onStop = vi.fn()
    within(READ, <PartialReconBadges activePartialRecons={[run]} onToggleLogs={vi.fn()} onStop={onStop} />)
    const stop = screen.getByTitle(NOTICE) as HTMLButtonElement
    expect(stop.disabled).toBe(true)
    expect((screen.getByTitle('View Logs') as HTMLButtonElement).disabled).toBe(false)
  })

  test('the triage run button and the running banner\'s Stop', () => {
    within(READ, <>
      <TriageRunButton projectId="p1" onConfirm={vi.fn()} />
      <TriageRunBanner projectId="p1" label="Priority Board running" phase={null} onStop={vi.fn()} />
    </>)
    expect(buttonByText('Start Triage').disabled).toBe(true)
    expect(buttonByText('Start Triage').title).toBe(NOTICE)
    expect(buttonByText('Stop').disabled).toBe(true)
    expect(buttonByText('Stop').title).toBe(NOTICE)
  })

  test('owner unchanged', () => {
    within(OWNS, <>
      <PartialReconBadges activePartialRecons={[run]} onToggleLogs={vi.fn()} onStop={vi.fn()} />
      <TriageRunButton projectId="p1" onConfirm={vi.fn()} />
    </>)
    expect((screen.getByTitle('Stop') as HTMLButtonElement).disabled).toBe(false)
    expect(buttonByText('Start Triage').disabled).toBe(false)
  })
})

describe('mutes, versions and uploads', () => {
  const node = { id: '42', name: 'CVE-1', type: 'Vulnerability', properties: { id: 'v1' } }

  test('controls disabled with the reason at read: a mute says whose read access it is (not "saved version")', () => {
    within(READ, (
      <MuteNodeProvider projectId="p1" readOnly readOnlyReason={NOTICE}>
        <GraphNodeMuteButton node={node as never} />
      </MuteNodeProvider>
    ))
    const mutes = screen.getAllByTitle(NOTICE) as HTMLButtonElement[]
    expect(mutes.length).toBeGreaterThanOrEqual(1)
    expect(mutes.every(b => b.disabled)).toBe(true)
  })

  test('a saved version keeps its own reason', () => {
    within(OWNS, (
      <MuteNodeProvider projectId="p1" readOnly>
        <GraphNodeMuteButton node={node as never} />
      </MuteNodeProvider>
    ))
    expect(screen.getAllByTitle(/You are viewing a saved version/).length).toBeGreaterThanOrEqual(1)
  })

  const versions = [
    { id: 'v-cur', label: 'Current', isCurrent: true, activatable: true, pinned: false, createdAt: '2026-11-01T00:00:00Z', updatedAt: '2026-11-01T00:00:00Z' },
    { id: 'v-old', label: 'Old', isCurrent: false, activatable: true, pinned: false, createdAt: '2026-10-01T00:00:00Z', updatedAt: '2026-10-01T00:00:00Z' },
  ]

  test('the version manager views versions only', () => {
    within(READ, <VersionManager isOpen onClose={() => {}} projectId="p1" versions={versions as never} onChanged={vi.fn()}
      selectedVersionId={null} onSelectVersion={vi.fn()} />)
    for (const label of ['Save current graph as a version', 'Activate', 'Rename', 'Pin', 'Delete']) {
      const b = buttonByText(label)
      expect(b.disabled).toBe(true)
    }
    const old = screen.getAllByRole('button').filter(b => b.textContent?.includes('Delete')).at(-1) as HTMLButtonElement
    expect(old.title).toBe(NOTICE)
    expect(screen.getAllByRole('button').some(b => b.textContent?.includes('View') && !(b as HTMLButtonElement).disabled)).toBe(true)
  })

  test('owner unchanged: the version manager', () => {
    within(OWNS, <VersionManager isOpen onClose={() => {}} projectId="p1" versions={versions as never} onChanged={vi.fn()}
      selectedVersionId={null} onSelectVersion={vi.fn()} />)
    expect(buttonByText('Save current graph as a version').disabled).toBe(false)
  })

  test('the workspace upload control, disabled with the reason', () => {
    const onFiles = vi.fn()
    render(<UploadMenu onFiles={onFiles} onFolder={vi.fn()} onArchive={vi.fn()} onImportUrl={vi.fn()} disabledReason={NOTICE} />)
    const upload = screen.getByRole('button', { name: 'Upload' }) as HTMLButtonElement
    expect(upload.disabled).toBe(true)
    expect(upload.title).toBe(NOTICE)
    expect(screen.queryByRole('button', { name: 'Upload options' })).toBeNull()
    cleanup()
    render(<UploadMenu onFiles={onFiles} onFolder={vi.fn()} onArchive={vi.fn()} onImportUrl={vi.fn()} />)
    expect((screen.getByTitle('Upload file(s) to current directory') as HTMLButtonElement).disabled).toBe(false)
  })
})
