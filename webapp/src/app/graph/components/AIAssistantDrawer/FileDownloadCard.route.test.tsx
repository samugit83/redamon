/**
 * The owner's in-chat download card, end to end on the webapp side (4.9 review, finding 6): the
 * card the agent emits (tests/fixtures/download_card/owner_card.json, which
 * agentic/tests/test_download_card_workspace.py proves the agent produces and serves) runs
 * through the real /api/agent/files route to the agent's project-scoped /workspace/download.
 * Only the project guard and the agent's answer are doubled.
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react'
import { NextRequest, NextResponse } from 'next/server'

const mockGuardProject = vi.fn()
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProjectOrCapability()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuardProject(...a) }))

import { GET } from '@/app/api/agent/files/route'
import { FileDownloadCard } from './FileDownloadCard'

interface OwnerCard {
  project_id: string
  file_ready: { filepath: string; filename: string; source: string; description: string; projectId: string }
  agent_download_path: string
}

const CARD = JSON.parse(readFileSync(
  path.resolve(__dirname, '../../../../../../tests/fixtures/download_card/owner_card.json'), 'utf8',
)) as OwnerCard
const PAYLOAD = 'MZ-payload-bytes'

let agentCalls: string[]
let saved: { download: string; blob: Blob }[]

beforeEach(() => {
  agentCalls = []
  saved = []
  mockGuardProject.mockReset()
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    const u = String(url)
    if (u.startsWith('/api/agent/files')) return GET(new NextRequest(`http://localhost${u}`))
    agentCalls.push(u)
    return new Response(PAYLOAD, { status: 200, headers: { 'Content-Type': 'application/octet-stream' } })
  }))
  let lastBlob: Blob | null = null
  URL.createObjectURL = vi.fn((b: Blob) => { lastBlob = b; return 'blob:mock' })
  URL.revokeObjectURL = vi.fn()
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    saved.push({ download: this.download, blob: lastBlob as Blob })
  })
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

const renderCard = (overrides: Partial<OwnerCard['file_ready']> = {}) => {
  const f = { ...CARD.file_ready, ...overrides }
  return render(<FileDownloadCard filepath={f.filepath} filename={f.filename} description={f.description}
    source={f.source} projectId={f.projectId} />)
}

describe('the owner downloads the file the agent offered', () => {
  test('the card reaches the agent\'s project workspace download and saves the bytes', async () => {
    mockGuardProject.mockResolvedValue(null)
    renderCard()
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(saved).toHaveLength(1))
    expect(mockGuardProject).toHaveBeenCalledWith(CARD.project_id)
    expect(agentCalls).toHaveLength(1)
    expect(agentCalls[0].endsWith(CARD.agent_download_path)).toBe(true)
    expect(saved[0].download).toBe(CARD.file_ready.filename)
    expect(await saved[0].blob.text()).toBe(PAYLOAD)
  })

  test('a person who cannot read the project gets the refusal, and the agent is not called', async () => {
    mockGuardProject.mockResolvedValue(NextResponse.json({ error: 'Project not found' }, { status: 404 }))
    renderCard()
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(screen.getByText(/Project not found/)).toBeTruthy())
    expect(agentCalls).toHaveLength(0)
    expect(saved).toHaveLength(0)
  })

  test('a card whose path sits in another project\'s workspace is refused before the agent', async () => {
    mockGuardProject.mockResolvedValue(null)
    renderCard({ filepath: '/workspace/proj-other/notes/payload.exe' })
    fireEvent.click(screen.getByTitle('Download file'))
    await waitFor(() => expect(screen.getByText(/outside this project's workspace/)).toBeTruthy())
    expect(agentCalls).toHaveLength(0)
  })
})
