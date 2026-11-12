/**
 * The Other Scans starts follow the viewer's permissions (step 3.16b, E2E-P3-01, UI-12): GitHub Hunt
 * and every TruffleHog source ask `scan:secrets`, the Supply-Chain start and its organisation batch
 * ask `scan:supply_chain` (route manifest). Without one, that card's Start (or Resume, or Queue org
 * batch) is disabled with the permission notice as its title, and the card shows the ForbiddenNotice.
 * The downloads and logs stay: they ask `recon:read`. With the permissions switch off the modal is as
 * before (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/OtherScansModal/OtherScansModal.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { forbiddenNoticeText } from '@/components/auth/ForbiddenNotice'
import type { GithubHuntStatus, SupplyChainStatus } from '@/lib/recon-types'

vi.mock('@/components/ui', async (orig) => ({
  ...(await orig<typeof import('@/components/ui')>()),
  useToast: () => ({ success: vi.fn(), info: vi.fn(), error: vi.fn(), warning: vi.fn() }),
  Modal: ({ isOpen, children }: { isOpen: boolean; children: React.ReactNode }) => (isOpen ? <div>{children}</div> : null),
  WikiInfoButton: () => null,
}))
vi.mock('@/components/ui/AlertModal/AlertModal', () => ({ useAlertModal: () => ({ alertError: vi.fn() }) }))

const supplyChain = vi.hoisted(() => ({ source: 'upload' as 'upload' | 'org', org: '' }))
vi.mock('./useSupplyChainConfig', () => ({
  useSupplyChainConfig: () => ({
    source: supplyChain.source, sbomFile: 'package-lock.json', repoUrl: '', repoRef: '', org: supplyChain.org,
    loading: false, error: null, ready: true, target: supplyChain.org || 'package-lock.json', reload: () => {},
  }),
}))

import { OtherScansModal } from './OtherScansModal'

const handlers = {
  onStartGithubHunt: vi.fn(), onResumeGithubHunt: vi.fn(), onStartTrufflehog: vi.fn(),
  onStartSupplyChain: vi.fn(), onResumeSupplyChain: vi.fn(),
}
const PROFILES = [
  { id: 'p-docker', source: 'docker', label: '', config: { images: ['nginx:1.25'] } },
  { id: 'p-github', source: 'github', label: '', config: { orgs: ['acme'] } },
]

beforeEach(() => {
  supplyChain.source = 'upload'
  supplyChain.org = ''
  vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({}) })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

function modal(value: AuthContextValue | null, status: { gh?: GithubHuntStatus; sc?: SupplyChainStatus } = {}) {
  return render(
    <AuthContext.Provider value={value}>
      <OtherScansModal
        isOpen onClose={() => {}} projectId="p1" hasReconData hasGithubToken
        githubHuntStatus={status.gh ?? 'idle'} supplyChainStatus={status.sc ?? 'idle'}
        trufflehogProfiles={PROFILES} trufflehogRunsBySource={{}}
        hasGithubHuntData hasTrufflehogData hasSupplyChainData
        {...handlers}
      />
    </AuthContext.Provider>,
  )
}

const card = (title: string) => screen.getByRole('heading', { name: title }).closest('.card') as HTMLElement
const buttons = (scope: HTMLElement, label: string) =>
  within(scope).getAllByRole('button').filter(b => b.textContent?.includes(label)) as HTMLButtonElement[]

describe('Other Scans starts and the viewer permissions', () => {
  test('switch on, Read-only analyst: every Start disabled with its notice, and each card says why', () => {
    modal(fakeAuth(FLAGS_ON, ['recon:read', 'graph:read']))
    const github = card('GitHub Secret Hunt')
    const truffle = card('Secret Multiscanner')
    const supply = card('Supply Chain Scanner')
    for (const [scope, permission, starts] of [
      [github, 'scan:secrets', 1], [truffle, 'scan:secrets', PROFILES.length], [supply, 'scan:supply_chain', 1],
    ] as const) {
      const found = buttons(scope, 'Start')
      expect(found).toHaveLength(starts)
      for (const b of found) {
        expect(b.disabled).toBe(true)
        expect(b.title).toBe(forbiddenNoticeText(permission))
        fireEvent.click(b)
      }
      expect(within(scope).getByRole('alert')).toHaveTextContent(permission)
    }
    expect(handlers.onStartGithubHunt).not.toHaveBeenCalled()
    expect(handlers.onStartTrufflehog).not.toHaveBeenCalled()
    expect(handlers.onStartSupplyChain).not.toHaveBeenCalled()
  })

  test('switch on: the downloads stay (they ask recon:read)', () => {
    modal(fakeAuth(FLAGS_ON, ['recon:read']))
    const downloads = screen.getAllByRole('button').filter(b => b.textContent?.includes('Download')) as HTMLButtonElement[]
    expect(downloads).toHaveLength(3)
    for (const b of downloads) expect(b.disabled).toBe(false)
  })

  test('switch on: a paused GitHub Hunt or Supply-Chain scan cannot be resumed without its permission', () => {
    modal(fakeAuth(FLAGS_ON, ['recon:read']), { gh: 'paused', sc: 'paused' })
    const [ghResume] = buttons(card('GitHub Secret Hunt'), 'Resume')
    const [scResume] = buttons(card('Supply Chain Scanner'), 'Resume')
    expect(ghResume.disabled).toBe(true)
    expect(ghResume.title).toBe(forbiddenNoticeText('scan:secrets'))
    expect(scResume.disabled).toBe(true)
    expect(scResume.title).toBe(forbiddenNoticeText('scan:supply_chain'))
  })

  test('switch on: the organisation batch asks scan:supply_chain too', () => {
    supplyChain.source = 'org'
    supplyChain.org = 'acme'
    modal(fakeAuth(FLAGS_ON, ['recon:read', 'scan:secrets']))
    const [batch] = buttons(card('Supply Chain Scanner'), 'Queue org batch')
    expect(batch.disabled).toBe(true)
    expect(batch.title).toBe(forbiddenNoticeText('scan:supply_chain'))
    fireEvent.click(batch)
    expect(fetch).not.toHaveBeenCalledWith('/api/projects/p1/supply-chain-batch', expect.anything())
  })

  test('switch on: each card follows its own permission', () => {
    modal(fakeAuth(FLAGS_ON, ['recon:read', 'scan:secrets']))
    for (const b of [...buttons(card('GitHub Secret Hunt'), 'Start'), ...buttons(card('Secret Multiscanner'), 'Start')]) {
      expect(b.disabled).toBe(false)
    }
    expect(within(card('GitHub Secret Hunt')).queryByRole('alert')).toBeNull()
    expect(buttons(card('Supply Chain Scanner'), 'Start')[0].disabled).toBe(true)
    fireEvent.click(buttons(card('Secret Multiscanner'), 'Start')[0])
    expect(handlers.onStartTrufflehog).toHaveBeenCalledWith('docker')
  })

  test('switch off, an empty set: every Start as before, no notice (DV-30)', () => {
    modal(fakeAuth(FLAGS_OFF, []))
    for (const b of screen.getAllByRole('button').filter(x => x.textContent?.includes('Start')) as HTMLButtonElement[]) {
      expect(b.disabled).toBe(false)
    }
    expect(screen.queryByText('You do not have the permission this needs.')).toBeNull()
    fireEvent.click(buttons(card('GitHub Secret Hunt'), 'Start')[0])
    expect(handlers.onStartGithubHunt).toHaveBeenCalledTimes(1)
  })
})
