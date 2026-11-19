/**
 * The URLScan key says both of its readers.
 *
 * The agent's execute_gau receives the key for gau's URLScan source, and the
 * project's Tool Matrix and the chat drawer both ask for it on that tool's
 * behalf. The Global Settings field said "Recon Pipeline" only, so a user who
 * set it for the agent was told it did nothing there.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams('tab=keys'),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/settings',
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))

// The real hook throws outside <AlertProvider>; mock the deep path and the barrel.
const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))

const SettingsPage = (await import('./page')).default

function stubFetch() {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const json = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
    if (url === '/api/users/user-1/settings') return json({ urlscanApiKey: '', rotationConfigs: {} })
    if (url === '/api/users/user-1/settings/api-usage') {
      return json({ enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] })
    }
    if (/\/(llm-providers|attack-skills|chat-skills|tradecraft-resources)$/.test(url) || url === '/api/projects') return json([])
    return { ok: false, status: 404, json: async () => ({}) }
  }))
}

describe('Settings > API Keys: URLScan', () => {
  test('the field is badged for the agent and the recon pipeline, and names execute_gau', async () => {
    stubFetch()
    render(<ToastProvider><SettingsPage /></ToastProvider>)
    const label = await screen.findByText('URLScan API Key')
    const group = label.closest('.formGroup') as HTMLElement
    expect(within(group).getByText('AI Agent')).toBeInTheDocument()
    expect(within(group).getByText('Recon Pipeline')).toBeInTheDocument()
    expect(group.textContent).toContain('execute_gau')
  })
})
