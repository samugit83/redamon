/**
 * The settings page loads the Secret Multiscanner credentials into its state.
 *
 * The settings GET returns them masked, like every key. The page used to copy
 * a fixed list of fields out of that answer and none of them was a
 * `trufflehog*` column, so the Secret Multiscanner drawer said "0 of 19 keys
 * set" for a user who had saved one, and the API usage inventory never saw them.
 * Only the whole page shows this: the drawer renders whatever state it is given.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { TRUFFLEHOG_KEY_FIELDS } from '@/lib/credentialFields'

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

/** The settings GET as a browser caller gets it: every secret masked to its last 4. */
function settingsAnswer(): Record<string, unknown> {
  return {
    ...Object.fromEntries(TRUFFLEHOG_KEY_FIELDS.map(f => [f.name, ''])),
    trufflehogGithubToken: '••••••••AB12',
    shodanApiKey: '',
    rotationConfigs: {},
  }
}

function stubFetch() {
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    const json = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
    if (url === '/api/users/user-1/settings') return json(settingsAnswer())
    if (url === '/api/users/user-1/settings/api-usage') {
      return json({ enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] })
    }
    if (/\/(llm-providers|attack-skills|chat-skills|tradecraft-resources)$/.test(url) || url === '/api/projects') return json([])
    return { ok: false, status: 404, json: async () => ({}) }
  }))
}

describe('Settings > API Keys: Secret Multiscanner drawer', () => {
  test('a saved (masked) Multiscanner key counts as set', async () => {
    stubFetch()
    render(<ToastProvider><SettingsPage /></ToastProvider>)
    const drawer = await screen.findByText('Secret Multiscanner')
    const section = drawer.closest('section')!
    expect(await within(section).findByText(`1 of ${TRUFFLEHOG_KEY_FIELDS.length} keys set`)).toBeInTheDocument()
  })
})
