/**
 * The Instance page (step 6.7, GV-08, UI-04, SH-21 UI; DV-06, DV-19). Inside the admin console
 * (governance on), one panel per group, each shown to whoever holds it:
 *   - the security policy, the public address, the sharing policy and the default member set: every
 *     administrator reads them, only the confirmed Root changes them, with its password (the step-up
 *     dialog); a Full admin gets no control and nothing is sent ("Root-only fields refused to Full
 *     admin"); Root's save sends exactly the changed fields ("values saved");
 *   - the tunnel's editor (the tunnel push is the route's: instance-settings/route.test.ts "tunnel
 *     push called"); TrafficMind's summary, dialog and link; the Nuclei templates' list, promote and
 *     delete, each confirmed through useAlertModal;
 *   - loading, error with Retry, a refused route, and a member who kept a platform tool from before
 *     the upgrade, told why the console shows them this page.
 * Audit rows are the routes' (instance-settings route.test.ts / route.securityPolicy.test.ts
 * "audited by field name", permissionSetAdmin's `instance.default_member_set_changed`,
 * nuclei-templates route.ownership.test.ts).
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/instance/page.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import type { AuthContextValue, AuthUser } from '@/providers/AuthProvider'
import { BUILTIN_ADMIN_PROFILES } from '@/lib/authz/builtinSets'
import { PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { ToastProvider } from '@/components/ui/Toast/Toast'

vi.mock('next/navigation', () => ({
  usePathname: () => '/admin/instance',
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
const alerts = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async (orig) => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alerts }))
vi.mock('@/components/ui', async (orig) => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alerts }))
const modal = vi.hoisted(() => ({ props: null as null | { isOpen: boolean; userId: string | null; onClose: () => void } }))
vi.mock('@/components/traffic/TrafficMindSettingsModal', () => ({
  TrafficMindSettingsModal: (p: { isOpen: boolean; userId: string | null; onClose: () => void }) => {
    modal.props = p
    return p.isOpen ? <div role="dialog" aria-label="TrafficMind settings"><button type="button" onClick={p.onClose}>Close</button></div> : null
  },
}))

import InstancePage from './page'

const FLAGS_GOV = { ...FLAGS_ON, governance: true }
const FULL_ADMIN = BUILTIN_ADMIN_PROFILES.find((s) => s.id === 'builtin:full-admin')!.permissions
const EVERYTHING = PERMISSION_IDS

const POLICY = {
  passwordMinLength: 12, passwordAskChangeIfShort: false, memberSessionTtlHours: 168, adminSessionTtlHours: 12,
  adminIdleMinutes: 60, inviteTtlHours: 168, resetTtlHours: 4, impersonationMaxMinutes: 720,
  impersonationReasonRequired: false, impersonationNotifyTarget: true, publicBaseUrl: null,
}
const SHARING = { enabled: false, maxLevel: 'write', membersMayGrantExploit: false, defaultExpiryDays: null, adminsSeeAllShares: true }
const CAPTURE = {
  captureProxyEnabled: true, captureProxyPort: 8888, captureProxyScope: 'both', captureProxyRetentionDays: 14,
  captureEgressBlockPrivate: true, captureEgressBlockLinkLocal: true, captureEgressFailClosed: true,
}
const TUNNEL = { tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }

function settingsFor(root: boolean, extra: Record<string, unknown> = {}) {
  return {
    ...TUNNEL, ...CAPTURE, canManageTunnels: true, canManageCapture: true,
    securityPolicy: { ...POLICY }, canManageSecurityPolicy: root, ...extra,
  }
}

type Answer = { status: number; body: unknown }
let routes: Record<string, Answer | ((init?: RequestInit, url?: string) => Answer)>
let fetchMock: ReturnType<typeof vi.fn>
const calls = (method: string, prefix: string) =>
  fetchMock.mock.calls.filter(([url, init]) => (init?.method ?? 'GET') === method && String(url).startsWith(prefix))
const bodyOf = (call: unknown[]) => JSON.parse(String((call[1] as RequestInit).body))

const TEMPLATES = [
  { id: 'aem-json', name: 'AEM JSON exposure', severity: 'medium', file: 'aem.yaml', path: 'aem.yaml', size: 10, ownership: 'instance' },
  { id: 'mine', name: 'Mine', severity: 'low', file: 'm.yaml', path: 'team/m.yaml', size: 10, ownership: 'other', owner: 'mem-a@e2e.local' },
]

beforeEach(() => {
  vi.clearAllMocks()
  modal.props = null
  alerts.confirm.mockResolvedValue(true)
  alerts.dangerConfirm.mockResolvedValue(true)
  routes = {
    'GET /api/admin/instance-settings': { status: 200, body: settingsFor(false) },
    'GET /api/admin/permission-sets': {
      status: 200,
      body: {
        kind: 'member', instanceDefaultSetId: null,
        sets: [
          { id: 'builtin:default-member', name: 'Default member', description: null, builtin: true, holders: 3 },
          { id: 'builtin:red-team-operator', name: 'Red team operator', description: null, builtin: true, holders: 0 },
        ],
      },
    },
    'GET /api/nuclei-templates': { status: 200, body: { templates: TEMPLATES, canManageAll: true } },
    'GET /api/agent/tunnel-status': { status: 200, body: {} },
  }
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    const path = String(url).split('?')[0]
    const key = `${init?.method ?? 'GET'} ${path}`
    const a = routes[key]
    if (!a) return new Response(JSON.stringify({ error: `unexpected ${key}` }), { status: 500 })
    const { status, body } = typeof a === 'function' ? a(init, String(url)) : a
    return new Response(JSON.stringify(body), { status })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function auth(held: readonly PermissionId[], accountType: AuthUser['accountType']): AuthContextValue {
  const base = fakeAuth(FLAGS_GOV, [...held])
  return { ...base, user: { ...base.user!, id: 'u-1', role: accountType === 'member' ? 'standard' : 'admin', accountType } }
}

function renderPage(a: AuthContextValue) {
  return render(
    <AuthContext.Provider value={a}>
      <ToastProvider><InstancePage /></ToastProvider>
    </AuthContext.Provider>,
  )
}

const region = (name: string) => screen.getByRole('region', { name })

async function confirmWithPassword(password = 'root-password') {
  const field = await screen.findByLabelText('Your password')
  fireEvent.change(field, { target: { value: password } })
  const dialog = field.closest('form')!
  fireEvent.submit(dialog)
}

describe('states', () => {
  test('loading, then the panels', async () => {
    renderPage(auth(FULL_ADMIN, 'admin'))
    expect(screen.getByRole('status')).toHaveTextContent('Loading the instance settings')
    expect(await screen.findByRole('region', { name: 'Security policy' })).toBeInTheDocument()
  })

  test('a failed read: the error with its cause, and Retry reads again', async () => {
    routes['GET /api/admin/instance-settings'] = { status: 503, body: { error: 'not ready', code: 'instance_settings_unavailable' } }
    renderPage(auth(FULL_ADMIN, 'admin'))
    expect(await screen.findByRole('alert')).toHaveTextContent("Couldn't load the instance settings (instance_settings_unavailable · HTTP 503)")
    routes['GET /api/admin/instance-settings'] = { status: 200, body: settingsFor(false) }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('region', { name: 'Security policy' })).toBeInTheDocument()
  })

  test('a member who kept platform:kali_terminal: the route refuses the settings, the page says why and where', async () => {
    routes['GET /api/admin/instance-settings'] = { status: 403, body: { error: 'no', code: 'forbidden', permission: 'platform:tunnels' } }
    renderPage(auth(['platform:kali_terminal'], 'member'))
    const panel = await screen.findByRole('region', { name: 'Platform tools used elsewhere' })
    expect(within(panel).getByRole('note')).toHaveTextContent('Your account is a member account. It sees this page because it holds a platform permission as a personal override, for example one kept from before the upgrade.')
    expect(panel).toHaveTextContent('platform:kali_terminal: The raw Kali terminal is the RedAmon Terminal tab')
    expect(within(panel).getByRole('link', { name: 'Open your projects' })).toHaveAttribute('href', '/projects')
    expect(screen.queryByRole('region', { name: 'Security policy' })).toBeNull()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(calls('GET', '/api/nuclei-templates')).toHaveLength(0)
  })

  test('the section list is a labelled navigation of anchors to each panel', async () => {
    renderPage(auth(FULL_ADMIN, 'admin'))
    const nav = await screen.findByRole('navigation', { name: 'Instance sections' })
    expect(within(nav).getByRole('link', { name: 'Tunnel' })).toHaveAttribute('href', '#tunnels')
    expect(document.getElementById('tunnels')).toHaveAttribute('aria-labelledby', 'tunnels-title')
  })
})

describe('Root-only fields refused to Full admin', () => {
  test('the security policy, public address and default set read only, with no control and no write', async () => {
    renderPage(auth(FULL_ADMIN, 'admin'))
    const security = await screen.findByRole('region', { name: 'Security policy' })
    expect(within(security).getByText('Minimum password length')).toBeInTheDocument()
    expect(within(security).getByText('12 characters')).toBeInTheDocument()
    expect(within(security).queryByRole('textbox')).toBeNull()
    expect(within(security).queryByRole('button')).toBeNull()
    expect(within(security).getByRole('note')).toHaveTextContent('Only Root changes these settings.')
    expect(within(region('Public address')).queryByRole('textbox')).toBeNull()
    const defaults = region('Defaults for new members')
    expect(await within(defaults).findByText('Default member')).toBeInTheDocument()
    expect(within(defaults).queryByRole('combobox')).toBeNull()
    expect(calls('PUT', '/api/')).toHaveLength(0)
  })

  test('the sharing policy, carried only with the sharing switch on, read only too', async () => {
    routes['GET /api/admin/instance-settings'] = { status: 200, body: settingsFor(false, { sharingPolicy: SHARING, canManageSharingPolicy: false }) }
    renderPage(auth(FULL_ADMIN, 'admin'))
    const sharing = await screen.findByRole('region', { name: 'Sharing policy' })
    expect(within(sharing).queryByRole('checkbox')).toBeNull()
    expect(sharing).toHaveTextContent('Highest level a share may haveWrite')
  })

  test('no sharing policy in the answer (switch off): no sharing panel', async () => {
    renderPage(auth(FULL_ADMIN, 'admin'))
    await screen.findByRole('region', { name: 'Security policy' })
    expect(screen.queryByRole('region', { name: 'Sharing policy' })).toBeNull()
  })

  test('an unconfirmed Root reads them and learns the host must confirm it', async () => {
    renderPage(auth(EVERYTHING, 'root'))
    const security = await screen.findByRole('region', { name: 'Security policy' })
    expect(within(security).getByRole('note')).toHaveTextContent('You are Root, chosen automatically: you change these once the host confirms you')
    expect(within(security).queryByRole('textbox')).toBeNull()
  })
})

describe('values saved (the confirmed Root, with its password)', () => {
  beforeEach(() => {
    routes['GET /api/admin/instance-settings'] = { status: 200, body: settingsFor(true, { sharingPolicy: SHARING, canManageSharingPolicy: true }) }
    routes['PUT /api/admin/instance-settings'] = (init) => {
      const { stepUpPassword: _pw, sharingPolicy, ...fields } = JSON.parse(String(init?.body))
      return {
        status: 200,
        body: settingsFor(true, {
          securityPolicy: { ...POLICY, ...fields }, sharingPolicy: { ...SHARING, ...sharingPolicy }, canManageSharingPolicy: true,
        }),
      }
    }
  })

  test('the security policy: only the changed fields and the password are sent, and the answer is shown', async () => {
    renderPage(auth(EVERYTHING, 'root'))
    const field = await screen.findByLabelText('Minimum password length (characters)')
    const save = screen.getByRole('button', { name: 'Save the security policy' })
    expect(save).toBeDisabled()
    fireEvent.change(field, { target: { value: '16' } })
    fireEvent.click(screen.getByLabelText('Ask for a reason before acting as someone'))
    fireEvent.click(save)
    await confirmWithPassword()
    await waitFor(() => expect(calls('PUT', '/api/admin/instance-settings')).toHaveLength(1))
    expect(bodyOf(calls('PUT', '/api/admin/instance-settings')[0])).toEqual({
      passwordMinLength: 16, impersonationReasonRequired: true, stepUpPassword: 'root-password',
    })
    expect(await screen.findByText('Security policy saved')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByLabelText('Minimum password length (characters)')).toHaveValue('16'))
    expect(screen.getByRole('button', { name: 'Save the security policy' })).toBeDisabled()
  })

  test('a wrong password: the dialog stays open with the reason, nothing shown as saved', async () => {
    routes['PUT /api/admin/instance-settings'] = { status: 403, body: { error: 'Password is incorrect', code: 'step_up_failed' } }
    renderPage(auth(EVERYTHING, 'root'))
    fireEvent.change(await screen.findByLabelText('Minimum password length (characters)'), { target: { value: '14' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save the security policy' }))
    await confirmWithPassword('wrong')
    expect(await screen.findByText(/Password is incorrect/)).toBeInTheDocument()
    expect(screen.getByLabelText('Your password')).toBeInTheDocument()
    expect(screen.queryByText('Security policy saved')).toBeNull()
  })

  test('a value out of bounds: refused on the page, Save off, nothing sent', async () => {
    renderPage(auth(EVERYTHING, 'root'))
    const field = await screen.findByLabelText('Administrator idle timeout (minutes)')
    fireEvent.change(field, { target: { value: '2' } })
    expect(field).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText('A whole number of minutes from 5 to 1440.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save the security policy' })).toBeDisabled()
    expect(calls('PUT', '/api/')).toHaveLength(0)
  })

  test('the public address', async () => {
    renderPage(auth(EVERYTHING, 'root'))
    fireEvent.change(await screen.findByLabelText('Public base URL'), { target: { value: ' https://redamon.example.com ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save the public address' }))
    await confirmWithPassword()
    await waitFor(() => expect(calls('PUT', '/api/admin/instance-settings')).toHaveLength(1))
    expect(bodyOf(calls('PUT', '/api/admin/instance-settings')[0])).toEqual({ publicBaseUrl: 'https://redamon.example.com', stepUpPassword: 'root-password' })
  })

  test('the sharing policy: sent as sharingPolicy with only what changed', async () => {
    renderPage(auth(EVERYTHING, 'root'))
    const sharing = await screen.findByRole('region', { name: 'Sharing policy' })
    fireEvent.click(within(sharing).getByLabelText(/Sharing is on/))
    fireEvent.change(within(sharing).getByLabelText('Default share expiry (days)'), { target: { value: '30' } })
    fireEvent.click(within(sharing).getByRole('button', { name: 'Save the sharing policy' }))
    await confirmWithPassword()
    await waitFor(() => expect(calls('PUT', '/api/admin/instance-settings')).toHaveLength(1))
    expect(bodyOf(calls('PUT', '/api/admin/instance-settings')[0])).toEqual({
      sharingPolicy: { enabled: true, defaultExpiryDays: 30 }, stepUpPassword: 'root-password',
    })
    expect(await screen.findByText('Sharing policy saved')).toBeInTheDocument()
  })

  test('the default member set goes through the permission sets route, Root\'s with its password', async () => {
    routes['PUT /api/admin/permission-sets/builtin%3Ared-team-operator'] = { status: 200, body: { set: {}, changed: true, signedOut: 2 } }
    renderPage(auth(EVERYTHING, 'root'))
    const defaults = await screen.findByRole('region', { name: 'Defaults for new members' })
    const select = await within(defaults).findByLabelText('Default member set')
    expect(select).toHaveValue('builtin:default-member')
    fireEvent.change(select, { target: { value: 'builtin:red-team-operator' } })
    fireEvent.click(within(defaults).getByRole('button', { name: 'Make it the default' }))
    await confirmWithPassword()
    await waitFor(() => expect(calls('PUT', '/api/admin/permission-sets/')).toHaveLength(1))
    const [put] = calls('PUT', '/api/admin/permission-sets/')
    expect(put[0]).toBe('/api/admin/permission-sets/builtin%3Ared-team-operator')
    expect(bodyOf(put)).toEqual({ instanceDefault: true, stepUpPassword: 'root-password' })
    expect(await screen.findByText('Default member set changed; 2 member(s) signed out')).toBeInTheDocument()
    expect(within(defaults).getByRole('button', { name: 'Make it the default' })).toBeDisabled()
  })

  test('the permission sets refused (no roles:manage read): the denied notice in that panel only', async () => {
    routes['GET /api/admin/permission-sets'] = { status: 403, body: { error: 'no', code: 'forbidden', permission: 'roles:manage' } }
    renderPage(auth(EVERYTHING, 'root'))
    const defaults = await screen.findByRole('region', { name: 'Defaults for new members' })
    expect(await within(defaults).findByRole('alert')).toHaveTextContent('roles:manage')
    expect(region('Security policy')).toBeInTheDocument()
  })
})

describe('the tunnel (platform:tunnels)', () => {
  test('its editor on this page, also with governance on; the save goes to the instance settings with the tunnel only', async () => {
    routes['PUT /api/admin/instance-settings'] = (init) => ({ status: 200, body: { ...settingsFor(false), ...JSON.parse(String(init?.body)) } })
    renderPage(auth(FULL_ADMIN, 'admin'))
    const tunnel = await screen.findByRole('region', { name: 'Tunnel' })
    fireEvent.click(await within(tunnel).findByLabelText('Enable tunnels'))
    fireEvent.click(within(tunnel).getByRole('button', { name: 'Save tunnel settings' }))
    await waitFor(() => expect(calls('PUT', '/api/admin/instance-settings')).toHaveLength(1))
    expect(Object.keys(bodyOf(calls('PUT', '/api/admin/instance-settings')[0])).sort()).toEqual(['chiselAuth', 'chiselServerUrl', 'ngrokAuthtoken', 'tunnelsEnabled'])
    expect(within(tunnel).queryByRole('link', { name: 'Open the tunnel settings' })).toBeNull()
  })

  test('not shown to whoever the route says may not change it', async () => {
    routes['GET /api/admin/instance-settings'] = { status: 200, body: settingsFor(false, { canManageTunnels: false }) }
    renderPage(auth(FULL_ADMIN, 'admin'))
    await screen.findByRole('region', { name: 'Security policy' })
    expect(screen.queryByRole('region', { name: 'Tunnel' })).toBeNull()
  })
})

describe('TrafficMind link (platform:traffic_capture)', () => {
  test('the summary, the TrafficMind page link, and the settings dialog as the signed-in person; closing reads again', async () => {
    routes['GET /api/admin/instance-settings'] = { status: 200, body: settingsFor(false, { captureEgressBlockPrivate: false }) }
    renderPage(auth(FULL_ADMIN, 'admin'))
    const traffic = await screen.findByRole('region', { name: 'TrafficMind and egress policy' })
    expect(traffic).toHaveTextContent('Capture proxyOn')
    expect(traffic).toHaveTextContent('Relaxed: private IPs')
    expect(within(traffic).getByRole('link', { name: 'Open TrafficMind' })).toHaveAttribute('href', '/traffic')
    const reads = calls('GET', '/api/admin/instance-settings').length
    fireEvent.click(within(traffic).getByRole('button', { name: 'Edit TrafficMind settings' }))
    expect(screen.getByRole('dialog', { name: 'TrafficMind settings' })).toBeInTheDocument()
    expect(modal.props?.userId).toBe('u-1')
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(calls('GET', '/api/admin/instance-settings').length).toBe(reads + 1))
    expect(screen.queryByRole('dialog', { name: 'TrafficMind settings' })).toBeNull()
  })
})

describe('Nuclei templates (platform:nuclei_templates)', () => {
  test('the list with owners; promote and delete each confirmed, then sent to the templates route', async () => {
    routes['PATCH /api/nuclei-templates'] = { status: 200, body: { templates: TEMPLATES.map((t) => ({ ...t, ownership: 'instance' })), canManageAll: true, promoted: true } }
    routes['DELETE /api/nuclei-templates'] = { status: 200, body: { templates: [], canManageAll: true } }
    renderPage(auth(FULL_ADMIN, 'admin'))
    const nuclei = await screen.findByRole('region', { name: 'Nuclei templates' })
    expect(await within(nuclei).findByText('mem-a@e2e.local')).toBeInTheDocument()
    expect(within(nuclei).queryByRole('button', { name: 'Make aem.yaml an instance template' })).toBeNull()

    alerts.confirm.mockResolvedValueOnce(false)
    fireEvent.click(within(nuclei).getByRole('button', { name: 'Make team/m.yaml an instance template' }))
    await waitFor(() => expect(alerts.confirm).toHaveBeenCalledTimes(1))
    expect(calls('PATCH', '/api/nuclei-templates')).toHaveLength(0)

    fireEvent.click(within(nuclei).getByRole('button', { name: 'Make team/m.yaml an instance template' }))
    await waitFor(() => expect(calls('PATCH', '/api/nuclei-templates')).toHaveLength(1))
    expect(bodyOf(calls('PATCH', '/api/nuclei-templates')[0])).toEqual({ path: 'team/m.yaml', promote: true })
    await waitFor(() => expect(within(nuclei).queryByRole('button', { name: 'Make team/m.yaml an instance template' })).toBeNull())

    fireEvent.click(within(nuclei).getByRole('button', { name: 'Delete aem.yaml' }))
    await waitFor(() => expect(calls('DELETE', '/api/nuclei-templates')).toHaveLength(1))
    expect(alerts.dangerConfirm).toHaveBeenCalledTimes(1)
    expect(calls('DELETE', '/api/nuclei-templates')[0][0]).toBe('/api/nuclei-templates?path=aem.yaml')
    expect(await within(nuclei).findByText(/No custom template yet/)).toBeInTheDocument()
  })

  test('a refused delete is told through the alert modal, the list kept', async () => {
    routes['DELETE /api/nuclei-templates'] = { status: 403, body: { error: 'no', code: 'forbidden', permission: 'scan:custom_templates' } }
    renderPage(auth(FULL_ADMIN, 'admin'))
    const nuclei = await screen.findByRole('region', { name: 'Nuclei templates' })
    fireEvent.click(await within(nuclei).findByRole('button', { name: 'Delete aem.yaml' }))
    await waitFor(() => expect(alerts.alertError).toHaveBeenCalledWith('The template was not deleted: it needs scan:custom_templates.'))
    expect(within(nuclei).getByText('aem.yaml')).toBeInTheDocument()
  })

  test('the route says the person does not manage every template: the denied notice', async () => {
    routes['GET /api/nuclei-templates'] = { status: 200, body: { templates: [], canManageAll: false } }
    renderPage(auth(FULL_ADMIN, 'admin'))
    const nuclei = await screen.findByRole('region', { name: 'Nuclei templates' })
    expect(await within(nuclei).findByRole('alert')).toHaveTextContent('platform:nuclei_templates')
  })
})

describe('quotas, plugins and the other platform tools', () => {
  test('Full admin: quotas unlimited, the Plugins link, and where the tools without a panel live', async () => {
    renderPage(auth(FULL_ADMIN, 'admin'))
    expect(await screen.findByRole('region', { name: 'Quotas' })).toHaveTextContent('No quota is set')
    expect(within(region('Plugins')).getByRole('link', { name: 'Open the Plugins page' })).toHaveAttribute('href', '/plugins')
    const other = region('Platform tools used elsewhere')
    expect(within(other).queryByRole('note')).toBeNull()
    expect(within(other).getByRole('link', { name: 'Open MCP Tool Plugins' })).toHaveAttribute('href', '/settings?tab=mcp')
  })
})
