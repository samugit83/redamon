/**
 * RouteExposureSection: the enable toggle, every generator and analysis toggle
 * writes its own field (falling back to the Prisma default), the authentication
 * hint links to Target & Modules, the numeric fields come from the registry, and
 * the "Half a cycle" alert reads the attack skills as the agent does and links to
 * Agent Skills.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/RouteExposureSection.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { RouteExposureSection } from './RouteExposureSection'
import { JevSelectionProvider } from '@/hooks/useHasJevProvider'

vi.mock('../NodeInfoTooltip', () => ({ NodeInfoTooltip: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))
vi.mock('../RegistryFields', () => ({
  RegistryFields: ({ keys, title }: { keys: string[]; title: string }) => (
    <div data-testid="registry-fields" data-title={title}>{keys.join(',')}</div>
  ),
}))
vi.mock('@/components/ui', () => ({
  WikiInfoButton: ({ target }: { target: string }) => <a data-testid="wiki" data-target={target} />,
  Toggle: ({ checked, onChange, ...rest }: { checked: boolean; onChange: (v: boolean) => void }) => (
    <button role="switch" aria-checked={checked} aria-label={(rest as Record<string, string>)['aria-label']}
            onClick={() => onChange(!checked)} />
  ),
}))

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function renderSection(data: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  const updateField = vi.fn()
  const view = render(<RouteExposureSection data={data as never} updateField={updateField as never} {...extra} />)
  return { ...view, updateField }
}

describe('RouteExposureSection', () => {
  test('the enable toggle writes routeExposureEnabled', () => {
    const { updateField } = renderSection({ routeExposureEnabled: false })
    fireEvent.click(screen.getByRole('switch', { name: 'Enable Route Exposure' }))
    expect(updateField).toHaveBeenCalledWith('routeExposureEnabled', true)
  })

  test('the wiki button points at the Route Exposure page', () => {
    renderSection({ routeExposureEnabled: false })
    expect(screen.getByTestId('wiki').getAttribute('data-target')).toBe('RouteExposure')
  })

  test('the body shows only while the module is on', () => {
    renderSection({ routeExposureEnabled: false })
    expect(screen.queryByRole('switch', { name: 'Seed paths' })).toBeNull()
    expect(screen.queryByTestId('registry-fields')).toBeNull()
    expect(screen.getByText(/never requests logout, delete or reset paths/)).toBeTruthy()
  })

  test.each([
    ['Seed paths', 'routeExposureSeedPaths'],
    ['Version control and env files', 'routeExposureVcsFiles'],
    ['Backup file variants', 'routeExposureBackupFiles'],
    ['Older API versions', 'routeExposureVersionVariants'],
    ['Compare with the logged-in answer', 'routeExposureCompareLoggedIn'],
    ['Personal data detection', 'routeExposurePiiDetection'],
    ['Sibling routes', 'routeExposureSiblings'],
    ['Framework paths', 'routeExposureFrameworkSeeds'],
    ['Follow route catalogs', 'routeExposureFollowCatalogs'],
    ['Git walk proof', 'routeExposureGitWalk'],
    ['Cross-origin (CORS)', 'routeExposureCorsRider'],
    ['Cacheable logged-in content', 'routeExposureCacheRider'],
  ])('%s writes %s, on by default', (name, field) => {
    // A project saved before the field existed has no value: the control reads on.
    const { updateField } = renderSection({ routeExposureEnabled: true })
    const toggle = screen.getByRole('switch', { name })
    expect(toggle.getAttribute('aria-checked')).toBe('true')
    fireEvent.click(toggle)
    expect(updateField).toHaveBeenCalledWith(field, false)
  })

  test('the authentication hint opens Target & Modules', () => {
    const onOpenAuth = vi.fn()
    renderSection({ routeExposureEnabled: true }, { onOpenAuth })
    fireEvent.click(screen.getByRole('button', { name: 'Target & Modules > Authenticated Session' }))
    expect(onOpenAuth).toHaveBeenCalled()
  })

  test('without a callback the hint is plain text', () => {
    renderSection({ routeExposureEnabled: true })
    expect(screen.getByText(/Without one it still finds routes open to anyone/)).toBeTruthy()
    expect(screen.getByText(/Target & Modules > Authenticated Session/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /Authenticated Session/ })).toBeNull()
  })

  test('the advanced fields are the five numeric registry keys', () => {
    renderSection({ routeExposureEnabled: true })
    const fields = screen.getByTestId('registry-fields')
    expect(fields.textContent).toBe(
      'routeExposureMaxRps,routeExposureWorkers,routeExposureTimeout,routeExposureMaxRoutesPerHost,routeExposureMaxRoutesTotal')
    expect(fields.getAttribute('data-title')).toBe('Advanced')
  })

  const skills = (builtIn: Record<string, unknown>) => ({ attackSkillConfig: { builtIn, user: {} } })

  test('the alert shows when Access Control is off, and only with the module on', () => {
    renderSection({ routeExposureEnabled: true, ...skills({ access_control: false }) })
    expect(screen.getByRole('alert').textContent).toMatch(/Half a cycle.*turn on Broken Access Control in AI Agent > Agent Skills/)
    cleanup()
    renderSection({ routeExposureEnabled: false, ...skills({ access_control: false }) })
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('the alert opens AI Agent > Agent Skills', () => {
    const onOpenAgentSkills = vi.fn()
    renderSection({ routeExposureEnabled: true, ...skills({ access_control: false }) }, { onOpenAgentSkills })
    fireEvent.click(screen.getByRole('button', { name: 'AI Agent > Agent Skills' }))
    expect(onOpenAgentSkills).toHaveBeenCalled()
  })

  test('without a callback the alert names the tab as plain text', () => {
    renderSection({ routeExposureEnabled: true, ...skills({ access_control: false }) })
    expect(screen.getByRole('alert').textContent).toMatch(/AI Agent > Agent Skills\.$/)
    expect(screen.queryByRole('button', { name: /Agent Skills/ })).toBeNull()
  })

  test.each([
    ['a missing key', {}],
    ['no attackSkillConfig at all', null],
  ])('%s counts as off, as in the agent', (_label, builtIn) => {
    const data = builtIn === null ? { routeExposureEnabled: true } : { routeExposureEnabled: true, ...skills(builtIn) }
    renderSection(data)
    expect(screen.getByRole('alert')).toBeTruthy()
  })

  test('with all three skills on there is neither the alert nor the hint', () => {
    renderSection({ routeExposureEnabled: true, ...skills({ access_control: true, path_traversal: true, rce: true }) })
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.queryByText(/proven by Path Traversal and RCE/)).toBeNull()
  })

  test.each(['path_traversal', 'rce'])('with %s off only the softer hint shows', (off) => {
    const builtIn: Record<string, boolean> = { access_control: true, path_traversal: true, rce: true }
    builtIn[off] = false
    renderSection({ routeExposureEnabled: true, ...skills(builtIn) })
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByText(/proven by Path Traversal and RCE/)).toBeTruthy()
  })

  test('Run partial recon shows only in edit mode with the module on', () => {
    const onRun = vi.fn()
    renderSection({ routeExposureEnabled: false }, { onRun })
    expect(screen.queryByText(/Run partial recon/)).toBeNull()
    cleanup()
    renderSection({ routeExposureEnabled: true }, { onRun })
    fireEvent.click(screen.getByText(/Run partial recon/))
    expect(onRun).toHaveBeenCalled()
  })

  test('Cross-host writes routeExposureCrossHost, off by default', () => {
    const { updateField } = renderSection({ routeExposureEnabled: true })
    const toggle = screen.getByRole('switch', { name: 'Cross-host' })
    expect(toggle.getAttribute('aria-checked')).toBe('false')
    fireEvent.click(toggle)
    expect(updateField).toHaveBeenCalledWith('routeExposureCrossHost', true)
  })
})

describe('RouteExposureSection Jev rows', () => {
  const FIELDS = ['routeExposureJevRank', 'routeExposureJevWallCheck', 'routeExposureJevAssess']

  function stubJevProvider() {
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => [{ id: 'j', name: 'Selected direct Jev', providerType: 'jev', apiKey: '••••c0de', modelIdentifier: 'jev-1.13.0' }],
    })))
  }

  test('each of the three controls writes its own field', async () => {
    stubJevProvider()
    const updateField = vi.fn()
    render(
      <JevSelectionProvider ownerUserId="u1" selectedProviderId="j">
        <RouteExposureSection data={{ routeExposureEnabled: true, aiInPipeline: true } as never} updateField={updateField as never} />
      </JevSelectionProvider>,
    )
    const groups = screen.getAllByRole('group', { name: 'Jev hook' })
    expect(groups).toHaveLength(3)
    for (const [i, field] of FIELDS.entries()) {
      const jev = within(groups[i]).getByRole('button', { name: 'Jev' })
      await waitFor(() => expect(jev).toBeEnabled())
      fireEvent.click(jev)
      expect(updateField).toHaveBeenCalledWith(field, true)
    }
  })

  test('they are disabled until AI in Pipeline is on, and say so', () => {
    stubJevProvider()
    renderSection({ routeExposureEnabled: true, aiInPipeline: false })
    for (const group of screen.getAllByRole('group', { name: 'Jev hook' })) {
      const jev = within(group).getByRole('button', { name: 'Jev' })
      expect(jev).toBeDisabled()
      expect(jev).toHaveAttribute('title', 'Enable "AI in Pipeline" in the Target tab to turn this on.')
    }
  })
})
