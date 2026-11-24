/**
 * Regression: the LHOST field must point the operator at the RedAmon HOST's
 * address the target can reach, never the Kali sandbox's own internal address
 * (10.214.x since per-user sandboxes; 172.x before).
 *
 * Issue #180 — the placeholder used to read "e.g. 172.28.0.2" (a pentest-net
 * container IP), which seeded exactly the wrong choice: a reverse target cannot
 * reach the container, only the host's address on a port forwarded to it.
 *
 * FU-26: the Payload Direction texts describe per-person sandboxes: without a
 * tunnel only the operator's port pool reaches a sandbox and the agent uses the
 * sandbox's own port as LPORT; the project's LPORT is never used as LPORT (D-F);
 * chisel forwards 4444 only.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/AgentBehaviourSection.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import {
  AgentBehaviourSection, FIRETEAM_TIMEOUT_SEC_DEFAULT, LHOST_HINT, LPORT_HINT, NO_TUNNEL_HINT, OWN_TUNNEL_NEEDED,
} from './AgentBehaviourSection'

vi.mock('@/components/shared/ModelPicker', () => ({ ModelPicker: () => null }))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'u1' }) }))
vi.mock('@/components/ui', () => ({
  Toggle: () => null,
  WikiInfoButton: () => null,
}))

afterEach(cleanup)

/** Minimal data with tunnels off so the manual LHOST/LPORT inputs render. */
const BASE = {
  agentLhost: '',
  agentLport: null,
  agentBindPortOnTarget: null,
  agentNgrokTunnelEnabled: false,
  agentChiselTunnelEnabled: false,
  agentPayloadUseHttps: false,
} as Record<string, unknown>

function renderSection(initial: Record<string, unknown> = {}, detectedHostIp?: string) {
  const data = { ...BASE, ...initial }
  const updateField = vi.fn()
  const view = render(
    <AgentBehaviourSection data={data as never} updateField={updateField as never} detectedHostIp={detectedHostIp} />,
  )
  return { ...view, updateField }
}

describe('LHOST field guides to the host LAN IP, not the container IP', () => {
  test('placeholder is a LAN-style example, never a 172.x container address', () => {
    renderSection()
    const lhost = screen.getByPlaceholderText(/^e\.g\. \d/) as HTMLInputElement
    expect(lhost.placeholder).toBe('e.g. 192.168.1.50')
    expect(lhost.placeholder).not.toMatch(/172\./)
  })

  test("hint names the RedAmon host's reachable address, never the sandbox's 10.214.x (FU-26)", () => {
    renderSection()
    expect(screen.getByText(LHOST_HINT)).toBeTruthy()
    expect(LHOST_HINT).toMatch(/RedAmon host that the target can reach/)
    expect(LHOST_HINT).toMatch(/Never your Kali sandbox's own 10\.214\.x address/)
    expect(document.body.textContent).not.toMatch(/172\.x|host machine's LAN IP/)
  })
})

describe('Payload Direction texts (FU-26)', () => {
  const text = () => document.body.textContent ?? ''

  test('no tunnel: the port pool reaches the sandbox and its port is LPORT; otherwise a tunnel or a bind payload', () => {
    renderSection()
    expect(screen.getByText(NO_TUNNEL_HINT)).toBeTruthy()
    expect(NO_TUNNEL_HINT).toMatch(/only through a port of the port pool your operator configured \(KALI_SANDBOX_PORT_POOL\)/)
    expect(NO_TUNNEL_HINT).toMatch(/uses your sandbox's own port as LPORT/)
    expect(NO_TUNNEL_HINT).toMatch(/use a tunnel or a bind payload/)
    expect(text()).not.toMatch(/configure LHOST\/LPORT manually/)
  })

  test('the project LPORT is never the agent\'s LPORT: pool port, tunnel port, or bind only (D-F)', () => {
    renderSection()
    expect(screen.getByText(LPORT_HINT)).toBeTruthy()
    expect(LPORT_HINT).toBe(
      "Not used as LPORT: with a port pool the agent uses your sandbox's own port; with a tunnel, the tunnel's; with neither, only bind payloads work. Leave it empty.",
    )
    expect(document.body.textContent).not.toMatch(/Used only when your operator configured no port pool|your own forwarding/)
  })

  test('the registry, which MCP clients and the settings reference read, says the same (D-F)', async () => {
    const { field } = await import('@/lib/reconSettings/registry')
    expect(field('agentLport')?.meaning).toBe(
      "Not used as LPORT: with a port pool the agent uses the person's own sandbox port; with a tunnel, the tunnel's; with neither, only bind payloads work. Leave it empty.",
    )
    expect(field('agentLhost')?.meaning).toMatch(/never the Kali sandbox's own 10\.214\.x address/)
    expect(field('agentLhost')?.meaning).not.toMatch(/&apos;|172\.x/)
  })

  test('chisel forwards 4444 only: no 8080, no web delivery or HTA, no "multi-port"', () => {
    renderSection({ agentChiselTunnelEnabled: true })
    expect(text()).toContain('Tunnels port 4444 of your sandbox only (the handler): no web delivery or HTA.')
    expect(text()).toContain('Only the handler port (4444) is tunneled.')
    expect(text()).not.toMatch(/8080|multi-port|web delivery\) ports/)
    expect(screen.getByRole('option', { name: 'chisel (port 4444 - requires a VPS)' })).toBeTruthy()
  })

  test('a tunnel needs the person\'s own tunnel on as well as the project setting', () => {
    for (const on of [{ agentNgrokTunnelEnabled: true }, { agentChiselTunnelEnabled: true }]) {
      const { unmount } = renderSection(on)
      expect(text()).toContain(OWN_TUNNEL_NEEDED)
      expect(OWN_TUNNEL_NEEDED).toMatch(/your own tunnel turned on in Global Settings → Tunneling/)
      unmount()
    }
  })
})

describe('detected host IP suggestion (issue #180)', () => {
  test('shows the suggestion and "Use this" fills LHOST on click', () => {
    const { updateField } = renderSection({}, '192.168.1.50')
    expect(screen.getByText(/Detected \(default route\): 192\.168\.1\.50/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /use this/i }))
    expect(updateField).toHaveBeenCalledWith('agentLhost', '192.168.1.50')
  })

  test('no suggestion when the prop is empty', () => {
    renderSection({}, '')
    expect(screen.queryByText(/Detected \(default route\)/)).toBeNull()
  })

  test('no suggestion when it equals the current LHOST', () => {
    renderSection({ agentLhost: '192.168.1.50' }, '192.168.1.50')
    expect(screen.queryByText(/Detected \(default route\)/)).toBeNull()
  })

  test('no suggestion for a non-IPv4 value', () => {
    renderSection({}, 'not-an-ip')
    expect(screen.queryByText(/Detected \(default route\)/)).toBeNull()
  })

  test('rendering the suggestion does NOT touch LHOST until clicked (never enters save payload)', () => {
    // Row 6: the value rides a prop, not formData. It must mutate state only on
    // an explicit click, so it can never reach the PUT payload on its own.
    const { updateField } = renderSection({}, '192.168.1.50')
    expect(screen.getByText(/Detected \(default route\): 192\.168\.1\.50/)).toBeTruthy()
    expect(updateField).not.toHaveBeenCalled()
  })

  test('suppressed under a tunnel (LHOST field is hidden)', () => {
    renderSection({ agentNgrokTunnelEnabled: true }, '192.168.1.50')
    expect(screen.queryByText(/Detected \(default route\)/)).toBeNull()
  })
})

/**
 * The engagement's two closed vocabularies, and why a near-miss is dangerous
 * rather than merely untidy.
 *
 * `roeForbiddenTools` and `roeForbiddenCategories` are both matched EXACTLY by
 * the gate in execute_plan_node.py: the tool name against the dispatched name,
 * the category against CATEGORY_TOOL_MAP's keys. A value that is almost right
 * is not partially enforced, it is not enforced at all - and it still renders
 * as a rule in the UI and still reaches the agent's prompt as advice, so the
 * engagement looks constrained while the tool runs.
 *
 * This was live: a real project held "Denial of Service", "Brute Forcing" and
 * "Password Spraying" as forbidden categories, none of which the gate knows, and
 * `execute_sqlmap` as a forbidden tool, which is not a tool at all. The tools
 * field was a comma-separated text box whose own placeholder suggested
 * `execute_sqlmap`, so the product taught the value that could not work.
 */
describe('a forbidden tool or category can only be one the gate enforces', () => {
  test('the tools offered are exactly the registry vocabulary', async () => {
    const { field } = await import('@/lib/reconSettings/registry')
    const expected = field('roeForbiddenTools')?.values ?? []
    expect(expected.length).toBeGreaterThan(0)

    const { container } = renderSection({ roeForbiddenTools: [], roeForbiddenCategories: [] })
    const offered = [...container.querySelectorAll('code')]
      .map(el => el.textContent ?? '')
      .filter(text => expected.includes(text))
    expect([...new Set(offered)].sort()).toEqual([...expected].sort())
  })

  test('there is no free-text box that could produce an unenforceable name', () => {
    const { container } = renderSection()
    const placeholders = [...container.querySelectorAll('input[type="text"]')]
      .map(el => (el as HTMLInputElement).placeholder)
    expect(placeholders.join(' ')).not.toMatch(/execute_sqlmap/)
  })

  test('ticking a tool writes that exact name and nothing else', () => {
    const { updateField, container } = renderSection({ roeForbiddenTools: [] })
    const box = [...container.querySelectorAll('label')]
      .find(l => l.querySelector('code')?.textContent === 'execute_hydra')
      ?.querySelector('input')
    expect(box).toBeTruthy()
    fireEvent.click(box!)
    expect(updateField).toHaveBeenCalledWith('roeForbiddenTools', ['execute_hydra'])
  })

  test('every category offered is a key the gate can expand', () => {
    // The UI used to offer `physical` with no matching CATEGORY_TOOL_MAP entry.
    // Whatever the set is, it must come from the registry rather than a literal
    // here, so the form and the validator cannot disagree.
    const { container } = renderSection({ roeForbiddenCategories: [] })
    const text = container.textContent ?? ''
    for (const label of ['Credential testing', 'Availability testing', 'Social engineering']) {
      expect(text).toContain(label)
    }
  })
})

/**
 * drift-map #12: the wave-timeout fallbacks (shown for a project without a value,
 * and written back when an entry is not a number) were 3600 and 1800 while the
 * agent runs with FIRETEAM_TIMEOUT_SEC = 7200. The Python default is read from
 * its source, so a change on either side fails here.
 */
describe('the fireteam wave-timeout fallback is the agent default', () => {
  const AGENT_SETTINGS_PY = join(__dirname, '../../../../../../agentic/project_settings.py')
  const available = existsSync(AGENT_SETTINGS_PY)

  function pythonDefault(): number {
    const src = readFileSync(AGENT_SETTINGS_PY, 'utf8')
    const m = src.match(/['"]FIRETEAM_TIMEOUT_SEC['"]\s*:\s*(\d+)/)
    expect(m, 'FIRETEAM_TIMEOUT_SEC not found in agentic/project_settings.py').toBeTruthy()
    return Number(m![1])
  }

  function timeoutInput(container: HTMLElement): HTMLInputElement {
    const label = [...container.querySelectorAll('label')]
      .find(l => l.textContent === 'Wave timeout (seconds)')
    const input = label?.parentElement?.querySelector('input')
    expect(input, 'wave timeout input not rendered').toBeTruthy()
    return input as HTMLInputElement
  }

  test.skipIf(!available)('the constant equals DEFAULT_AGENT_SETTINGS FIRETEAM_TIMEOUT_SEC', () => {
    expect(FIRETEAM_TIMEOUT_SEC_DEFAULT).toBe(pythonDefault())
  })

  test('a project without a value shows the default', () => {
    const { container } = renderSection()
    expect(timeoutInput(container).value).toBe(String(FIRETEAM_TIMEOUT_SEC_DEFAULT))
  })

  test('an entry that is not a number is replaced by the default on blur', () => {
    const { container, updateField } = renderSection({ fireteamTimeoutSec: 900 })
    fireEvent.blur(timeoutInput(container), { target: { value: '' } })
    expect(updateField).toHaveBeenLastCalledWith('fireteamTimeoutSec', FIRETEAM_TIMEOUT_SEC_DEFAULT)
  })

  test('a number is clamped, not replaced', () => {
    const { container, updateField } = renderSection({ fireteamTimeoutSec: 900 })
    fireEvent.blur(timeoutInput(container), { target: { value: '99999' } })
    expect(updateField).toHaveBeenLastCalledWith('fireteamTimeoutSec', 7200)
  })
})
