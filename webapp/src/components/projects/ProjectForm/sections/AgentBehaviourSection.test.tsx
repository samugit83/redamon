/**
 * Regression: the LHOST field must point the operator at their HOST machine's
 * LAN IP, never the sandbox container's internal 172.x address.
 *
 * Issue #180 — the placeholder used to read "e.g. 172.28.0.2" (a pentest-net
 * container IP), which seeded exactly the wrong choice: a reverse target cannot
 * reach the container, only the host's LAN IP forwarded on port 4444.
 *
 * Run: npx vitest run src/components/projects/ProjectForm/sections/AgentBehaviourSection.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { AgentBehaviourSection } from './AgentBehaviourSection'

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
    const lhost = screen.getByPlaceholderText(/^e\.g\. /) as HTMLInputElement
    expect(lhost.placeholder).toBe('e.g. 192.168.1.50')
    expect(lhost.placeholder).not.toMatch(/172\./)
  })

  test('hint tells the operator to use the host machine LAN IP', () => {
    renderSection()
    expect(screen.getByText(/host machine's LAN IP/i)).toBeTruthy()
    expect(screen.getByText(/not the container's 172\.x/i)).toBeTruthy()
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
