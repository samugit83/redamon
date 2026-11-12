/**
 * usePermissionRefused (step 3.16b, UI-12): a control that only works with one permission is refused
 * up front only when the permissions switch is on and /api/auth/me's set lacks it. With the switch
 * off it answers "not refused" whatever the set holds (DV-30), and so does a session still loading
 * or a component with no AuthProvider above it: the route decides then, as before the switch.
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/usePermissionRefused.test.tsx
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { PermissionId } from '@/lib/authz/permissions'
import { FLAGS_OFF, FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { usePermissionRefused } from './useCan'

afterEach(cleanup)

function Probe({ permission }: { permission: PermissionId }) {
  return <span data-testid="refused">{String(usePermissionRefused(permission, 'p1'))}</span>
}

function refused(value: AuthContextValue | null, permission: PermissionId = 'recon:scan'): string {
  render(<AuthContext.Provider value={value}><Probe permission={permission} /></AuthContext.Provider>)
  const answer = screen.getByTestId('refused').textContent ?? ''
  cleanup()
  return answer
}

describe('usePermissionRefused', () => {
  test('switch on: refused without the permission, not refused with it', () => {
    expect(refused(fakeAuth(FLAGS_ON, ['recon:read']))).toBe('true')
    expect(refused(fakeAuth(FLAGS_ON, ['recon:read', 'recon:scan']))).toBe('false')
  })

  test('switch off: never refused, whatever the set holds (DV-30)', () => {
    expect(refused(fakeAuth(FLAGS_OFF, []))).toBe('false')
    expect(refused(fakeAuth(FLAGS_OFF, ['recon:read']), 'agent:chat')).toBe('false')
  })

  test('switch on with a set the server could not resolve (empty): refused, as every useCan surface', () => {
    expect(refused(fakeAuth(FLAGS_ON, []), 'agent:chat')).toBe('true')
  })

  test('while the session loads, signed out, or with no provider: not refused (the route decides)', () => {
    expect(refused(fakeAuth(FLAGS_ON, [], { isLoading: true }))).toBe('false')
    expect(refused(fakeAuth(null, []))).toBe('false')
    expect(refused(null)).toBe('false')
  })
})
