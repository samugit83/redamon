/**
 * The override picker (step 3.13; PE-03, PE-30, DV-19): permissions grouped by area, only those an
 * override may name on the account (member permissions, a platform tool on a member, never an
 * administration right), a grant of what the person does not hold listed disabled with the reason.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/PermissionPicker.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import type { PermissionId } from '@/lib/authz/permissions'
import { PermissionPicker } from './PermissionPicker'

afterEach(cleanup)

function renderPicker(props: Partial<Parameters<typeof PermissionPicker>[0]> = {}) {
  const onChange = vi.fn()
  render(
    <PermissionPicker
      id="pick" label="Permission" accountType="member" effect="grant"
      givable={new Set<PermissionId>(['recon:scan', 'platform:tunnels'])} value="" onChange={onChange} {...props}
    />,
  )
  return { onChange, picker: screen.getByRole('combobox', { name: 'Permission' }) }
}
const option = (picker: HTMLElement, name: string) => within(picker).getByRole('option', { name }) as HTMLOptionElement
const groups = (picker: HTMLElement) => within(picker).getAllByRole('group').map((g) => g.getAttribute('label'))

describe('PermissionPicker', () => {
  test('grouped by area; a member may get a platform tool, never an administration right', () => {
    const { picker } = renderPicker()
    expect(groups(picker)).toEqual([
      'Platform operations', 'Your own account', 'Projects', 'Recon and scanning', 'AI agent', 'Workspace',
      'Graph and analytics', 'Triage and remediation', 'Reports', 'Traffic and authenticated sessions', 'Plugins',
    ])
    expect(within(picker).queryByRole('option', { name: /users:read/ })).toBeNull()
    expect(option(picker, 'platform:tunnels').disabled).toBe(false)
  })

  test('an admin\'s overrides name member permissions only: its profile states its admin side', () => {
    const { picker } = renderPicker({ accountType: 'admin' })
    expect(groups(picker)).not.toContain('Platform operations')
    expect(groups(picker)).not.toContain('Administration')
  })

  test('a grant of what the person does not hold is disabled, with the reason in its name; a deny is not', () => {
    const { picker } = renderPicker()
    expect(option(picker, 'recon:scan').disabled).toBe(false)
    expect(option(picker, 'agent:kali_exec (you do not hold it)').disabled).toBe(true)
    cleanup()
    const deny = renderPicker({ effect: 'deny' })
    expect(option(deny.picker, 'agent:kali_exec').disabled).toBe(false)
  })

  test('already overridden permissions are left out; choosing one reports it and shows its description', () => {
    const { picker, onChange } = renderPicker({ exclude: new Set<PermissionId>(['recon:scan']) })
    expect(within(picker).queryByRole('option', { name: 'recon:scan' })).toBeNull()
    fireEvent.change(picker, { target: { value: 'platform:tunnels' } })
    expect(onChange).toHaveBeenCalledWith('platform:tunnels')
    cleanup()
    renderPicker({ value: 'platform:tunnels' })
    expect(screen.getByText('Configure and enable the ngrok or chisel tunnel every user shares.')).toBeTruthy()
  })
})
