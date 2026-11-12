/**
 * ForbiddenNotice (step 3.12, UI-12): a 403 that names a permission (`{error, code: 'forbidden',
 * permission}`, DV-07) is shown as that permission, what it allows, and "ask an administrator",
 * instead of a bare "Forbidden".
 */
import { describe, test, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ApiError, readApiError } from '@/lib/apiError'
import { PERMISSIONS } from '@/lib/authz/permissions'
import { ForbiddenNotice, forbiddenPermission } from './ForbiddenNotice'

afterEach(() => cleanup())

const refusal = (body: Record<string, unknown>, status = 403) =>
  readApiError(new Response(JSON.stringify(body), { status }), 'Could not load')

describe('ForbiddenNotice', () => {
  test('ForbiddenNotice shows the permission, what it allows, and who can grant it', () => {
    render(<ForbiddenNotice permission="users:read" />)
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('You do not have the permission this needs.')
    expect(notice).toHaveTextContent('users:read')
    expect(notice).toHaveTextContent(PERMISSIONS['users:read'].description)
    expect(notice).toHaveTextContent('Ask an administrator to grant it to you.')
  })

  test('an id the registry does not hold is shown as sent, with no description', () => {
    render(<ForbiddenNotice permission="users:invite" />)
    const notice = screen.getByRole('alert')
    expect(notice).toHaveTextContent('users:invite')
    expect(notice.textContent).not.toContain('undefined')
  })
})

describe('forbiddenPermission', () => {
  test('reads the permission of a forbidden refusal (guards.ts forbiddenResponse)', async () => {
    const err = await refusal({ error: 'You do not hold the permission this action needs (users:delete).', code: 'forbidden', permission: 'users:delete' })
    expect(forbiddenPermission(err)).toBe('users:delete')
  })

  test('null for any other error: another 403 code, a 404, a 403 without a permission, a plain error', async () => {
    expect(forbiddenPermission(await refusal({ error: 'Forbidden', code: 'root_only', permission: 'x' }))).toBeNull()
    expect(forbiddenPermission(await refusal({ error: 'Not found', code: 'forbidden', permission: 'users:read' }, 404))).toBeNull()
    expect(forbiddenPermission(await refusal({ error: 'Forbidden', code: 'forbidden' }))).toBeNull()
    expect(forbiddenPermission(new ApiError({ reason: 'x', status: 403, code: 'forbidden' }))).toBeNull()
    expect(forbiddenPermission(new Error('Forbidden'))).toBeNull()
    expect(forbiddenPermission(null)).toBeNull()
  })
})
