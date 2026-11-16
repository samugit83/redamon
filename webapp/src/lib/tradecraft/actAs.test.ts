/**
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { loginUseRefusal } from './actAs'

describe('loginUseRefusal (stub until T6.5)', () => {
  test('refuses nothing while no resource can hold a login', async () => {
    expect(await loginUseRefusal({ ownerId: 'owner', resourceId: 'r1' })).toBeNull()
  })
})
