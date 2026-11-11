/**
 * Account emails compared ignoring case (NF-09): the sign-in lookup and the
 * "already taken" check of the user routes.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ queryRaw: vi.fn() }))
vi.mock('@/lib/prisma', () => ({
  default: { $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => h.queryRaw(strings, ...values) },
}))

import { normalizeEmail, findSignInAccount, emailTakenByAnother } from './accountEmail'

const row = (id: string, email: string, password = '$2a$12$hash') => ({ id, name: id, email, password, role: 'standard' })

/** The SQL text of call `n`, with each bound value shown as `$`. */
const sqlOf = (n = 0) => (h.queryRaw.mock.calls[n][0] as string[]).join('$')

beforeEach(() => {
  h.queryRaw.mockReset()
  h.queryRaw.mockResolvedValue([])
})

describe('normalizeEmail', () => {
  test('stores the lowercase form', () => {
    expect(normalizeEmail('Alice.Smith@Example.COM')).toBe('alice.smith@example.com')
  })
})

describe('findSignInAccount', () => {
  test('Alice@x finds alice@x', async () => {
    h.queryRaw.mockResolvedValue([row('u1', 'alice@x')])
    expect((await findSignInAccount('Alice@x'))?.id).toBe('u1')
  })

  test('two accounts differing in case: the exact match wins', async () => {
    h.queryRaw.mockResolvedValue([row('upper', 'Alice@x'), row('lower', 'alice@x')])
    expect((await findSignInAccount('alice@x'))?.id).toBe('lower')
    expect((await findSignInAccount('Alice@x'))?.id).toBe('upper')
  })

  test('two accounts differing in case and no exact match: nobody, never a pick', async () => {
    h.queryRaw.mockResolvedValue([row('upper', 'Alice@x'), row('lower', 'alice@x')])
    expect(await findSignInAccount('ALICE@x')).toBeNull()
  })

  test('no account: null', async () => {
    expect(await findSignInAccount('nobody@x')).toBeNull()
  })

  test('one query, a lower() equality with the email bound, never a LIKE pattern', async () => {
    await findSignInAccount('a_min%@x')
    expect(h.queryRaw).toHaveBeenCalledTimes(1)
    const sql = sqlOf()
    expect(sql).toMatch(/lower\(email\)\s*=\s*lower\(\$\)/)
    expect(sql).not.toMatch(/like/i)
    expect(h.queryRaw.mock.calls[0].slice(1)).toEqual(['a_min%@x'])
    // The row carries what the sign-in needs and nothing else.
    expect(sql).toMatch(/SELECT id, name, email, password, role FROM users/)
  })

  test('a failed read throws (the route answers a coded 500)', async () => {
    h.queryRaw.mockRejectedValue(Object.assign(new Error('down'), { code: 'P1001' }))
    await expect(findSignInAccount('a@x')).rejects.toMatchObject({ code: 'P1001' })
  })
})

describe('emailTakenByAnother', () => {
  test('a case variant held by another account is taken', async () => {
    h.queryRaw.mockResolvedValue([{ id: 'other' }])
    expect(await emailTakenByAnother('alice@x', 'me')).toBe(true)
  })

  test('the account itself does not count', async () => {
    h.queryRaw.mockResolvedValue([{ id: 'me' }])
    expect(await emailTakenByAnother('alice@x', 'me')).toBe(false)
  })

  test('free when nobody holds it', async () => {
    expect(await emailTakenByAnother('alice@x')).toBe(false)
  })

  test('without an id to exclude, any holder takes it', async () => {
    h.queryRaw.mockResolvedValue([{ id: 'other' }])
    expect(await emailTakenByAnother('alice@x')).toBe(true)
  })

  test('the same lower() equality, the email bound', async () => {
    await emailTakenByAnother('Bob_1@x', 'me')
    expect(sqlOf()).toMatch(/lower\(email\)\s*=\s*lower\(\$\)/)
    expect(sqlOf()).not.toMatch(/like/i)
    expect(h.queryRaw.mock.calls[0].slice(1)).toEqual(['Bob_1@x'])
  })
})
