/**
 * The 12-character floor is written in more than one place because the host
 * scripts cannot import TypeScript: the standalone image copies `scripts/` as
 * plain .mjs (webapp/Dockerfile), and redamon.sh is bash. This test fails the
 * moment one of the copies drifts from passwordPolicy.ts.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'
import { MIN_PASSWORD_LENGTH } from './passwordPolicy'

const webappFile = (rel: string) => readFileSync(path.resolve(__dirname, '../../..', rel), 'utf8')
const repoFile = (rel: string) => readFileSync(path.resolve(__dirname, '../../../..', rel), 'utf8')

function onlyNumber(source: string, pattern: RegExp, where: string): number {
  const hits = [...source.matchAll(pattern)]
  expect(hits, `${where}: exactly one definition of the floor`).toHaveLength(1)
  return Number(hits[0][1])
}

describe('the password floor has one value everywhere', () => {
  test.each(['scripts/create-admin.mjs', 'scripts/reset-password.mjs'])('%s', (rel) => {
    const src = webappFile(rel)
    expect(onlyNumber(src, /const MIN_PASSWORD_LENGTH = (\d+)/g, rel)).toBe(MIN_PASSWORD_LENGTH)
    // The check reads the constant, not a second literal.
    expect(src).toMatch(/\[\.\.\.password\]\.length < MIN_PASSWORD_LENGTH/)
    expect(src).toContain('src/lib/authz/passwordPolicy.ts')
  })

  test('redamon.sh MIN_ADMIN_PASSWORD_LEN', () => {
    expect(onlyNumber(repoFile('redamon.sh'), /^MIN_ADMIN_PASSWORD_LEN=(\d+)$/gm, 'redamon.sh')).toBe(MIN_PASSWORD_LENGTH)
  })
})
