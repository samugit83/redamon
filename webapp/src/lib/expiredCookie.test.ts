/**
 * A cleared cookie must leave the server expired. Next re-reads a response's Set-Cookie before
 * sending it and the re-read drops `maxAge: 0`, so every clear goes through EXPIRED_COOKIE, whose
 * past Expires survives it.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/expiredCookie.test.ts
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, test, expect } from 'vitest'
import { ResponseCookies } from 'next/dist/compiled/@edge-runtime/cookies'
import { EXPIRED_COOKIE } from './expiredCookie'

/** What Next does to a route's answer: read its cookies back from the header and write them again. */
function sentAfterNextRereads(options: Record<string, unknown>): string {
  const headers = new Headers()
  new ResponseCookies(headers).set('redamon-auth', '', { path: '/', httpOnly: true, ...options })
  const again = new ResponseCookies(headers)
  again.set(again.get('redamon-auth')!)
  return headers.get('set-cookie') ?? ''
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sourceFiles(path)
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : []
  })
}

describe('a cleared cookie', () => {
  test('maxAge: 0 alone does not survive the re-read, the past Expires does', () => {
    expect(sentAfterNextRereads({ maxAge: 0 })).not.toMatch(/Max-Age|Expires/)
    expect(sentAfterNextRereads({ ...EXPIRED_COOKIE })).toContain('Expires=Thu, 01 Jan 1970 00:00:00 GMT')
  })

  test('no source clears a cookie with a bare maxAge: 0', () => {
    const offenders = sourceFiles(join(__dirname, '..'))
      .filter((f) => !f.endsWith('expiredCookie.ts'))
      .filter((f) => /maxAge:\s*0\b/.test(readFileSync(f, 'utf8')))
    expect(offenders).toEqual([])
  })
})
