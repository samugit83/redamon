import { test, expect } from '@playwright/test'
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { redactRequestErrors, redactSecrets, redactedError } from './perUserSandboxFixtures'

/**
 * The e2e fixtures never print a credential when a call fails: a Playwright API call's failure
 * carries its call log, the request's headers (the test account's `redamon-auth` session cookie,
 * the internal key) among them, each line wrapped in ANSI dim codes inside the runner. Every value
 * here is synthetic. No stack, no page: the last test runs a nested Playwright run against a
 * closed local port.
 */

const PLANTED = ['synthetic-internal-key-0001', 'synthetic-bearer-0002', 'synthetic-cookie-0003', 'synthetic-ticket-0004']

/** Verbatim: the message of `api.get()` on a context with these headers, cookie and query,
 *  caught inside the runner (Playwright 1.62.1). */
const CAPTURED = "apiRequestContext.get: connect ECONNREFUSED 127.0.0.1:9\nCall log:\n\u001b[2m  - \u2192 GET http://127.0.0.1:9/api/agent/sessions?ticket=synthetic-ticket-0004\u001b[22m\n\u001b[2m    - user-agent: Playwright/1.62.1 (x64; ubuntu 24.04) node/23.10\u001b[22m\n\u001b[2m    - accept: */*\u001b[22m\n\u001b[2m    - accept-encoding: gzip,deflate,br\u001b[22m\n\u001b[2m    - X-Internal-Key: synthetic-internal-key-0001\u001b[22m\n\u001b[2m    - Authorization: Bearer synthetic-bearer-0002\u001b[22m\n\u001b[2m    - cookie: redamon-auth=synthetic-cookie-0003\u001b[22m\n"

test('a call log captured in the runner keeps its shape and loses every credential', () => {
  const out = redactSecrets(CAPTURED)
  for (const secret of PLANTED) expect(out).not.toContain(secret)
  expect(out).not.toContain('\u001b[')
  expect(out).toContain('GET http://127.0.0.1:9/api/agent/sessions?ticket=[redacted]')
  expect(out).toContain('- cookie: [redacted]')
  expect(out).toContain('- X-Internal-Key: [redacted]')
  expect(out).toContain('- Authorization: [redacted]')
  expect(out).toContain('- accept: */*')
})

test('values outside a header line are redacted too', () => {
  expect(redactSecrets('set redamon-auth=abc.def; x=1 then')).toBe('set redamon-auth=[redacted]; x=1 then')
  expect(redactSecrets('sent Bearer abc.def-123 to it')).toBe('sent Bearer [redacted] to it')
  expect(redactSecrets('ticket=t-123&x=1')).toBe('ticket=[redacted]&x=1')
  expect(redactSecrets('nothing secret here: 404')).toBe('nothing secret here: 404')
  expect(redactedError('plain Bearer x.y').message).toBe('plain Bearer [redacted]')
})

test('a guarded context\'s real failing call throws a redacted error', async ({ playwright }) => {
  const api = redactRequestErrors(await playwright.request.newContext({
    baseURL: 'http://127.0.0.1:9',
    extraHTTPHeaders: { 'X-Internal-Key': PLANTED[0], Authorization: `Bearer ${PLANTED[1]}` },
    storageState: { cookies: [{ name: 'redamon-auth', value: PLANTED[2], domain: '127.0.0.1', path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }], origins: [] },
  }))
  try {
    const err = await api.get(`/api/agent/sessions?ticket=${PLANTED[3]}`).then(() => null, (e: Error) => e)
    expect(err, 'a closed port fails the call').toBeInstanceOf(Error)
    const printed = [err!.message, err!.stack ?? '', JSON.stringify((err as Error & { log?: unknown }).log ?? [])].join('\n')
    for (const secret of PLANTED) expect(printed).not.toContain(secret)
  } finally {
    await api.dispose()
  }
})

const NESTED_SPEC = (fixtures: string) => `import { test } from '@playwright/test'
import { redactRequestErrors } from ${JSON.stringify(fixtures)}
test('fails through a guarded context', async ({ playwright }) => {
  const api = redactRequestErrors(await playwright.request.newContext({
    baseURL: 'http://127.0.0.1:9',
    extraHTTPHeaders: { 'X-Internal-Key': ${JSON.stringify(PLANTED[0])}, Authorization: 'Bearer ${PLANTED[1]}' },
    storageState: { cookies: [{ name: 'redamon-auth', value: ${JSON.stringify(PLANTED[2])}, domain: '127.0.0.1', path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }], origins: [] },
  }))
  await api.get('/api/agent/sessions?ticket=${PLANTED[3]}')
})
`

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? filesUnder(path) : [path]
  })
}

test('a failing test prints, and its error-context.md holds, none of the planted values', () => {
  test.setTimeout(120_000)
  // Inside testing/e2e (an ignored results folder), so the nested spec resolves
  // @playwright/test from its node_modules.
  const parent = join(__dirname, '..', 'test-results-g1e2e')
  mkdirSync(parent, { recursive: true })
  const dir = mkdtempSync(join(parent, 'redact-check-'))
  try {
    writeFileSync(join(dir, 'nested.spec.ts'), NESTED_SPEC(join(__dirname, 'perUserSandboxFixtures')))
    writeFileSync(join(dir, 'nested.config.ts'),
      "import { defineConfig } from '@playwright/test'\nexport default defineConfig({ testDir: '.', outputDir: './out', reporter: [['list']], retries: 0 })\n")
    const run = spawnSync('npx', ['playwright', 'test', '-c', join(dir, 'nested.config.ts')],
      { cwd: join(__dirname, '..'), encoding: 'utf8', timeout: 100_000, env: { ...process.env, FORCE_COLOR: '1' } })
    const printed = `${run.stdout}\n${run.stderr}`
    expect(run.status, `the nested test fails as planned:\n${redactSecrets(printed).slice(-600)}`).toBe(1)
    expect(printed).toContain('ECONNREFUSED')
    const contexts = filesUnder(join(dir, 'out')).filter((f) => f.endsWith('error-context.md'))
    expect(contexts.length, 'Playwright wrote the failure\'s error-context.md').toBeGreaterThan(0)
    const written = contexts.map((f) => readFileSync(f, 'utf8')).join('\n')
    for (const secret of PLANTED) {
      expect(printed, 'the reporter\'s output').not.toContain(secret)
      expect(written, 'error-context.md').not.toContain(secret)
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
