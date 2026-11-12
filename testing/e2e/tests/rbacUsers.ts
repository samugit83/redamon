import { execFileSync } from 'node:child_process'
import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, type BrowserContext, type Page } from '@playwright/test'

/**
 * Several seeded accounts for the RBAC specs: sign in as any of them through the
 * real login form, each in its own browser context.
 *
 * The accounts come from webapp/scripts/e2e-rbac-seed.mjs (rbac-*@e2e.local, all
 * synthetic, one fixed test password). The seed's KEY=VALUE output is kept in
 * testing/e2e/.rbac-seed.env, which tests/rbac_matrix_live.sh also writes and
 * the root .gitignore (`*.env`) keeps out of git. The two scripts are fed to the
 * webapp container on stdin, so they work against an image built before them.
 */

export type RbacLoginKey = 'ADMIN_A' | 'ADMIN_B' | 'MEMBER_A' | 'MEMBER_B' | 'MEMBER_C'
export type RbacSeed = Record<string, string>

function repoRoot(): string {
  return join(__dirname, '..', '..', '..')
}

export const RBAC_SEED_FILE = join(repoRoot(), 'testing', 'e2e', '.rbac-seed.env')

const DISCLAIMER_STORAGE_KEY = 'redamon-v2-onboarding'
const DISCLAIMER_VERSION = '2026-03-28-v2'

function runFixtureScript(name: 'e2e-rbac-seed.mjs' | 'e2e-rbac-cleanup.mjs'): string {
  const script = readFileSync(join(repoRoot(), 'webapp', 'scripts', name))
  return execFileSync(
    'docker',
    ['compose', 'exec', '-T', '-w', '/app', 'webapp', 'node', '--input-type=module', '-'],
    { cwd: repoRoot(), input: script, encoding: 'utf8' },
  )
}

export function parseRbacSeed(text: string): RbacSeed {
  const seed: RbacSeed = {}
  for (const line of text.split('\n')) {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim())
    if (m) seed[m[1]] = m[2]
  }
  return seed
}

/** Create (or reset) the fixtures and record them for loginAs. Idempotent. */
export function seedRbac(): RbacSeed {
  const out = runFixtureScript('e2e-rbac-seed.mjs')
  const seed = parseRbacSeed(out)
  if (!seed.PA_ID || !seed.RBAC_PASSWORD) throw new Error('the RBAC seed printed no fixture ids')
  writeFileSync(RBAC_SEED_FILE, out, { mode: 0o600 })
  return seed
}

/** Remove every rbac-*@e2e.local account, its projects and its audit rows. */
export function cleanupRbac(): void {
  runFixtureScript('e2e-rbac-cleanup.mjs')
  rmSync(RBAC_SEED_FILE, { force: true })
}

export function readRbacSeed(): RbacSeed {
  let text: string
  try {
    text = readFileSync(RBAC_SEED_FILE, 'utf8')
  } catch {
    throw new Error(`${RBAC_SEED_FILE} is missing: call seedRbac() first`)
  }
  return parseRbacSeed(text)
}

/** Dismiss the first-run welcome and disclaimer, which cover every page, in a context with no sign-in. */
export async function skipFirstRunScreens(context: BrowserContext): Promise<void> {
  await context.addInitScript(([storageKey, version]) => {
    localStorage.setItem(storageKey, JSON.stringify({ version, acceptedAt: new Date().toISOString() }))
  }, [DISCLAIMER_STORAGE_KEY, DISCLAIMER_VERSION])
}

/**
 * Sign in as a seeded account through the login form. Use one browser context
 * per account: contexts never share cookies, so two accounts can be open at once.
 */
export async function loginAs(page: Page, key: RbacLoginKey): Promise<void> {
  const seed = readRbacSeed()
  const email = seed[`${key}_EMAIL`]
  if (!email) throw new Error(`the RBAC seed has no ${key}_EMAIL`)
  // The first-run welcome and disclaimer cover every page, the login form included.
  await page.context().addInitScript(([storageKey, version]) => {
    localStorage.setItem(storageKey, JSON.stringify({ version, acceptedAt: new Date().toISOString() }))
  }, [DISCLAIMER_STORAGE_KEY, DISCLAIMER_VERSION])
  await page.goto('/login')
  await page.locator('#email').fill(email)
  await page.locator('#password').fill(seed.RBAC_PASSWORD)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page).not.toHaveURL(/\/login(\?|$)/, { timeout: 30_000 })
}
