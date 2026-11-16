import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, type Page } from '@playwright/test'

/**
 * The Tradecraft 2.0 specs' fixtures (T4.10): one synthetic account with 2.0 on, three resources
 * and a project, written straight into the database by webapp/scripts/e2e-tradecraft-seed.mjs and
 * removed by e2e-tradecraft-cleanup.mjs. No agent and no site is reached. The scripts are fed to
 * the webapp container on stdin, so they run against an image built before them.
 */

export type TradecraftSeed = Record<'TC_USER_ID' | 'TC_EMAIL' | 'TC_PASSWORD' | 'TC_PROJECT_ID' | 'TC_WIKI_ID' | 'TC_BLOG_ID' | 'TC_DISABLED_ID', string>

const REPO = join(__dirname, '..', '..', '..')
const DISCLAIMER_STORAGE_KEY = 'redamon-v2-onboarding'
const DISCLAIMER_VERSION = '2026-03-28-v2'

function run(name: 'e2e-tradecraft-seed.mjs' | 'e2e-tradecraft-cleanup.mjs'): string {
  return execFileSync(
    'docker',
    ['compose', 'exec', '-T', '-w', '/app', 'webapp', 'node', '--input-type=module', '-'],
    { cwd: REPO, input: readFileSync(join(REPO, 'webapp', 'scripts', name)), encoding: 'utf8' },
  )
}

function parse(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const m = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim())
    if (m) out[m[1]] = m[2]
  }
  return out
}

/** Writes the fixtures again from scratch; idempotent. */
export function seedTradecraft(): TradecraftSeed {
  const seed = parse(run('e2e-tradecraft-seed.mjs'))
  if (!seed.TC_USER_ID || !seed.TC_PROJECT_ID) throw new Error('the Tradecraft seed printed no fixture ids')
  return seed as TradecraftSeed
}

export function cleanupTradecraft(): void {
  const out = parse(run('e2e-tradecraft-cleanup.mjs'))
  if (out.TC_RESOURCES_LEFT !== '0') throw new Error(`the Tradecraft cleanup left ${out.TC_RESOURCES_LEFT} resources`)
}

/** Signs in as the seeded account through the login form; the first-run screens are dismissed. */
export async function loginTradecraft(page: Page, seed: TradecraftSeed): Promise<void> {
  await page.context().addInitScript(([key, version]) => {
    localStorage.setItem(key, JSON.stringify({ version, acceptedAt: new Date().toISOString() }))
    localStorage.setItem('redamon-github-star-dismissed', '1')
  }, [DISCLAIMER_STORAGE_KEY, DISCLAIMER_VERSION])
  await page.goto('/login')
  await page.locator('#email').fill(seed.TC_EMAIL)
  await page.locator('#password').fill(seed.TC_PASSWORD)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page).not.toHaveURL(/\/login(\?|$)/, { timeout: 30_000 })
}

/** Opens the chat drawer of a project (the pattern of agentInTheLoop.spec.ts). */
export async function openChatDrawer(page: Page, projectId: string): Promise<void> {
  await page.goto(`/graph?project=${projectId}`)
  await page.waitForFunction(() => document.documentElement.style.getPropertyValue('--drawer-bottom') !== '')
  const gear = page.getByTitle('Agent settings')
  await expect(async () => {
    if (!(await gear.isVisible())) await page.getByRole('button', { name: 'Toggle AI Agent' }).click()
    await expect(gear).toBeVisible({ timeout: 3_000 })
    await page.waitForTimeout(500)
    await expect(gear).toBeVisible()
  }).toPass({ timeout: 60_000 })
}
