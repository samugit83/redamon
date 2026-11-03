import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, type Page } from '@playwright/test'

/**
 * Sign in through the real login form, with the UI_LOGIN_USERNAME /
 * UI_LOGIN_PASSWORD of the repository .env. Values are never logged.
 */

function repoRoot(): string {
  return join(__dirname, '..', '..', '..')
}

export function envValue(name: string): string {
  let text = ''
  try {
    text = readFileSync(join(repoRoot(), '.env'), 'utf8')
  } catch {
    return ''
  }
  const line = text.split('\n').find(l => l.startsWith(`${name}=`))
  if (!line) return ''
  return line.slice(name.length + 1).trim().replace(/^["']|["']$/g, '')
}

export async function loginThroughUi(page: Page): Promise<void> {
  await page.goto('/login')
  await page.locator('#email').fill(envValue('UI_LOGIN_USERNAME'))
  await page.locator('#password').fill(envValue('UI_LOGIN_PASSWORD'))
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page).not.toHaveURL(/\/login(\?|$)/, { timeout: 30_000 })
}
