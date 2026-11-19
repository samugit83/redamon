/**
 * U2 (§12, R-240, AC-46): the CVE (MSF) skill starts off in a new project, and a project
 * that saved it on keeps it on. The form's fallback, the Prisma default and the agent's
 * default say the same (agentic/tests/test_prisma_default_parity.py holds the agent side).
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'

vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))
vi.mock('@/components/ui/AlertModal', () => ({ useAlertModal: () => ({ alert: vi.fn(), alertError: vi.fn() }) }))

import { AttackSkillsSection } from './AttackSkillsSection'

type FormData = React.ComponentProps<typeof AttackSkillsSection>['data']

function draw(over: Partial<FormData> = {}) {
  render(<AttackSkillsSection data={{ hydraEnabled: false, ...over } as FormData} updateField={vi.fn()} />)
}

const cveSwitch = async () => screen.findByRole('switch', { name: 'CVE (MSF)' })

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([]), { status: 200 })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('CVE (MSF) default', () => {
  test('new_project_shows_cve_off: no saved config falls back to off', async () => {
    draw({ attackSkillConfig: undefined as unknown as FormData['attackSkillConfig'] })
    expect(await cveSwitch()).toHaveAttribute('aria-checked', 'false')
    // The other defaults are unchanged: SQL injection still starts on.
    expect(screen.getByRole('switch', { name: 'SQL Injection' })).toHaveAttribute('aria-checked', 'true')
  })

  test('a saved config without the key shows off, as the agent reads a missing key', async () => {
    draw({ attackSkillConfig: { builtIn: { sql_injection: true }, user: {} } as unknown as FormData['attackSkillConfig'] })
    expect(await cveSwitch()).toHaveAttribute('aria-checked', 'false')
  })

  test('saved_config_with_cve_on_stays_on', async () => {
    draw({ attackSkillConfig: { builtIn: { cve_exploit: true }, user: {} } as unknown as FormData['attackSkillConfig'] })
    expect(await cveSwitch()).toHaveAttribute('aria-checked', 'true')
  })

  test('the Prisma default for new rows has cve_exploit false and the risky skills still off', () => {
    const schema = readFileSync(path.resolve(__dirname, '../../../../../prisma/schema.prisma'), 'utf8')
    const line = schema.split('\n').find(l => /^\s*attackSkillConfig\s+Json\s+@default\(/.test(l))!
    const raw = line.match(/@default\("((?:[^"\\]|\\.)*)"\)/)![1].replace(/\\"/g, '"')
    const builtIn = JSON.parse(raw).builtIn
    expect(builtIn.cve_exploit).toBe(false)
    expect(builtIn.sql_injection).toBe(true)
    for (const off of ['brute_force_credential_guess', 'phishing_social_engineering', 'denial_of_service']) expect(builtIn[off]).toBe(false)
  })
})
