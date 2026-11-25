/**
 * The boot-time clamp of stored review budgets (scripts/clamp-triage-review-budget.mjs).
 *
 * An update never migrates rows, so a budget stored before the 1000 bound
 * existed is brought into range by the webapp entrypoint on its next start.
 * Two things make that true, and each can drift on its own: the script clamps
 * to the SAME limit the run and the settings validator use, and the entrypoint
 * runs it after a schema push that must have succeeded.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

import { field } from '@/lib/reconSettings/registry'
import { MAX_REVIEW_BUDGET } from './limits'
import { MAX_REVIEW_BUDGET as SCRIPT_MAX } from '../../../scripts/clamp-triage-review-budget.mjs'

describe('the boot-time review budget clamp', () => {
  test('clamps to the limit the run and the registry use', () => {
    expect(SCRIPT_MAX).toBe(MAX_REVIEW_BUDGET)
    expect(field('triageReviewBudget')?.bounds?.max).toBe(MAX_REVIEW_BUDGET)
  })

  test('the entrypoint pushes the schema fatally, then clamps, then serves', () => {
    const dockerfile = readFileSync(path.resolve(__dirname, '../../../Dockerfile'), 'utf8')
    const entry = dockerfile.split('\n').find((line) => line.includes('> /app/entrypoint.sh')) ?? ''
    // A push that fails and is ignored serves code against missing columns.
    expect(entry).toMatch(/db push [^\\]*\|\| exit 1\\n/)
    const push = entry.indexOf('db push')
    const clamp = entry.indexOf('node scripts/clamp-triage-review-budget.mjs')
    expect(push).toBeGreaterThan(-1)
    expect(clamp).toBeGreaterThan(push)
    expect(entry.indexOf('exec node scripts/serve.cjs')).toBeGreaterThan(clamp)
  })
})
