/**
 * The start-up script that moves the Tradecraft row of existing projects from the old default to
 * the new one (owner decision 2026-11-17, FIX-PHASES; R-321). What it does to the rows is proved on
 * a real Postgres (backfill-tradecraft-phases.pg.integration.test.ts); this file holds the rest:
 * the phases it moves between, its markers' labels and retention, where it runs, that it changes no
 * schema and deletes nothing, and that a failure is logged with a fixed text and never stops the boot.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { AUDIT_ACTION_LABELS } from '@/lib/authz/auditLabels'
import { keptRuleFor } from '@/lib/authz/auditRetention'
import { field } from '@/lib/reconSettings/registry'
import { CUTOFF_ACTION, MARKER_ACTION, NEW_PHASES, OLD_PHASES, main } from './backfill-tradecraft-phases.mjs'

const WEBAPP = path.resolve(__dirname, '..')
const SOURCE = readFileSync(path.join(__dirname, 'backfill-tradecraft-phases.mjs'), 'utf8')
/** The script without its comments, so the rules below read only what it runs. */
const CODE = SOURCE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')

/** A Prisma client whose transaction runs `fn` on `tx`, recording what the script asks. */
function fakePrisma(tx: Record<string, unknown>) {
  return {
    $transaction: async (fn: (t: unknown) => Promise<unknown>) => fn(tx),
    $disconnect: async () => {},
  }
}

afterEach(() => { vi.restoreAllMocks() })

describe('backfill-tradecraft-phases', () => {
  test('it moves the old default to the default new projects get', () => {
    expect(OLD_PHASES).toEqual(['exploitation', 'post_exploitation'])
    expect(JSON.parse(String(field('agentToolPhaseMap')!.default)).tradecraft_lookup).toEqual(NEW_PHASES)
  })

  test('its markers are labelled and retention never deletes them (a marker gone would run it again)', () => {
    for (const action of [CUTOFF_ACTION, MARKER_ACTION]) {
      expect(action).toMatch(/^system\./)
      expect(AUDIT_ACTION_LABELS[action]?.group, action).toBe('system')
      expect(keptRuleFor(action), action).not.toBeNull()
      expect(keptRuleFor(action)?.scope, action).toBeUndefined()
    }
  })

  test('the image runs it at every start, after db push and before the server, never fatal', () => {
    const docker = readFileSync(path.join(WEBAPP, 'Dockerfile'), 'utf8')
    const entry = docker.match(/RUN printf '(#!\/bin\/sh[^']*)'/)?.[1] ?? ''
    const at = entry.indexOf('node scripts/backfill-tradecraft-phases.mjs 2>&1\\n')
    expect(at).toBeGreaterThan(entry.indexOf('db push'))
    expect(entry.indexOf('db push')).toBeGreaterThan(-1)
    expect(at).toBeLessThan(entry.indexOf('exec node scripts/serve.cjs'))
    // The dev container's list equals this one: tests/webapp_dev_startup_parity_test.sh.
  })

  test('it changes no schema and deletes nothing', () => {
    expect(CODE).not.toMatch(/\b(DROP|DELETE|TRUNCATE|ALTER|CREATE|INSERT)\b/)
    expect(CODE).not.toMatch(/accept-data-loss|\.delete(Many)?\(|db push|\$executeRawUnsafe/i)
    expect(CODE.match(/\bUPDATE\s+projects\b/gi)).toHaveLength(1)
  })

  test('the marker keeps the moved ids, sorted; the log line carries the count only', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    const create = vi.fn(async () => ({ createdAt: new Date('2026-11-17T00:00:00Z') }))
    const tx = {
      $executeRaw: vi.fn(async () => 1),
      $queryRaw: vi.fn(async () => [{ id: 'p-c' }, { id: 'p-a' }, { id: 'p-b' }]),
      auditLog: { findFirst: vi.fn(async () => null), create },
    }
    await main(fakePrisma(tx) as never)
    expect(log).toHaveBeenCalledTimes(1)
    const line = log.mock.calls[0].join(' ')
    expect(line).toMatch(/^\[tradecraft\] phases_default_moved projects=3\b/)
    expect(line).not.toMatch(/p-[abc]/)
    expect(create).toHaveBeenCalledWith({
      data: expect.objectContaining({ action: MARKER_ACTION, after: { projects: 3, ids: ['p-a', 'p-b', 'p-c'] } }),
    })
  })

  test('a failure is logged with a fixed text, writes no marker, and the boot goes on', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    // The cut-off is written; the update then fails.
    const create = vi.fn(async () => ({ createdAt: new Date('2026-11-17T00:00:00Z') }))
    const tx = {
      $executeRaw: vi.fn(async () => 1),
      $queryRaw: vi.fn(async () => { throw new Error('canceling statement: "projects" row (id)=(p-1) ...') }),
      auditLog: { findFirst: vi.fn(async () => null), create },
    }
    await expect(main(fakePrisma(tx) as never)).resolves.toBeUndefined()
    expect(error).toHaveBeenCalledTimes(1)
    const line = error.mock.calls[0].join(' ')
    expect(line).toMatch(/^\[tradecraft\] phases_default_failed code=Error\b/)
    expect(line).not.toContain('p-1')
    expect(create).toHaveBeenCalledWith({ data: expect.objectContaining({ action: CUTOFF_ACTION }) })
    expect(create).not.toHaveBeenCalledWith({ data: expect.objectContaining({ action: MARKER_ACTION }) })
  })
})
