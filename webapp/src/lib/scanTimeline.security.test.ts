/**
 * Scan Timeline — security invariants across the whole feature (plan Section 8).
 *
 * A meta-test over the source: every new endpoint the feature adds must carry its
 * guard, and the ones that take a client-supplied version/schedule id must ALSO
 * prove object ownership. This is the check that keeps a future route from being
 * added to these directories without one — a grep a reviewer would otherwise have
 * to remember to run.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import path from 'path'

const API = path.resolve(__dirname, '../app/api')

function routeFiles(dir: string): string[] {
  const abs = path.join(API, dir)
  const out: string[] = []
  const walk = (d: string) => {
    for (const entry of readdirSync(d)) {
      const p = path.join(d, entry)
      if (statSync(p).isDirectory()) walk(p)
      else if (entry === 'route.ts') out.push(p)
    }
  }
  walk(abs)
  return out
}

const PROJECT_SCOPED = [
  'projects/[id]/versions',
  'projects/[id]/delta',
  'projects/[id]/schedules',
]
const INTERNAL = ['internal/scan-schedules']

describe('every project-scoped Scan Timeline route proves project ownership', () => {
  const files = PROJECT_SCOPED.flatMap(routeFiles)

  test('the expected routes exist', () => {
    expect(files.length).toBeGreaterThanOrEqual(6)
  })

  // Step 3.8: the routes ask requirePermission on their project, whose check is the same
  // projectAccess() rule requireEffectiveUser + requireProjectAccess made; every handler names it.
  test.each(PROJECT_SCOPED.flatMap(d => routeFiles(d).map(f => [path.relative(API, f), f] as const)))(
    '%s checks the project in every handler (requirePermission with its projectId)',
    (_rel, file) => {
      const src = readFileSync(file, 'utf8')
      const handlers = src.split(/^export (?:async function|const) (?:GET|HEAD|POST|PUT|PATCH|DELETE)\b/m).slice(1)
      expect(handlers.length).toBeGreaterThan(0)
      for (const handler of handlers) {
        expect(handler).toMatch(/requirePermission\(\s*\w+,\s*'[a-z_]+:[a-z_]+',\s*\{\s*projectId\b/)
      }
    }
  )
})

describe('routes that accept a client-supplied object id also prove object ownership', () => {
  const cases: Array<[string, string]> = [
    ['versions/[versionId]/route.ts', 'requireVersionInProject'],
    ['versions/[versionId]/graph/route.ts', 'requireVersionInProject'],
    ['versions/[versionId]/activate/route.ts', 'requireVersionInProject'],
    ['delta/route.ts', 'resolveVersionSelector'],
    ['schedules/[scheduleId]/route.ts', 'loadOwnedSchedule'],
  ]

  test.each(cases)('%s uses %s (anti-IDOR)', (rel, guard) => {
    const file = path.join(API, 'projects/[id]', rel)
    expect(readFileSync(file, 'utf8')).toContain(guard)
  })
})

describe('the scheduler internal API is internal-key only', () => {
  test.each(INTERNAL.flatMap(d => routeFiles(d).map(f => [path.relative(API, f), f] as const)))(
    '%s gates on isInternalRequest',
    (_rel, file) => {
      const src = readFileSync(file, 'utf8')
      expect(src).toContain('isInternalRequest')
      // It must NOT be reachable with a plain user session.
      expect(src).not.toContain('requireProjectAccess')
    }
  )

  test('the middleware allowlist covers exactly the scheduler internal routes', async () => {
    const { internalKeyRouteAllowed } = await import('@/middleware')
    expect(internalKeyRouteAllowed('GET', '/api/internal/scan-schedules/due')).toBe(true)
    expect(internalKeyRouteAllowed('POST', '/api/internal/scan-schedules/s1/run')).toBe(true)
    // The /defer route was removed in Scan Queue Phase 4 (temporary refusals now
    // enqueue), so it is no longer allowlisted.
    expect(internalKeyRouteAllowed('POST', '/api/internal/scan-schedules/s1/defer')).toBe(false)
    // Nothing wider than that.
    expect(internalKeyRouteAllowed('POST', '/api/internal/scan-schedules/due')).toBe(false)
    expect(internalKeyRouteAllowed('DELETE', '/api/internal/scan-schedules/s1/run')).toBe(false)
    expect(internalKeyRouteAllowed('POST', '/api/internal/scan-schedules/s1/anything')).toBe(false)
    expect(internalKeyRouteAllowed('GET', '/api/projects/p1/versions')).toBe(false)
  })
})

describe('snapshot contents never reach an audit row', () => {
  // Audit entries are long-lived and widely readable; recon graphs carry banners,
  // secrets and credentials. Only ids, counts and labels may be recorded.
  const AUDIT_SOURCES = [
    'scanTimeline.ts',
    '../app/api/projects/[id]/versions/route.ts',
    '../app/api/projects/[id]/versions/[versionId]/route.ts',
    '../app/api/projects/[id]/versions/[versionId]/activate/route.ts',
  ]

  test.each(AUDIT_SOURCES)('%s passes no payload into writeAudit', rel => {
    const src = readFileSync(path.resolve(__dirname, rel), 'utf8')
    const blocks = src.split('writeAudit(').slice(1)
    for (const block of blocks) {
      const body = block.slice(0, block.indexOf('})'))
      expect(body).not.toMatch(/\b(nodes|relationships|snapshot|properties|payload|captured)\b\s*[,:}]/)
    }
  })
})

describe('no snapshot contents are logged', () => {
  test.each([
    'scanSnapshot.ts',
    'scanTimeline.ts',
    'graphRestore.ts',
  ])('%s never logs a payload', file => {
    const src = readFileSync(path.resolve(__dirname, file), 'utf8')
    for (const line of src.split('\n')) {
      if (!/console\.(log|info|warn|error)/.test(line)) continue
      // Counts + ids are fine; the node/relationship payloads are not.
      expect(line).not.toMatch(/\b(payload|snapshot\.nodes|captured\.nodes|nodes\)|relationships\))/)
    }
  })
})
