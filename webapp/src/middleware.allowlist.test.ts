/**
 * S2/E2 — internal-key route allowlist (middleware scoping): what the key must
 * NOT open. That every route the Python services call IS open is computed from
 * their source in middleware.internalCallers.test.ts.
 * Run: npx vitest run src/middleware.allowlist.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { internalKeyRouteAllowed, scannerKeyRouteAllowed } from './middleware'

describe('internalKeyRouteAllowed — off-allowlist routes are NOT allowed', () => {
  test.each([
    ['POST', '/api/users'],                       // mint-admin path
    ['PUT', '/api/users/abc'],                     // user update
    ['DELETE', '/api/users/abc'],                  // user delete
    ['POST', '/api/users/abc/llm-providers'],      // add provider (write)
    ['GET', '/api/users'],                         // list all users
    ['GET', '/api/analytics/redzone'],             // arbitrary route
    ['POST', '/api/users/abc/settings'],           // settings is GET-only for the key
    ['POST', '/api/internal/capture-config'],      // capture-config is GET-only
    ['GET', '/api/internal/supply-chain/guarddog'], // guarddog is POST-only
    ['GET', '/api/projects'],                      // projects LIST (only /[id] allowed)
  ])('%s %s → NOT allowed', (method, path) => {
    expect(internalKeyRouteAllowed(method, path)).toBe(false)
  })
})

// The agent reads a node-filter run, heartbeats it and records its end with the
// internal key. If the middleware blocked any of the three, every apply would
// die as agent_lost while the UI waited on it.
describe('node-filter apply runs: the three agent callbacks and nothing else', () => {
  test.each([
    ['GET', '/api/internal/node-filter-runs/run1', true],
    ['POST', '/api/internal/node-filter-runs/run1/heartbeat', true],
    ['POST', '/api/internal/node-filter-runs/run1/finish', true],
    ['POST', '/api/internal/node-filter-runs/run1', false],
    ['DELETE', '/api/internal/node-filter-runs/run1', false],
    ['GET', '/api/internal/node-filter-runs/run1/heartbeat', false],
    ['GET', '/api/internal/node-filter-runs/run1/finish', false],
    ['POST', '/api/internal/node-filter-runs', false],
    ['POST', '/api/internal/node-filter-runs/run1/finish/../../../users/x', false],
  ])('%s %s → %s', (method, path, allowed) => {
    expect(internalKeyRouteAllowed(method, path)).toBe(allowed)
    // Scan containers hold the scanner key; a run's rules are not theirs.
    expect(scannerKeyRouteAllowed(method, path)).toBe(false)
  })
})

// The agent reads a run's tradecraft catalog when the run starts (T1.12). The route checks the key
// itself; the allowlist opens exactly that GET, and the scanner key never.
describe('the tradecraft run catalog: one GET for the agent', () => {
  test.each([
    ['GET', '/api/internal/agent/tradecraft/catalog', true],
    ['POST', '/api/internal/agent/tradecraft/catalog', false],
    ['GET', '/api/internal/agent/tradecraft/catalog/extra', false],
    ['GET', '/api/internal/agent/tradecraft', false],
    ['GET', '/api/internal/agent/tradecraft/catalog/../../../users/x/settings', false],
  ])('%s %s → %s', (method, path, allowed) => {
    expect(internalKeyRouteAllowed(method, path)).toBe(allowed)
    expect(scannerKeyRouteAllowed(method, path)).toBe(false)
  })
})

describe('scannerKeyRouteAllowed — S3/E6 scoped scanner token', () => {
  test.each([
    ['GET', '/api/users/abc/llm-providers'],       // key harvest — MUST be blocked
    ['GET', '/api/users/abc/tradecraft-resources'],
    ['POST', '/api/users'],                        // mint-admin — MUST be blocked
    ['PUT', '/api/users/abc'],
    ['POST', '/api/internal/codefix-sandbox/j/exec'],
    ['POST', '/api/remediations'],
    ['GET', '/api/global/tunnel-config'],
    ['POST', '/api/users/abc/settings'],           // scanner is GET-only
    ['GET', '/api/traffic/p1/ingest'],             // ingest is POST-only
    ['POST', '/api/traffic/p1'],                    // list route is not a write target
    ['GET', '/api/traffic/p1'],                     // read routes use JWT, not scanner key
  ])('%s %s → NOT allowed for scanner', (method, path) => {
    expect(scannerKeyRouteAllowed(method, path)).toBe(false)
  })
})

describe('traffic-capture ingest route allowlisting', () => {
  test('scanner key may POST the ingest route (recon capture)', () => {
    expect(scannerKeyRouteAllowed('POST', '/api/traffic/proj-123/ingest')).toBe(true)
  })
  test('internal key may POST the ingest route (agent capture, Phase 1)', () => {
    expect(internalKeyRouteAllowed('POST', '/api/traffic/proj-123/ingest')).toBe(true)
  })
  test('ingest allowlisting does not leak to the read routes', () => {
    // Only /ingest is opened; the tenant-scoped read routes stay JWT-only.
    expect(scannerKeyRouteAllowed('GET', '/api/traffic/proj-123')).toBe(false)
    expect(scannerKeyRouteAllowed('GET', '/api/traffic/proj-123/facets')).toBe(false)
    expect(internalKeyRouteAllowed('GET', '/api/traffic/proj-123/some-id')).toBe(false)
  })
  test('cannot smuggle a different route via the projectId segment', () => {
    // The [^/]+ segment cannot contain a slash, so no path traversal into other APIs.
    expect(scannerKeyRouteAllowed('POST', '/api/traffic/p1/ingest/../../users/x/settings')).toBe(false)
  })
})
