import neo4j, { Driver, Session } from 'neo4j-driver'

// Derived from the Session type rather than imported by name: `TransactionConfig`
// is re-exported from neo4j-driver-core, not the `neo4j-driver` entry point, and
// this stays correct if that moves again.
type RunArgs = Parameters<Session['run']>
type TxConfig = NonNullable<RunArgs[2]>

declare global {
  var neo4jDriver: Driver | undefined
  var neo4jShutdownHooked: boolean | undefined
}

const uri = process.env.NEO4J_URI || 'bolt://localhost:7687'
const user = process.env.NEO4J_USER || 'neo4j'
const password = process.env.NEO4J_PASSWORD || 'password'

// Server-side ceiling on a single Cypher query. The driver's connectionTimeout /
// connectionAcquisitionTimeout only bound ACQUIRING a connection; once a session
// holds one, an unbounded query (e.g. a whole-graph read on a 300K-node project)
// runs forever, leaving the HTTP request pending indefinitely and pinning a
// pooled connection the whole time. Generous by default -- this exists to stop
// "forever", not to police slow-but-legitimate reads.
const DEFAULT_QUERY_TIMEOUT_MS = 120_000

function queryTimeoutMs(): number {
  const raw = Number(process.env.NEO4J_QUERY_TIMEOUT_MS)
  // 0 / negative / unset / garbage -> the default. Set a huge value to opt out.
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_QUERY_TIMEOUT_MS
}

function createDriver(): Driver {
  return neo4j.driver(uri, neo4j.auth.basic(user, password), {
    // With a single shared driver (below) this is a real GLOBAL ceiling on
    // concurrent Bolt connections from the webapp, not a per-request multiplier.
    maxConnectionPoolSize: 50,
    connectionAcquisitionTimeout: 30000,
    connectionTimeout: 30000,
  })
}

/**
 * The shared driver.
 *
 * A neo4j `Driver` is designed to be long-lived and shared: it owns the
 * connection pool. This used to return a FRESH driver on every call when
 * NODE_ENV=production (only development reused the singleton), so every request
 * built a new pool of up to `maxConnectionPoolSize` Bolt connections and
 * abandoned it -- `closeDriver()` is never called per-request. That leaked
 * connections and memory continuously and produced Neo4j's
 * "Increase in network aborts detected" on a busy instance.
 *
 * All environments now share one instance. `global` (not a module-level `let`)
 * because Next.js dev hot-reload re-evaluates the module and would otherwise
 * strand the previous driver.
 */
export function getDriver(): Driver {
  if (!global.neo4jDriver) {
    global.neo4jDriver = createDriver()
    registerShutdownHook()
  }
  return global.neo4jDriver
}

export interface GraphSessionOptions {
  /**
   * A read-only session: Neo4j itself refuses any write in it
   * (Neo.ClientError.Statement.AccessMode). For a query the caller typed, where
   * a text check alone cannot be the only thing between it and a write.
   */
  readOnly?: boolean
}

/**
 * A session whose `run()` carries a default query timeout.
 *
 * Wrapped in a Proxy rather than changing ~20 call sites across 8 route files:
 * every other Session member (close, executeRead, beginTransaction, ...) passes
 * through untouched, and a caller that supplies its own TransactionConfig still
 * wins.
 */
export function getGraphSession({ readOnly = false }: GraphSessionOptions = {}): Session {
  const driver = getDriver()
  // 'READ' is neo4j.session.READ, spelled out so a driver double needs no constants.
  const session = readOnly ? driver.session({ defaultAccessMode: 'READ' }) : driver.session()
  const timeout = queryTimeoutMs()

  return new Proxy(session, {
    get(target, prop, receiver) {
      if (prop !== 'run') return Reflect.get(target, prop, receiver)
      return (query: RunArgs[0], params?: RunArgs[1], config?: TxConfig) =>
        // Caller-supplied config wins, so an explicit `{ timeout: ... }` (or a
        // deliberate opt-out) is never silently overridden.
        target.run(query, params, { timeout, ...(config ?? {}) })
    },
  })
}

export async function closeDriver(): Promise<void> {
  if (global.neo4jDriver) {
    await global.neo4jDriver.close()
    global.neo4jDriver = undefined
  }
}

// Drain the pool on shutdown so Neo4j does not see the connections drop as
// aborts. Guarded by a global flag: the module is re-evaluated on dev
// hot-reload, and re-registering would leak process listeners until Node warns.
function registerShutdownHook(): void {
  if (global.neo4jShutdownHooked) return
  if (typeof process === 'undefined' || typeof process.once !== 'function') return
  global.neo4jShutdownHooked = true
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.once(signal, () => {
      void closeDriver()
    })
  }
}

export async function verifyConnection(): Promise<boolean> {
  const driver = getDriver()
  try {
    await driver.verifyConnectivity()
    return true
  } catch (error) {
    console.error('Neo4j connection failed:', error)
    return false
  }
}

export { neo4j }
