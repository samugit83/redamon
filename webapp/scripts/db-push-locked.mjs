/**
 * `prisma db push` behind a Postgres advisory lock, so webapp copies booting together over
 * one database push the schema one at a time.
 *
 * Two copies of a new image starting over an older database both diff the schema and both
 * ALTER the same new columns; the second fails with "column ... already exists" and, the
 * push being fatal in the startup list, that copy exits and restarts (master plan §9.6,
 * "Several copies"). Prisma's `db push` takes no lock of its own. Under this one the second
 * copy waits, then finds the schema in sync and pushes nothing.
 *
 * The lock is session-level, taken on a client of its own limited to one connection, so the
 * lock and its unlock run on the same session; a copy that dies mid-push closes that
 * connection and Postgres releases the lock with it. It is released after the push
 * whatever the push did.
 *
 * Usage, from the image entrypoint and the dev command (the arguments are Prisma's):
 *   node scripts/db-push-locked.mjs db push [prisma options]
 * Exits with the push's code (the lists keep `|| exit 1`), 1 when the lock cannot be taken
 * (Postgres not reachable yet: the container restarts, as a failed push did), 2 on usage.
 */
import { spawn } from 'node:child_process'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { PrismaClient } from '@prisma/client'

export const LOCK_NAME = 'prisma-db-push'
// The CLI the image installs next to the server (webapp/Dockerfile), relative to /app.
export const PRISMA_CLI = path.join('node_modules', 'prisma', 'build', 'index.js')

/**
 * DATABASE_URL with `connection_limit=1`. Other parameters are kept as written: re-encoding
 * them (URLSearchParams turns `%20` into `+`) could change what Prisma reads.
 * @param {string} url
 * @returns {string}
 */
export function singleConnectionUrl(url) {
  const q = url.indexOf('?')
  const base = q < 0 ? url : url.slice(0, q)
  const params = (q < 0 ? '' : url.slice(q + 1)).split('&').filter((p) => p && !p.startsWith('connection_limit='))
  return `${base}?${[...params, 'connection_limit=1'].join('&')}`
}

/**
 * Runs `push` holding the lock and returns its exit code. Rejects before pushing when the
 * lock cannot be taken; a push that throws still releases the lock.
 * @param {{ $queryRaw: Function, $executeRaw: Function }} db a client with one connection
 * @param {() => Promise<number>} push
 * @param {{ log: Function, warn: Function }} [log]
 * @returns {Promise<number>}
 */
export async function pushUnderLock(db, push, log = console) {
  try {
    const [{ locked }] = await db.$queryRaw`SELECT pg_try_advisory_lock(hashtext(${LOCK_NAME})) AS locked`
    if (!locked) {
      log.log('[db-push] another webapp copy is pushing the schema; waiting for it to finish')
      const started = Date.now()
      // $executeRaw: Prisma cannot read the void this returns as a row.
      await db.$executeRaw`SELECT pg_advisory_lock(hashtext(${LOCK_NAME}))`
      log.log(`[db-push] the other copy finished after ${Math.round((Date.now() - started) / 1000)}s; pushing`)
    }
  } catch (err) {
    throw new Error(`could not take the schema-push lock: ${err?.message || err}`)
  }
  try {
    return await push()
  } finally {
    try {
      const [{ unlocked }] = await db.$queryRaw`SELECT pg_advisory_unlock(hashtext(${LOCK_NAME})) AS unlocked`
      if (!unlocked) log.warn('[db-push] the schema-push lock was no longer held at release (its connection was replaced)')
    } catch (err) {
      log.warn(`[db-push] could not release the schema-push lock (Postgres releases it when this process exits): ${err?.message || err}`)
    }
  }
}

/**
 * Runs the Prisma CLI with `args`, its output on ours; resolves to its exit code, 1 when it
 * was killed by a signal or could not start.
 * @param {string[]} args
 * @param {{ cwd?: string, spawnImpl?: Function, execPath?: string, log?: { error: Function } }} [opts]
 * @returns {Promise<number>}
 */
export function runPrismaCli(args, { cwd = process.cwd(), spawnImpl = spawn, execPath = process.execPath, log = console } = {}) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawnImpl(execPath, [path.join(cwd, PRISMA_CLI), ...args], { cwd, stdio: 'inherit' })
    } catch (err) {
      log.error(`[db-push] could not start the Prisma CLI: ${err?.message || err}`)
      resolve(1)
      return
    }
    child.on('error', (err) => {
      log.error(`[db-push] could not start the Prisma CLI: ${err?.message || err}`)
      resolve(1)
    })
    child.on('exit', (code) => resolve(code ?? 1))
  })
}

/**
 * @param {string[]} argv the Prisma arguments, `db push ...`
 * @param {{ env?: Record<string, string | undefined>, createClient?: (url: string) => any,
 *   runCli?: (args: string[]) => Promise<number>, log?: { log: Function, warn: Function, error: Function } }} [deps]
 * @returns {Promise<number>} the exit code
 */
export async function main(argv, deps = {}) {
  const {
    env = process.env,
    createClient = (url) => new PrismaClient({ datasourceUrl: url }),
    runCli = (args) => runPrismaCli(args),
    log = console,
  } = deps
  if (argv[0] !== 'db' || argv[1] !== 'push') {
    log.error('[db-push] usage: node scripts/db-push-locked.mjs db push [prisma options]')
    return 2
  }
  if (!env.DATABASE_URL) {
    log.error('[db-push] DATABASE_URL is not set; cannot push the schema')
    return 1
  }
  let db
  try {
    db = createClient(singleConnectionUrl(env.DATABASE_URL))
    return await pushUnderLock(db, () => runCli(argv), log)
  } catch (err) {
    log.error(`[db-push] ${err?.message || err}`)
    return 1
  } finally {
    await db?.$disconnect().catch(() => {})
  }
}

// Imported by the tests without running; executed by the startup lists.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code })
}
