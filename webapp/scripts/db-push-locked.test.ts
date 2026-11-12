/**
 * The boot `prisma db push` behind a Postgres advisory lock (scripts/db-push-locked.mjs).
 *
 * Two webapp copies booting together over an older database both diff the schema and both
 * ALTER the same new columns; the second fails with "column ... already exists" and, the
 * push being fatal, that copy exits and restarts (master plan §9.6, "Several copies"). The
 * wrapper takes the lock on a one-connection client of its own, runs the push, and
 * releases the lock whatever the push did; the push's exit code is the wrapper's.
 *
 * Doubles here (the database, the Prisma CLI); scripts/db-push-locked.pg.integration.test.ts
 * runs two wrappers at once on a real Postgres.
 *
 * @vitest-environment node
 */
import { EventEmitter } from 'node:events'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, vi } from 'vitest'
import {
  LOCK_NAME, PRISMA_CLI, main, pushUnderLock, runPrismaCli, singleConnectionUrl,
} from './db-push-locked.mjs'

const WEBAPP = path.resolve(__dirname, '..')

type Call = { op: string; values: unknown[] }

/** A database double: records each lock statement in order, in a shared event list. */
function fakeDb(events: string[], opts: { free?: boolean; lockError?: Error; unlockError?: Error; unlocked?: boolean } = {}) {
  const calls: Call[] = []
  const op = (strings: TemplateStringsArray) => {
    const sql = strings.join('$')
    if (sql.includes('pg_try_advisory_lock')) return 'try-lock'
    if (sql.includes('pg_advisory_unlock')) return 'unlock'
    if (sql.includes('pg_advisory_lock')) return 'lock'
    return `unexpected: ${sql}`
  }
  return {
    calls,
    $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const name = op(strings)
      calls.push({ op: name, values }); events.push(name)
      if (name === 'try-lock') {
        if (opts.lockError) throw opts.lockError
        return [{ locked: opts.free ?? true }]
      }
      if (name === 'unlock') {
        if (opts.unlockError) throw opts.unlockError
        return [{ unlocked: opts.unlocked ?? true }]
      }
      throw new Error(name)
    },
    $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const name = op(strings)
      calls.push({ op: name, values }); events.push(name)
      if (name !== 'lock') throw new Error(name)
      return 1
    },
    $disconnect: async () => { events.push('disconnect') },
  }
}

function fakeLog() {
  const lines: string[] = []
  const put = (...a: unknown[]) => { lines.push(a.map(String).join(' ')) }
  return { lines, log: { log: put, warn: put, error: put } }
}

describe('pushUnderLock', () => {
  test('takes the lock before the push and releases it after a push that succeeds', async () => {
    const events: string[] = []
    const db = fakeDb(events)
    const code = await pushUnderLock(db, async () => { events.push('push'); return 0 }, fakeLog().log)
    expect(code).toBe(0)
    expect(events).toEqual(['try-lock', 'push', 'unlock'])
    // The lock and the unlock name the same key.
    expect(db.calls.map((c) => c.values)).toEqual([[LOCK_NAME], [LOCK_NAME]])
  })

  test('a second copy finds the lock taken, waits for it, then pushes', async () => {
    const events: string[] = []
    const db = fakeDb(events, { free: false })
    const { lines, log } = fakeLog()
    const code = await pushUnderLock(db, async () => { events.push('push'); return 0 }, log)
    expect(code).toBe(0)
    expect(events).toEqual(['try-lock', 'lock', 'push', 'unlock'])
    expect(db.calls.find((c) => c.op === 'lock')?.values).toEqual([LOCK_NAME])
    expect(lines.join('\n')).toMatch(/\[db-push\] another webapp copy is pushing the schema; waiting/)
  })

  test('a failed push still releases the lock, and its exit code is returned', async () => {
    const events: string[] = []
    const code = await pushUnderLock(fakeDb(events), async () => { events.push('push'); return 1 }, fakeLog().log)
    expect(code).toBe(1)
    expect(events).toEqual(['try-lock', 'push', 'unlock'])
  })

  test('a push that throws still releases the lock, and the error propagates', async () => {
    const events: string[] = []
    const push = async () => { events.push('push'); throw new Error('spawn exploded') }
    await expect(pushUnderLock(fakeDb(events), push, fakeLog().log)).rejects.toThrow('spawn exploded')
    expect(events).toEqual(['try-lock', 'push', 'unlock'])
  })

  test('no push without the lock: a lock that cannot be taken rejects before the push', async () => {
    const events: string[] = []
    const push = vi.fn(async () => 0)
    const db = fakeDb(events, { lockError: new Error("Can't reach database server") })
    await expect(pushUnderLock(db, push, fakeLog().log)).rejects.toThrow(/schema-push lock.*Can't reach database server/)
    expect(push).not.toHaveBeenCalled()
    expect(events).toEqual(['try-lock'])
  })

  test('an unlock that fails or finds no lock keeps the push result (the session ends with the process)', async () => {
    for (const opts of [{ unlockError: new Error('connection reset') }, { unlocked: false }]) {
      const events: string[] = []
      const { lines, log } = fakeLog()
      expect(await pushUnderLock(fakeDb(events, opts), async () => 0, log)).toBe(0)
      expect(lines.join('\n')).toMatch(/\[db-push\] .*release/)
    }
  })
})

describe('main', () => {
  const ARGS = ['db', 'push', '--skip-generate', '--accept-data-loss', '--schema', './prisma/schema.prisma']
  const ENV = { DATABASE_URL: 'postgresql://u:p@postgres:5432/redamon?schema=public' }

  test('runs the Prisma CLI with the list\'s own arguments, under the lock, on a one-connection client', async () => {
    const events: string[] = []
    const urls: string[] = []
    const runCli = vi.fn(async (args: string[]) => { events.push('push'); expect(args).toEqual(ARGS); return 0 })
    const code = await main(ARGS, {
      env: ENV, runCli, log: fakeLog().log,
      createClient: (url: string) => { urls.push(url); return fakeDb(events) },
    })
    expect(code).toBe(0)
    expect(runCli).toHaveBeenCalledTimes(1)
    expect(urls).toEqual(['postgresql://u:p@postgres:5432/redamon?schema=public&connection_limit=1'])
    expect(events).toEqual(['try-lock', 'push', 'unlock', 'disconnect'])
  })

  test('a failing push makes the wrapper fail with its code (the entrypoint keeps `|| exit 1`)', async () => {
    const events: string[] = []
    const code = await main(ARGS, {
      env: ENV, runCli: async () => 1, log: fakeLog().log, createClient: () => fakeDb(events),
    })
    expect(code).toBe(1)
    expect(events).toEqual(['try-lock', 'unlock', 'disconnect'])
  })

  test('a lock that cannot be taken fails the boot, without a push', async () => {
    const events: string[] = []
    const runCli = vi.fn(async () => 0)
    const { lines, log } = fakeLog()
    const code = await main(ARGS, {
      env: ENV, runCli, log,
      createClient: () => fakeDb(events, { lockError: new Error('P1001 unreachable') }),
    })
    expect(code).toBe(1)
    expect(runCli).not.toHaveBeenCalled()
    expect(events).toEqual(['try-lock', 'disconnect'])
    expect(lines.join('\n')).toMatch(/\[db-push\] .*P1001 unreachable/)
  })

  test('only a `db push` is run, and only with a DATABASE_URL', async () => {
    const createClient = vi.fn(() => fakeDb([]))
    const runCli = vi.fn(async () => 0)
    const log = fakeLog().log
    expect(await main(['migrate', 'reset', '--force'], { env: ENV, runCli, log, createClient })).toBe(2)
    expect(await main([], { env: ENV, runCli, log, createClient })).toBe(2)
    expect(await main(ARGS, { env: {}, runCli, log, createClient })).toBe(1)
    expect(createClient).not.toHaveBeenCalled()
    expect(runCli).not.toHaveBeenCalled()
  })

  test('run as a file it exits with main\'s code', () => {
    // A bare env on purpose (no DATABASE_URL); Next's ProcessEnv type requires a NODE_ENV the child does not need.
    const bare: Partial<NodeJS.ProcessEnv> = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' }
    const env = bare as NodeJS.ProcessEnv
    const usage = spawnSync(process.execPath, ['scripts/db-push-locked.mjs', 'migrate', 'reset'], { cwd: WEBAPP, env, encoding: 'utf8' })
    expect(usage.status).toBe(2)
    expect(usage.stderr).toMatch(/\[db-push\] usage/)
    const noUrl = spawnSync(process.execPath, ['scripts/db-push-locked.mjs', 'db', 'push'], { cwd: WEBAPP, env, encoding: 'utf8' })
    expect(noUrl.status).toBe(1)
    expect(noUrl.stderr).toMatch(/\[db-push\] DATABASE_URL/)
  })
})

describe('singleConnectionUrl', () => {
  test('limits the client to one connection, so the lock and its unlock share a session', () => {
    expect(singleConnectionUrl('postgresql://u:p@h:5432/db')).toBe('postgresql://u:p@h:5432/db?connection_limit=1')
  })

  test('keeps every other parameter as written, an encoded one included', () => {
    expect(singleConnectionUrl('postgresql://u:p@h/db?options=-c%20lock_timeout%3D2000&schema=public'))
      .toBe('postgresql://u:p@h/db?options=-c%20lock_timeout%3D2000&schema=public&connection_limit=1')
  })

  test('replaces a connection_limit already in the URL', () => {
    expect(singleConnectionUrl('postgresql://u:p@h/db?connection_limit=10&schema=public'))
      .toBe('postgresql://u:p@h/db?schema=public&connection_limit=1')
  })
})

describe('runPrismaCli', () => {
  function fakeSpawn(finish: (child: EventEmitter) => void) {
    const calls: { file: string; args: string[]; opts: Record<string, unknown> }[] = []
    const spawnImpl = (file: string, args: string[], opts: Record<string, unknown>) => {
      calls.push({ file, args, opts })
      const child = new EventEmitter()
      setImmediate(() => finish(child))
      return child
    }
    return { calls, spawnImpl }
  }

  test('runs the Prisma CLI the image ships, with the arguments, its output on ours', async () => {
    const { calls, spawnImpl } = fakeSpawn((c) => c.emit('exit', 0, null))
    const code = await runPrismaCli(['db', 'push', '--accept-data-loss'], { cwd: '/app', spawnImpl, execPath: '/usr/local/bin/node' })
    expect(code).toBe(0)
    expect(calls).toEqual([{
      file: '/usr/local/bin/node',
      args: [path.join('/app', PRISMA_CLI), 'db', 'push', '--accept-data-loss'],
      opts: { cwd: '/app', stdio: 'inherit' },
    }])
    expect(PRISMA_CLI).toBe(path.join('node_modules', 'prisma', 'build', 'index.js'))
  })

  test('the exit code is the CLI\'s; a signal or a failed start is a failure', async () => {
    const log = fakeLog().log
    expect(await runPrismaCli([], { cwd: '/app', log, spawnImpl: fakeSpawn((c) => c.emit('exit', 1, null)).spawnImpl })).toBe(1)
    expect(await runPrismaCli([], { cwd: '/app', log, spawnImpl: fakeSpawn((c) => c.emit('exit', null, 'SIGKILL')).spawnImpl })).toBe(1)
    expect(await runPrismaCli([], { cwd: '/app', log, spawnImpl: fakeSpawn((c) => c.emit('error', new Error('ENOENT'))).spawnImpl })).toBe(1)
  })
})

describe('the startup lists', () => {
  const dockerfile = readFileSync(path.join(WEBAPP, 'Dockerfile'), 'utf8')
  const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('> /app/entrypoint.sh'))!
  const dev = readFileSync(path.join(WEBAPP, '..', 'docker-compose.dev.yml'), 'utf8').split('\n').map((l) => l.trim())

  test('the entrypoint pushes through the lock, fatally, with today\'s arguments, between the pre-push scripts and the re-applies', () => {
    const step = '\\nnode scripts/db-push-locked.mjs db push --skip-generate --accept-data-loss --schema ./prisma/schema.prisma 2>&1 || exit 1\\n'
    const at = entry.indexOf(step)
    expect(at).toBeGreaterThan(entry.indexOf('add-js-recon-trufflehog-column.mjs'))
    expect(entry.indexOf('apply-ingest-role.mjs')).toBeGreaterThan(at)
    // No push outside the lock.
    expect(entry.split('db push')).toHaveLength(2)
    expect(entry).not.toContain('prisma/build/index.js db push')
  })

  test('the dev command does the same at the same place, keeping its own arguments', () => {
    const at = dev.indexOf('node scripts/db-push-locked.mjs db push --accept-data-loss || exit 1')
    expect(at).toBeGreaterThan(0)
    expect(dev[at - 1]).toBe('node scripts/add-js-recon-trufflehog-column.mjs || exit 1')
    expect(dev[at + 1]).toBe('node scripts/apply-ingest-role.mjs')
    expect(dev.filter((l) => !l.startsWith('#') && l.includes('db push'))).toHaveLength(1)
  })
})
