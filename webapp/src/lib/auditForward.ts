/**
 * Audit forwarding (AU-06): with `AUDIT_FORWARD=stdout` every audit row the webapp writes is also
 * printed once, as one JSON line after the prefix `[audit-forward]`, so an operator can ship the
 * container log to a store the database cannot rewrite (tamper evidence). `off`, the default,
 * prints nothing and changes nothing. The setting is independent of the RBAC switches.
 *
 * Every webapp insert into the three audit tables (`audit_log`, `act_as_audit`,
 * `fireteam_settings_audit`) goes through the three `create*` functions here, the only place that
 * writes them (auditWriters.static.test.ts fails on any other). A row written through the root
 * client is committed when its insert resolves, so it prints at once. A row written through a
 * transaction prints only after that transaction commits: a Prisma interactive transaction has no
 * commit hook, so `auditedTransaction` runs the transaction, queues the lines its writers produce,
 * and prints them once `$transaction` has resolved; a rolled-back transaction prints nothing. Every
 * transaction that writes an audit row runs in it (the static test follows each such write to its
 * transaction).
 *
 * The line is the row as stored, never the request around it. Audit rows hold no credential
 * (master §9.8); should one ever carry a key named like one, the printed copy says `[redacted]`
 * and an error line names the key. Printing never fails the write: an error is logged and the
 * write stands.
 *
 * The host scripts (webapp/scripts/*.mjs: the backfills, set-root, create-admin, reset-password)
 * write their rows with their own Prisma client and are not forwarded.
 *
 * Kept apart from lib/audit.ts so the many tests that replace that module keep these real.
 */
import type { Prisma, PrismaClient } from '@prisma/client'

export type AuditTable = 'audit_log' | 'act_as_audit' | 'fireteam_settings_audit'
export type AuditForwardMode = 'off' | 'stdout'

export const FORWARD_PREFIX = '[audit-forward]'

export interface AuditLogDb {
  auditLog: { create(args: { data: Prisma.AuditLogUncheckedCreateInput }): Promise<unknown> }
}
export interface ActAsAuditDb {
  actAsAudit: { create(args: { data: Prisma.ActAsAuditUncheckedCreateInput }): Promise<unknown> }
}
export interface FireteamAuditDb {
  fireteamSettingsAudit: { createMany(args: { data: Prisma.FireteamSettingsAuditCreateManyInput[] }): Promise<unknown> }
}

const warnedValues = new Set<string>()

/** Read on every write, so a test (or a restarted process) sees the value in force. */
export function auditForwardMode(): AuditForwardMode {
  const raw = (process.env.AUDIT_FORWARD ?? '').trim()
  const value = raw.toLowerCase()
  if (value === 'stdout') return 'stdout'
  if (value !== '' && value !== 'off' && !warnedValues.has(value)) {
    warnedValues.add(value)
    console.warn(`${FORWARD_PREFIX} AUDIT_FORWARD=${JSON.stringify(raw)} is neither off nor stdout: forwarding stays off`)
  }
  return 'off'
}

// Exact names, compared without case: a suffix rule would also hide `settingsHash` or
// `evidence_hash`, which audit rows legitimately carry.
const CREDENTIAL_KEYS = new Set([
  'password', 'passwordhash', 'passwordonhold', 'stepuppassword', 'currentpassword', 'newpassword',
  'temporarypassword', 'token', 'tokenhash', 'rawtoken', 'secret', 'apikey', 'privatekey',
])

function withoutCredentials(value: unknown, found: string[]): unknown {
  if (Array.isArray(value)) return value.map((v) => withoutCredentials(v, found))
  if (value === null || typeof value !== 'object' || value instanceof Date) return value
  return Object.fromEntries(Object.entries(value).map(([key, v]) => {
    if (!CREDENTIAL_KEYS.has(key.toLowerCase())) return [key, withoutCredentials(v, found)]
    found.push(key)
    return [key, '[redacted]']
  }))
}

function describeRow(table: AuditTable, row: Record<string, unknown>): string {
  const what = row.action ?? row.event ?? row.field
  return typeof what === 'string' ? `a ${table} row (${what})` : `a ${table} row`
}

/** The printed line, or null when the row cannot be printed (logged; the write stands). */
function lineOf(table: AuditTable, row: object): string | null {
  try {
    const found: string[] = []
    const clean = withoutCredentials(row, found) as Record<string, unknown>
    if (found.length) {
      console.error(`${FORWARD_PREFIX} redacted ${found.join(', ')} in ${describeRow(table, clean)}: an audit row must never hold a credential`)
    }
    return `${FORWARD_PREFIX} ${JSON.stringify({ table, ...clean })}`
  } catch (e) {
    quietly(() => console.error(`${FORWARD_PREFIX} could not print ${describeRow(table, row as Record<string, unknown>)}: ${e instanceof Error ? e.message : String(e)}`))
    return null
  }
}

function quietly(print: () => void): void {
  try {
    print()
  } catch {
    // stdout or stderr is gone; the row is in the database, which is what matters.
  }
}

function emit(line: string): void {
  quietly(() => console.info(line))
}

/** The line queues of the transactions `auditedTransaction` is running, by transaction client. */
const openTransactions = new WeakMap<object, string[][]>()

function isRootClient(db: object): boolean {
  // Prisma leaves `$transaction` off an interactive transaction's client.
  return typeof (db as { $transaction?: unknown }).$transaction === 'function'
}

function forward(db: object, table: AuditTable, rows: readonly object[]): void {
  if (auditForwardMode() === 'off') return
  const lines = rows.map((row) => lineOf(table, row)).filter((line): line is string => line !== null)
  const queues = openTransactions.get(db)
  if (queues && queues.length > 0) {
    queues[queues.length - 1].push(...lines)
    return
  }
  if (!isRootClient(db)) {
    // The static test keeps this from happening; printing now beats losing the line, since a
    // forwarded copy missing for a stored row would read as a row forged into the database.
    quietly(() => console.error(`${FORWARD_PREFIX} ${describeRow(table, rows[0] as Record<string, unknown>)} was written in a transaction auditedTransaction does not run: printed before its commit`))
  }
  for (const line of lines) emit(line)
}

/** What the insert answered (the stored row, with its id and time), else what was written. */
function storedRow(answer: unknown, written: object): object {
  return answer !== null && typeof answer === 'object' ? answer : written
}

export async function createAuditLogRow(db: AuditLogDb, data: Prisma.AuditLogUncheckedCreateInput): Promise<void> {
  const answer = await db.auditLog.create({ data })
  forward(db, 'audit_log', [storedRow(answer, data)])
}

export async function createActAsAuditRow(db: ActAsAuditDb, data: Prisma.ActAsAuditUncheckedCreateInput): Promise<void> {
  const answer = await db.actAsAudit.create({ data })
  forward(db, 'act_as_audit', [storedRow(answer, data)])
}

/** `createMany` answers only a count, so each line is the row as written (no id, no time). */
export async function createFireteamAuditRows(db: FireteamAuditDb, rows: Prisma.FireteamSettingsAuditCreateManyInput[]): Promise<void> {
  await db.fireteamSettingsAudit.createMany({ data: rows })
  forward(db, 'fireteam_settings_audit', rows)
}

/**
 * `db.$transaction(fn)`, for every transaction that writes an audit row: the rows its writers
 * produced are printed after it commits, and never when it rolls back. Forwarding off, `fn` goes to
 * `$transaction` untouched.
 */
export async function auditedTransaction<T>(
  db: Pick<PrismaClient, '$transaction'>,
  fn: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  if (auditForwardMode() === 'off') return db.$transaction(fn)
  let committed: string[] = []
  const result = await db.$transaction(async (tx) => {
    const queue: string[] = []
    committed = queue
    const queues = openTransactions.get(tx) ?? []
    queues.push(queue)
    openTransactions.set(tx, queues)
    try {
      return await fn(tx)
    } finally {
      queues.splice(queues.indexOf(queue), 1)
      if (queues.length === 0) openTransactions.delete(tx)
    }
  })
  for (const line of committed) emit(line)
  return result
}
