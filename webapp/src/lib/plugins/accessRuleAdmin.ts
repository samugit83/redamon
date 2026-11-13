import { NextResponse, type NextRequest } from 'next/server'
import prisma from '@/lib/prisma'
import { writeAuditTx } from '@/lib/audit'
import { auditedTransaction } from '@/lib/auditForward'
import type { Session } from '@/lib/session'
import { BUILTIN_MEMBER_SETS, builtinSet } from '@/lib/authz/builtinSets'
import { lockPermissions, personAuditEntry } from '@/lib/authz/permissionAdmin'
import type { PluginAuditAction } from './audit'
import { readAccessRules, replaceAccessRules } from './accessRuleStore'

/**
 * Managing a plugin's allowlist (GV-16): whoever holds platform:plugins reads and replaces the
 * member permission sets a plugin is limited to (accessRules.ts decides who may use it).
 *
 * A rule names a member set: a built-in one or a stored `member` row. Admin profiles are not
 * offered: an admin holding platform:plugins passes every rule anyway. The replacement commits
 * under the permissions lock, the one `deleteSet` takes, so a set cannot be deleted between the
 * check that it exists and the rule naming it; it commits with its audit row
 * (`plugin.access_rules_changed`, fail closed) and writes nothing when the sets did not change.
 */
export const MAX_RULE_SETS = 50
const MAX_SET_ID = 128
const ACTION: PluginAuditAction = 'plugin.access_rules_changed'

export interface SelectableSet {
  id: string
  name: string
  builtin: boolean
}

export interface AccessRulesView {
  pluginId: string
  /** The sets the plugin is limited to, in id order; empty = everyone holding plugins:use. */
  setIds: string[]
  /** The member sets a rule may name: the built-ins, then the stored ones by name. */
  sets: SelectableSet[]
}

const refuse = (status: number, code: string, error: string, extra: Record<string, unknown> = {}) =>
  NextResponse.json({ error, code, ...extra }, { status, headers: { 'Cache-Control': 'no-store' } })

export async function accessRulesView(pluginId: string): Promise<AccessRulesView> {
  const [rules, stored] = await Promise.all([
    readAccessRules(pluginId),
    prisma.permissionSet.findMany({ where: { kind: 'member' }, select: { id: true, name: true } }),
  ])
  return {
    pluginId,
    setIds: rules.map((r) => r.setId),
    sets: [
      ...BUILTIN_MEMBER_SETS.map((s) => ({ id: s.id, name: s.name, builtin: true })),
      ...stored.sort((a, b) => a.name.localeCompare(b.name)).map((r) => ({ id: r.id, name: r.name, builtin: false })),
    ],
  }
}

function parseSetIds(value: unknown): string[] | NextResponse {
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || v.length === 0 || v.length > MAX_SET_ID)) {
    return refuse(400, 'invalid_set_ids', 'setIds must be a list of permission set ids.')
  }
  const ids = [...new Set(value as string[])]
  if (ids.length > MAX_RULE_SETS) return refuse(400, 'invalid_set_ids', `A plugin can be limited to at most ${MAX_RULE_SETS} sets.`)
  return ids
}

type Outcome = { kind: 'unknown'; setIds: string[] } | { kind: 'saved'; setIds: string[] }

/** PUT `{setIds}`: the plugin's rules become exactly these sets; `[]` opens it to everyone again. */
export async function saveAccessRules(
  request: NextRequest,
  session: Session,
  pluginId: string,
  body: Record<string, unknown>,
): Promise<NextResponse> {
  const ids = parseSetIds(body.setIds)
  if (ids instanceof NextResponse) return ids
  const outcome = await auditedTransaction(prisma, async (tx): Promise<Outcome> => {
    await lockPermissions(tx)
    const stored = ids.filter((id) => !id.startsWith('builtin:'))
    const found = stored.length === 0
      ? []
      : (await tx.permissionSet.findMany({ where: { id: { in: stored }, kind: 'member' }, select: { id: true } })).map((r) => r.id)
    const unknown = ids.filter((id) => (id.startsWith('builtin:') ? builtinSet(id)?.kind !== 'member' : !found.includes(id)))
    if (unknown.length > 0) return { kind: 'unknown', setIds: unknown }
    const { before, after } = await replaceAccessRules(tx, pluginId, ids, session.userId)
    if (before.join('\n') !== after.join('\n')) {
      await writeAuditTx(tx, await personAuditEntry(request, session, {
        action: ACTION, targetType: 'plugin', targetId: pluginId, permission: 'platform:plugins',
        before: { setIds: before }, after: { setIds: after },
      }))
    }
    return { kind: 'saved', setIds: after }
  })
  if (outcome.kind === 'unknown') {
    return refuse(400, 'unknown_set', 'A plugin can be limited only to member permission sets that exist.', { setIds: outcome.setIds })
  }
  console.log(`[plugins] access rules of ${pluginId} by ${session.userId}: ${outcome.setIds.length} set(s)`)
  return NextResponse.json({ pluginId, setIds: outcome.setIds }, { headers: { 'Cache-Control': 'no-store' } })
}
