/**
 * Every audit action the webapp writes has a label (step 4.13, UI-08, AU-09; the table 6.6's viewer
 * reuses). The actions are read from the TypeScript syntax tree of every production file of src/ and
 * scripts/: the strings an `action` property, parameter or field type names (a ternary's both arms, a
 * union of literal types), the strings of a `*_ACTION(S)` constant, and the string arguments of a call
 * whose name says audit (the host scripts' `audit(tx, 'root.set_by_host', ...)`, `auditPlugin(...)`).
 * A template action is a family: each one written today is expanded here, and a new one fails until
 * it is. An audit write whose action is a plain variable must be one of the writers listed below,
 * whose names the rules above already read.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/auditLabels.test.ts
 * @vitest-environment node
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { describe, expect, test } from 'vitest'
import {
  AUDIT_ACTION_FAMILIES, AUDIT_ACTION_LABELS, AUDIT_GROUPS, AUDIT_GROUP_IDS, auditActionLabel, auditGroupTerms, isAuditGroup,
} from './auditLabels'

const WEBAPP = path.resolve(__dirname, '../../..')
const ACTION_SHAPE = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$/

function productionFiles(): string[] {
  const out: string[] = []
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name)
      if (statSync(full).isDirectory()) {
        if (name !== 'node_modules' && name !== '__testing__' && name !== '__fixtures__') walk(full)
      } else if (/\.(ts|tsx|mjs)$/.test(name) && !/\.(test|spec)\.(ts|tsx|mjs)$/.test(name)) {
        out.push(full)
      }
    }
  }
  walk(path.join(WEBAPP, 'src'))
  walk(path.join(WEBAPP, 'scripts'))
  return out
}

const nameOf = (n: ts.Node | undefined): string | null =>
  n && (ts.isIdentifier(n) || ts.isStringLiteral(n)) ? n.text : null

const calleeName = (call: ts.CallExpression): string => {
  const c = call.expression
  return ts.isIdentifier(c) ? c.text : ts.isPropertyAccessExpression(c) ? c.name.text : ''
}

interface Found {
  actions: Map<string, Set<string>>
  templates: Map<string, Set<string>>
  /** `file: expression` of each audit write whose action is neither a literal nor a template. */
  indirect: Set<string>
}

/** The audit actions a source names, by the rules of the header. */
function readActions(files: Array<{ file: string; source: string }>): Found {
  const found: Found = { actions: new Map(), templates: new Map(), indirect: new Set() }
  const note = (map: Map<string, Set<string>>, key: string, file: string) => {
    if (!map.has(key)) map.set(key, new Set())
    map.get(key)!.add(file)
  }
  for (const { file, source } of files) {
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
    const strings = (node: ts.Node) => {
      const visit = (n: ts.Node): void => {
        if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
          if (ACTION_SHAPE.test(n.text)) note(found.actions, n.text, file)
          return
        }
        if (ts.isTemplateExpression(n)) {
          note(found.templates, n.getText(sf), file)
          return
        }
        // A call or a function inside the value computes something else (a lookup, a callback).
        if (ts.isCallExpression(n) || ts.isArrowFunction(n) || ts.isFunctionExpression(n)) return
        ts.forEachChild(n, visit)
      }
      visit(node)
    }
    // An audit row, wherever it is built: an object literal that names both `action` and `targetType`
    // (writeAudit's argument, an entry builder's return value, `auditLog.create`'s data).
    // A query's filter or projection names the same keys and writes nothing.
    const inQuery = (n: ts.Node): boolean => {
      for (let up = n.parent; up && !ts.isFunctionLike(up); up = up.parent) {
        if (ts.isPropertyAssignment(up) && ['where', 'select', 'include'].includes(nameOf(up.name) ?? '')) return true
      }
      return false
    }
    const auditRow = (n: ts.Node): n is ts.ObjectLiteralExpression => ts.isObjectLiteralExpression(n)
      && ['action', 'targetType'].every(k => n.properties.some(p => nameOf(p.name) === k)) && !inQuery(n)
    const visit = (n: ts.Node): void => {
      if (ts.isPropertyAssignment(n) && nameOf(n.name) === 'action') strings(n.initializer)
      if ((ts.isPropertySignature(n) || ts.isParameter(n)) && nameOf(n.name) === 'action' && n.type) strings(n.type)
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && /(^|_)ACTIONS?$/.test(n.name.text) && n.initializer) strings(n.initializer)
      if (ts.isCallExpression(n)) {
        if (/audit/i.test(calleeName(n))) {
          for (const a of n.arguments) {
            if ((ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a)) && ACTION_SHAPE.test(a.text)) note(found.actions, a.text, file)
          }
        }
      }
      if (auditRow(n)) {
        for (const p of n.properties) {
          const isAction = (ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && nameOf(p.name) === 'action'
          if (!isAction) continue
          const value = ts.isPropertyAssignment(p) ? p.initializer : p.name
          // `action: true`: a projection kept in a constant (a select), not a row.
          if (value.kind === ts.SyntaxKind.TrueKeyword || value.kind === ts.SyntaxKind.FalseKeyword) continue
          const literal = ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value) || ts.isTemplateExpression(value)
            || (ts.isConditionalExpression(value) && ts.isStringLiteral(value.whenTrue) && ts.isStringLiteral(value.whenFalse))
          if (!literal) found.indirect.add(`${path.relative(WEBAPP, file)}: ${value.getText(sf)}`)
        }
      }
      ts.forEachChild(n, visit)
    }
    visit(sf)
  }
  return found
}

/**
 * The audit writes whose action is a variable, and where the names they receive are read from (a
 * rule above reads each). A new one fails the test: give it a literal, a typed parameter or an
 * `*_ACTION` constant, then list it here.
 */
const INDIRECT_WRITERS: Readonly<Record<string, string>> = {
  'src/lib/audit.ts: entry.action': 'the helper every writer calls (writeAudit, writeAuditTx): its callers are read',
  'src/lib/userAudit.ts: entry.action': "callers pass `action: 'user.…'` literals (the action property rule)",
  'src/lib/workspaceImport/audit.ts: action': "a parameter typed with the three workspace.* literals",
  'src/lib/authz/projectShares.ts: audit.action': "the share writers pass `action: 'project.share.…'` literals",
  'src/lib/plugins/audit.ts: action': 'PluginAuditAction, the PLUGIN_AUDIT_ACTIONS constant',
  'src/lib/plugins/accessRuleAdmin.ts: ACTION': 'the ACTION constant',
  'src/lib/authz/sharedTools.ts: COMPAT_USED_ACTION': 'the COMPAT_USED_ACTION constant',
  'src/lib/authz/updateReview.ts: action': 'KEEP_ACTION / REMOVE_ACTION constants passed by the callers',
  'src/lib/authz/updateReview.ts: WHATS_NEW_DISMISSED_ACTION': 'the WHATS_NEW_DISMISSED_ACTION constant',
  'src/lib/mcp/kaliTools.ts: action': "auditExec(ctx, id, 'mcp.kali_…', …) literals (the audit call rule)",
  'src/app/api/internal/agent/decisions/route.ts: action': "the KINDS table's `action:` literals",
  'src/app/api/agent/sessions/sessionDrive.ts: action': 'a parameter typed with the three agent.* literals',
  'src/lib/authz/oversight.ts: OVERSEE_ACTION': 'the OVERSEE_ACTION constant (step 4.14)',
  'src/lib/authz/breakGlass.ts: BREAKGLASS_ACTION': 'the BREAKGLASS_ACTION constant (step 4.14)',
  'src/lib/authz/breakGlass.ts: BREAKGLASS_END_ACTION': 'the BREAKGLASS_END_ACTION constant (step 4.14)',
  'scripts/backfill-nuclei-template-owners.mjs: MARKER_ACTION': 'the MARKER_ACTION constant',
  'scripts/backfill-rbac-root.mjs: ASSIGNED_ACTION': 'the ASSIGNED_ACTION constant',
  'scripts/set-root.mjs: action': "audit(tx, 'root.…', …) literals (the audit call rule)",
  'scripts/reset-password.mjs: action': "audit(tx, 'user.…', …) literals (the audit call rule)",
  'scripts/create-admin.mjs: action': "audit(tx, 'user.…', …) literals (the audit call rule)",
  'scripts/backfill-rbac-instance-settings.mjs: MARKER_ACTION': 'the MARKER_ACTION constant',
  'scripts/backfill-user-skill-toggles.mjs: CUTOFF_ACTION': 'the CUTOFF_ACTION constant',
  'scripts/backfill-user-skill-toggles.mjs: MARKER_ACTION': 'the MARKER_ACTION constant',
  'scripts/backfill-rbac-legacy-grants.mjs: CUTOFF_ACTION': 'the CUTOFF_ACTION constant',
  'scripts/backfill-rbac-legacy-grants.mjs: MARKER_ACTION': 'the MARKER_ACTION constant',
  'scripts/backfill-rbac-legacy-overrides.mjs: MARKER_ACTION': 'the MARKER_ACTION constant',
  'scripts/backfill-jev-provider-selection.mjs: CUTOFF_ACTION': 'the CUTOFF_ACTION constant',
  'scripts/backfill-jev-provider-selection.mjs: MARKER_ACTION': 'the MARKER_ACTION constant',
}

/** What each template written today stands for: its expansions, or the family that labels it. */
function templateExpansions(): Record<string, string[] | { family: string }> {
  const words = [...readFileSync(path.join(WEBAPP, 'src/lib/authz/permissionSetAdmin.ts'), 'utf8')
    .matchAll(/audit: '([a-z_]+)'/g)].map(m => m[1])
  return {
    // accountActivity.ts names the act-as table's rows (start, end) for "My activity".
    '`act_as.${r.event}`': ['act_as.start', 'act_as.end'],
    '`${words.audit}.created`': words.map(w => `${w}.created`),
    '`${words.audit}.updated`': words.map(w => `${w}.updated`),
    '`${words.audit}.deleted`': words.map(w => `${w}.deleted`),
    '`mcp.${tool}`': { family: 'mcp.' },
  }
}

/** Labelled before any code writes them, with the step that will. */
const WRITTEN_LATER: Readonly<Record<string, string>> = {
  'scan_schedule.confirmed': 'step 5.5: the owner confirms a paused schedule (schedules/[scheduleId]/confirm)',
}

const found = readActions(productionFiles().map(file => ({ file, source: readFileSync(file, 'utf8') })))

describe('audit action labels (step 4.13, UI-08, AU-09)', () => {
  test('the reader finds the actions the code writes (not vacuous)', () => {
    expect(found.actions.size).toBeGreaterThan(140)
    for (const a of ['project.share.grant', 'project.share.expired', 'user.override_expired', 'act_as.refused', 'mcp.kali_exec',
      'plugin.override.adopt', 'root.set_by_host', 'system.rbac_root_assigned', 'workspace.resync', 'agent.session_kill',
      'triage.finish.late', 'auth.login.disabled', 'project.roe.replace', 'user.reset_link_used']) {
      expect(found.actions.has(a), a).toBe(true)
    }
  })

  test('labels cover every action written in the codebase', () => {
    const missing = [...found.actions.keys()].filter(a => !auditActionLabel(a).known).sort()
    expect(missing, 'add each to AUDIT_ACTION_LABELS (auditLabels.ts)').toEqual([])
  })

  test('every template action is expanded here, and each expansion has a label', () => {
    const expansions = templateExpansions()
    expect([...found.templates.keys()].filter(t => !(t in expansions)).sort(), 'expand the new template in templateExpansions()').toEqual([])
    for (const [template, expansion] of Object.entries(expansions)) {
      expect(found.templates.has(template), `${template} is no longer written: drop it`).toBe(true)
      if (Array.isArray(expansion)) {
        expect(expansion.length, template).toBeGreaterThan(0)
        for (const a of expansion) expect(AUDIT_ACTION_LABELS[a], `${a} (${template})`).toBeDefined()
      } else {
        expect(AUDIT_ACTION_FAMILIES.some(f => f.prefix === expansion.family), template).toBe(true)
      }
    }
  })

  test('an audit write whose action is a variable is a listed writer', () => {
    expect([...found.indirect].sort()).toEqual(Object.keys(INDIRECT_WRITERS).sort())
  })

  test('no label for an action nothing writes, except the ones a later step writes', () => {
    const expanded = new Set(Object.values(templateExpansions()).flatMap(e => (Array.isArray(e) ? e : [])))
    const stale = Object.keys(AUDIT_ACTION_LABELS)
      .filter(a => !found.actions.has(a) && !expanded.has(a) && !(a in WRITTEN_LATER)).sort()
    expect(stale).toEqual([])
    for (const a of Object.keys(WRITTEN_LATER)) expect(AUDIT_ACTION_LABELS[a], a).toBeDefined()
  })

  test('the feed\'s spec rows: share changes, oversight, break-glass and acting as have their group', () => {
    for (const a of ['project.share.grant', 'project.share.update', 'project.share.revoke', 'project.share.leave', 'project.share.expired']) {
      expect(auditActionLabel(a).group, a).toBe('sharing')
    }
    expect(auditActionLabel('project.oversee').group).toBe('oversight')
    expect(auditActionLabel('project.breakglass').group).toBe('oversight')
    expect(auditActionLabel('project.breakglass.end').group).toBe('oversight')
    expect(auditActionLabel('act_as.refused').group).toBe('acting')
  })

  test('each label is a short sentence and each group is a known one', () => {
    for (const [action, { label, group }] of Object.entries(AUDIT_ACTION_LABELS)) {
      expect(isAuditGroup(group), action).toBe(true)
      expect(label.length, action).toBeGreaterThan(5)
      expect(label.length, action).toBeLessThanOrEqual(80)
      expect(label, action).toMatch(/^[A-Z]/)
      expect(label, action).not.toMatch(/\.$/)
    }
    expect(AUDIT_GROUP_IDS).toEqual(Object.keys(AUDIT_GROUPS))
  })

  test('a family labels the variable part; an exact entry wins; an unknown action keeps its name', () => {
    expect(auditActionLabel('mcp.list_findings')).toEqual({ label: 'MCP tool call: list findings', group: 'mcp', known: true })
    expect(auditActionLabel('mcp.kali_exec')).toEqual({ label: 'Ran a Kali command through MCP', group: 'mcp', known: true })
    expect(auditActionLabel('mcp.')).toEqual({ label: 'mcp.', group: null, known: false })
    expect(auditActionLabel('future.thing')).toEqual({ label: 'future.thing', group: null, known: false })
    expect(auditActionLabel('mcp-token.create').group).toBe('accounts')
    expect(auditActionLabel('mcp_server.stdio_refused').group).toBe('platform')
  })

  test("a group's terms are its exact actions and its family prefixes", () => {
    expect(auditGroupTerms('sharing')).toEqual({
      actions: [
        // Step 5.6: the owner's consent to collaborators spending the project's credentials, and each spend.
        'credits.used', 'project.owner_consent.grant', 'project.owner_consent.withdraw',
        'project.share.expired', 'project.share.grant', 'project.share.leave', 'project.share.lookup', 'project.share.revoke', 'project.share.update',
      ],
      prefixes: [],
    })
    expect(auditGroupTerms('mcp').prefixes).toEqual(['mcp.'])
    for (const id of AUDIT_GROUP_IDS) {
      const { actions, prefixes } = auditGroupTerms(id)
      expect(actions.length + prefixes.length, id).toBeGreaterThan(0)
    }
  })

  test('the reader: rules and refusals on fixtures', () => {
    const fixture = readActions([{
      file: path.join(WEBAPP, 'src/fixture.ts'),
      source: [
        "writeAudit({ action: ok ? 'a.yes' : 'a.no', targetType: 'x' })",
        "await writeAuditTx(tx, { action: chosen, targetType: 'x' })",
        "await tx.auditLog.create({ data: { action: SOME_ACTION, targetType: 'x' } })",
        "const SOME_ACTION = 'b.marker'",
        "const NOT_A_NAME = 'c.ignored'",
        "audit(tx, 'd.host', id)",
        "log('e.not_audit')",
        "function f(action: 'g.one' | 'g.two') {}",
        "const t = { action: `h.${x}` }",
        "const u = { action: 'plainword' }",
        "const v = { action: lookup('i.inside_call') }",
        "const w = prisma.auditLog.findMany({ where: { action: K, targetType: 'user' }, select: { action: true, targetType: true } })",
        "const SELECT = { action: true, targetType: true }",
      ].join('\n'),
    }])
    expect([...fixture.actions.keys()].sort()).toEqual(['a.no', 'a.yes', 'b.marker', 'd.host', 'g.one', 'g.two'])
    expect([...fixture.templates.keys()]).toEqual(['`h.${x}`'])
    expect([...fixture.indirect].sort()).toEqual(['src/fixture.ts: SOME_ACTION', 'src/fixture.ts: chosen'])
  })
})
