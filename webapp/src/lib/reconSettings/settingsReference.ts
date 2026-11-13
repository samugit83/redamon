/**
 * The exhaustive settings reference, rendered from the registry.
 *
 * `Project-Settings-Reference.md` is 2,241 hand-written lines with screenshots
 * and a narrative, and it opened by claiming "245+ configurable parameters"
 * when the model has 714. That page keeps its editorial content; this one is the
 * complete table beside it, generated, so the exhaustive answer can never be
 * stale and the prose never has to be exhaustive.
 *
 * Determinism first, for the reason `apiReference.ts` already documents: no
 * dates, no version strings, stable ordering throughout. A generated diff that
 * changes on every run is one people learn to ignore, and this page is only
 * worth having if a diff on it means something.
 */
import {
  fieldsWhere,
  loadRegistry,
  type NamedField,
  type RegistryTool,
} from './registry'

export const SETTINGS_REFERENCE_PAGE = 'Project-Settings-Registry.md'

const CANONICAL_BANNER = [
  '<!-- canonical-banner -->',
  '> 📖 **Canonical version:** read this page on the official docs site — ' +
    '**[https://www.redamon.org/docs/project-settings-registry](https://www.redamon.org/docs/project-settings-registry)**. ' +
    'The GitHub wiki is a mirror.',
  '<!-- canonical-banner -->',
  '',
]

const DISPOSITION_LABEL: Record<string, string> = {
  settable: 'settable',
  create_only: 'create-only',
  never: 'closed',
}

/** One markdown table cell: pipes and newlines would break the row. */
function cell(text: string): string {
  return text.replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').trim()
}

function boundsCell(f: NamedField): string {
  if (f.bounds) {
    const unit = f.unit === 'none' ? '' : ` ${f.unit}`
    return `${f.bounds.min}–${f.bounds.max}${unit}`
  }
  if (f.values) return f.values.map(v => `\`${v}\``).join(', ')
  if (f.validator) return `\`${f.validator}\``
  if (f.type === 'boolean') return 'true / false'
  return '—'
}

function defaultCell(f: NamedField): string {
  if (!f.has_default) return '—'
  const d = f.default
  if (Array.isArray(d)) return d.length === 0 ? '(empty)' : `\`${JSON.stringify(d).slice(0, 80)}\``
  if (typeof d === 'string') return d === '' ? '(empty)' : `\`${d.slice(0, 80)}\``
  return `\`${String(d)}\``
}

function meaningCell(f: NamedField): string {
  const notes: string[] = []
  if (f.zero_means === 'unlimited') {
    notes.push('**0 means UNLIMITED here, so it is the fastest value and not the safest.**')
  }
  if (f.roe_capped) {
    notes.push('Capped to the engagement rate ceiling at scan start.')
  }
  if (f.fallback === 'falsy') {
    notes.push('An empty value is replaced by the default rather than honoured.')
  }
  if (f.mcp === 'create_only') {
    notes.push('Fixed at project creation; refused on an existing project.')
  }
  if (f.group === 'engagement_limits') {
    notes.push('An engagement LIMIT: enforced at scan start whatever tuning says.')
  }
  if (f.deny_reason === 'engagement-record') {
    notes.push('Part of the engagement RECORD. A person writes it, a model reads it, ' +
      'nothing enforces it; the MCP surface never touches it.')
  }
  if (f.deny_reason === 'derived') {
    notes.push('DERIVED, never written.')
  }
  if (f.deny_reason === 'upload-managed' && f.written_by) {
    notes.push(`Written only by ${f.written_by}.`)
  }
  if (f.roe_parse === 'deny') {
    notes.push('A Rules of Engagement document may never set this.')
  }
  if (f.roe_parse === 'tighten_only') {
    notes.push(`A Rules of Engagement document may only set it to \`${JSON.stringify(f.roe_safe_value)}\`.`)
  }
  if (f.readable === false) {
    notes.push('Withheld from every read on the MCP surface.')
  }
  if (f.share === 'secret') {
    notes.push("The owner's only: never shown to a collaborator.")
  }
  // What stealth mode does to this field. An operator choosing a value wants to
  // know it will be overwritten before they spend time on it, and a `ceiling`
  // behaves differently from a `set`: it leaves an already-quieter value alone.
  if (f.stealth) {
    notes.push(
      'ceiling' in f.stealth
        ? `In stealth mode this is lowered to at most ${f.stealth.ceiling}; a quieter value is kept.`
        : `In stealth mode this is forced to \`${JSON.stringify(f.stealth.set)}\`.`
    )
  }
  return cell([f.meaning, ...notes].join(' '))
}

function toolHeading(id: string, tool: RegistryTool | undefined): string {
  const title = tool?.title ?? id
  const phase = tool?.phase === 'standalone' ? 'standalone' : `phase \`${tool?.phase}\``
  const traffic =
    tool?.traffic === 'none'
      ? 'sends no traffic'
      : tool?.traffic === 'passive'
        ? 'passive traffic'
        : 'active traffic at the target'
  return `### ${title}\n\n*${phase} · ${traffic}*\n`
}

export function renderSettingsReference(): string {
  const registry = loadRegistry()
  const all = fieldsWhere(() => true)
  const byTool = new Map<string, NamedField[]>()
  for (const f of all) {
    const list = byTool.get(f.tool)
    if (list) list.push(f)
    else byTool.set(f.tool, [f])
  }

  const counts = {
    total: all.length,
    settable: all.filter(f => f.mcp === 'settable').length,
    createOnly: all.filter(f => f.mcp === 'create_only').length,
    never: all.filter(f => f.mcp === 'never').length,
    engagementLimits: all.filter(f => f.group === 'engagement_limits' && f.mcp === 'settable').length,
  }

  const out: string[] = [...CANONICAL_BANNER]
  out.push('# Project Settings Registry')
  out.push('')
  out.push(
    'Every configurable parameter of a RedAmon project, with what it means, what it accepts ' +
    'and whether an external agent may write it. **GENERATED** from ' +
    '`recon_settings/registry.yaml`; a test fails the build when this page and the registry ' +
    'disagree, so it cannot go stale.'
  )
  out.push('')
  out.push(
    `There are **${counts.total}** parameters. ${counts.settable} are settable over the MCP ` +
    `surface at any time, ${counts.createOnly} are fixed when a project is created, and ` +
    `${counts.never} are not pipeline parameters at all. ${counts.engagementLimits} of the ` +
    `settable ones are the engagement's LIMITS - a rate ceiling, an exclusion list, a time ` +
    `window, the agent's denylists - which the form and the MCP surface reach alike and which ` +
    `the pipeline enforces at scan start whatever tuning says.`
  )
  out.push('')
  out.push('For the narrative version with screenshots, see [Project Settings Reference](Project-Settings-Reference).')
  out.push('')
  out.push('## How to read this')
  out.push('')
  out.push(
    '- **Accepts** is the ENFORCED bound, not a suggestion. A value outside it is refused ' +
    'by name rather than clamped, and one bad key refuses a whole batch.'
  )
  out.push(
    '- **Written vs resolved.** Several values are corrected at scan start rather than ' +
    'refused: a rate above the engagement ceiling comes down to the ceiling, a container ' +
    'image outside the shipped set is pinned back to the default, and a wordlist path ' +
    'outside the project directory is dropped. Each is logged with a `[guardrail]` line.'
  )
  out.push(
    '- **Zero is not always the slowest value.** Several rate fields treat `0` as ' +
    'UNLIMITED, which makes it the most aggressive setting available. Those say so.'
  )
  out.push(
    '- **Two levels.** `scanModules` decides which PHASES run; a per-tool `*Enabled` flag ' +
    'decides which tools run inside a phase. Setting one without the other is a silent no-op. ' +
    'JS recon is the exception: it is no phase, `jsReconEnabled` alone switches it on, and it ' +
    'analyzes the JS files `resource_enum` and `http_probe` found, so it needs one of those. ' +
    'jsluice runs inside `resource_enum`.'
  )
  out.push(
    '- **One capability surface.** Every settable field has an input in the project form and ' +
    'is writable through `update_recon_settings`; neither door reaches something the other ' +
    'cannot. The exception is the engagement RECORD, which is deliberately UI-only.'
  )
  out.push('')

  const toolIds = [...byTool.keys()].sort((a, b) => {
    const at = registry.tools[a]?.title ?? a
    const bt = registry.tools[b]?.title ?? b
    return at.localeCompare(bt)
  })

  out.push('## Contents')
  out.push('')
  for (const id of toolIds) {
    const title = registry.tools[id]?.title ?? id
    const anchor = title.toLowerCase().replace(/[^a-z0-9 -]/g, '').replace(/ /g, '-')
    out.push(`- [${title}](#${anchor}) (${byTool.get(id)!.length})`)
  }
  out.push('')
  out.push('---')
  out.push('')

  for (const id of toolIds) {
    out.push(toolHeading(id, registry.tools[id]))
    out.push('| Field | Accepts | Default | MCP | Meaning |')
    out.push('| --- | --- | --- | --- | --- |')
    for (const f of byTool.get(id)!.sort((a, b) => a.key.localeCompare(b.key))) {
      out.push(
        `| \`${f.key}\` | ${boundsCell(f)} | ${defaultCell(f)} | ` +
        `${DISPOSITION_LABEL[f.mcp]} | ${meaningCell(f)} |`
      )
    }
    out.push('')
  }

  return out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'
}

/**
 * The counts the narrative page must agree with.
 *
 * TWO numbers, not one, because "714 configurable parameters" was false in a
 * quieter way than the "245+" it replaced: 47 of the 714 configure nothing a
 * person or an agent can reach - row identity, internal state, a stored
 * credential, a derived flag. Stating the total as the configurable count
 * overstates the surface exactly as the old number understated it.
 */
export function parameterCount(): number {
  return settableFieldCount()
}

/** Every Project column the registry describes, configurable or not. */
export function totalColumnCount(): number {
  return fieldsWhere(() => true).length
}

/** Columns a token may write through `update_recon_settings`. */
export function settableFieldCount(): number {
  return fieldsWhere(f => f.mcp === 'settable').length
}
