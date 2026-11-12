'use client'

/**
 * The permission checkboxes, shared by the create form, the edit panel and the
 * Agent Onboarding modal.
 *
 * Grouped rather than flat. A flat list of nine, where reading, scanning and
 * writing interleave and the one permission that reaches a live target looks
 * like the eight above it, was readable only by someone who already knew the
 * model. With a profile now ticking boxes on the operator's behalf, the ticks
 * have to read as a SHAPE at a glance ("this token reads and scans, nothing
 * else"), which is what the group headers are for.
 *
 * Every row inside a group looks the same. Tinting the heavier permissions red
 * made an operator decode two colour scales at once - group tier AND row
 * weight - for a distinction the row already had to spell out in words. What a
 * permission touches is a BADGE now: read, write, or both, derived from what
 * its tools really do rather than from how alarming it felt.
 *
 * `kali:exec` still gets its own panel below a separator, because a shell on a
 * target-facing box is a different KIND of block, not a louder one.
 *
 * With the permissions switch on, a scope the token's owner cannot grant is
 * disabled with the permissions it lacks (`limits`); one the token already holds
 * stays enabled so it can be taken away, since the token cannot use it anyway.
 */
import { ShieldAlert, Terminal } from 'lucide-react'
import { ExternalLink } from '@/components/ui'
import type { McpScope } from '@/lib/mcpAuth'
import { MCP_SCOPE_COPY as SCOPE_COPY, SCOPE_GROUPS, type ScopeAccess } from '@/lib/mcp/scopeCopy'
import { PROFILES, type ProfileId } from '@/lib/mcp/profiles'
import { LOOP_SCOPE, loopTokenWarning } from '@/lib/mcp/loopScopes'
import styles from './McpTokensTab.module.css'

/** Read and write share one chip each; the point is only what changes. */
const ACCESS_TEXT: Record<ScopeAccess, string> = {
  read: 'read',
  write: 'write',
  'read-write': 'read + write',
}

interface Props {
  selected: McpScope[]
  onToggle: (scope: McpScope) => void
  disabled?: boolean
  /**
   * When set, rows that differ from this profile's recommendation carry a quiet
   * "modified" tag, and the opt-in scopes it recommends are labelled as such
   * while staying unchecked.
   */
  profile?: ProfileId | null
  /**
   * Agent in the Loop is off on this deployment: its scope is not offered for a
   * new token, and a token that already holds it shows it marked off.
   */
  loopOff?: boolean
  /**
   * The scopes the token's owner cannot grant, each with the permissions it lacks
   * (the token list's `ungrantableScopes`). Absent with the permissions switch off.
   */
  limits?: Partial<Record<McpScope, readonly string[]>>
}

/** An empty list: no permission maps the scope, so nobody can grant it. */
const needsText = (missing: readonly string[]) =>
  missing.length > 0 ? missing.join(' and ') : 'a permission no account holds'

export default function ScopeChecklist({ selected, onToggle, disabled = false, profile, loopOff = false, limits }: Props) {
  const meta = profile ? PROFILES[profile] : null
  const recommended = new Set(meta?.recommendedScopes ?? [])
  const optIn = new Set(meta?.optInScopes ?? [])

  const rowState = (scope: McpScope) => {
    const checked = selected.includes(scope)
    if (!meta) return { checked, tag: null as string | null }
    if (recommended.has(scope)) {
      return { checked, tag: checked ? 'from profile' : 'removed' }
    }
    if (optIn.has(scope)) {
      // Recommended for the job, deliberately not ticked for you.
      return { checked, tag: checked ? 'added' : 'recommended, tick it yourself' }
    }
    return { checked, tag: checked ? 'added' : null }
  }
  const offered = (scope: McpScope) => !(loopOff && scope === LOOP_SCOPE && !selected.includes(scope))
  const loopWarning = loopTokenWarning(selected)

  const renderRow = (scope: McpScope, tone: 'neutral' | 'action' | 'exec') => {
    const { checked, tag } = rowState(scope)
    const copy = SCOPE_COPY[scope]
    const missing = limits?.[scope]
    return (
      <label
        key={scope}
        className={[
          styles.scopeRow,
          checked ? styles.scopeChecked : '',
          tone === 'exec' ? styles.scopeExecRow : '',
        ].filter(Boolean).join(' ')}
      >
        <input
          type="checkbox"
          className={`checkbox ${styles.scopeCheckbox}`}
          checked={checked}
          disabled={disabled || (missing !== undefined && !checked)}
          onChange={() => onToggle(scope)}
        />
        <span className={styles.scopeText}>
          <span className={styles.scopeTitleRow}>
            <strong className={styles.scopeLabel}>{copy.label}</strong>
            <span
              className={[
                styles.scopeAccess,
                copy.access === 'read' ? styles.scopeAccessRead : styles.scopeAccessWrite,
              ].join(' ')}
            >
              {ACCESS_TEXT[copy.access]}
            </span>
            <code className={styles.scopeCode}>{scope}</code>
            {tag && <span className={styles.scopeTag}>{tag}</span>}
            {loopOff && scope === LOOP_SCOPE && (
              <span className={styles.scopeTag}>(off on this deployment)</span>
            )}
            {missing !== undefined && <span className={styles.scopeTag}>limited by your permissions</span>}
          </span>
          {missing !== undefined && (
            <span className={styles.scopeLimit}>
              {checked
                ? `This token cannot use it: it needs ${needsText(missing)}, which your permissions do not include. You can remove it.`
                : `Needs ${needsText(missing)}, which your permissions do not include.`}
            </span>
          )}
          <span className={styles.scopeBlurb}>{tone === 'exec' ? copy.detail ?? copy.blurb : copy.blurb}</span>
          {tone === 'exec' && copy.learnMore && (
            <span className={styles.scopeLinks}>
              {copy.learnMore.map(link => (
                <ExternalLink key={link.href} href={link.href} className={styles.scopeLink}>
                  {link.text}
                </ExternalLink>
              ))}
            </span>
          )}
        </span>
      </label>
    )
  }

  return (
    <fieldset className={styles.scopes} disabled={disabled}>
      <legend className="formLabel">Permissions</legend>
      {limits && (
        <p className={styles.scopeFootnote}>
          <ShieldAlert size={13} />
          <span>
            Limited by your permissions: a token only ever uses what your own RedAmon permissions
            allow, checked on every call. A permission you do not hold cannot be ticked.
          </span>
        </p>
      )}

      {SCOPE_GROUPS.filter(g => g.tone !== 'exec' && g.scopes.some(offered)).map(group => (
        <div key={group.id} className={styles.scopeGroup}>
          <div className={styles.scopeGroupHeader}>
            <span className={styles.scopeGroupLabel}>{group.label}</span>
            <span className={styles.scopeGroupHint}>{group.hint}</span>
          </div>
          <div className={styles.scopeList}>
            {group.scopes.filter(offered).map(s => renderRow(s, group.tone))}
          </div>
          {group.scopes.includes(LOOP_SCOPE) && loopWarning && (
            <p className={styles.scopeFootnote} role="alert">
              <ShieldAlert size={13} />
              <span>{loopWarning}</span>
            </p>
          )}
        </div>
      ))}

      {SCOPE_GROUPS.filter(g => g.tone === 'exec').map(group => (
        <div key={group.id} className={styles.scopeExecPanel}>
          <div className={styles.scopeExecHeader}>
            <Terminal size={14} />
            <span className={styles.scopeGroupLabel}>{group.label}</span>
            <span className={styles.scopeGroupHint}>{group.hint}</span>
          </div>
          <div className={styles.scopeList}>
            {group.scopes.map(s => renderRow(s, 'exec'))}
          </div>
        </div>
      ))}

      {meta && meta.optInScopes.length > 0 && (
        <p className={styles.scopeFootnote}>
          <ShieldAlert size={13} />
          <span>
            <strong>{meta.label}</strong> also suggests{' '}
            {meta.optInScopes.map((s, i) => (
              <span key={s}>
                {i > 0 && ' and '}
                <code className={styles.scopeCode}>{s}</code>
              </span>
            ))}
            , but a profile never ticks those for you. They are deliberate choices, not side effects
            of picking a job.
          </span>
        </p>
      )}
    </fieldset>
  )
}
