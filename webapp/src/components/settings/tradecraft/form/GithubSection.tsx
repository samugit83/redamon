'use client'

import type { CheckUrlResult } from '@/lib/tradecraft/agentContract'
import { SettingsOnlySection, Suggest, type FormContext } from './OverrideList'
import css from './form.module.css'

type Github = NonNullable<CheckUrlResult['github']>

/** GitHub repository (§6.5): branch or tag, folders, file types, one entry per folder, map size. */
export function GithubSection({ ctx, github }: { ctx: FormContext; github: Github | null }) {
  const include = Array.isArray(ctx.overrides['type.github.includeFolders']) ? ctx.overrides['type.github.includeFolders'] as string[] : []
  const exclude = Array.isArray(ctx.overrides['type.github.excludeFolders']) ? ctx.overrides['type.github.excludeFolders'] as string[] : []
  const refs = github ? [...new Set([github.default_branch, ...github.branches, ...github.tags])].filter(Boolean) : []
  const folders = github?.top_folders ?? []
  const hints = github ? {
    'type.github.branch': refs.length > 0 && (
      <div className={css.suggestions} aria-label="Branches and tags Check URL found">
        {refs.slice(0, 30).map(r => <Suggest key={r} label={r} onUse={() => ctx.setOverride('type.github.branch', r)} />)}
      </div>
    ),
    'type.github.includeFolders': folders.length > 0 && (
      <div className={css.suggestions} aria-label="Folders to include">
        {folders.filter(f => !include.includes(f)).slice(0, 50).map(f => (
          <Suggest key={f} label={`+ ${f}`} onUse={() => ctx.setOverride('type.github.includeFolders', [...include, f])} />
        ))}
      </div>
    ),
    'type.github.excludeFolders': folders.length > 0 && (
      <div className={css.suggestions} aria-label="Folders to exclude">
        {folders.filter(f => !exclude.includes(f)).slice(0, 50).map(f => (
          <Suggest key={f} label={`− ${f}`} onUse={() => ctx.setOverride('type.github.excludeFolders', [...exclude, f])} />
        ))}
      </div>
    ),
  } : {}
  return <SettingsOnlySection ctx={ctx} title="GitHub repository" section="github" hints={hints} />
}
