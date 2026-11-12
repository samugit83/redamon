'use client'

import { useCallback, useEffect, useState } from 'react'
import { fetchJson, settle, type ApiResult } from '@/lib/apiError'
import { forbiddenPermission } from '@/components/auth/ForbiddenNotice'
import type { ProjectSkillsRowContribution } from '@/lib/plugins/contributions'
import type { SkillSummary, SummaryModel } from '@/lib/plugins/summaryModel'

export interface ProjectSkillRowAction extends ProjectSkillsRowContribution {
  pluginId: string
  pluginDisplayName: string
}

interface Loaded {
  projectId: string
  bySkill: Map<string, SkillSummary>
  rowActions: ProjectSkillRowAction[]
  error: string | null
}

const NONE = { bySkill: new Map<string, SkillSummary>(), rowActions: [] as ProjectSkillRowAction[] }

/** A read's error to show; a person without `plugins:use` has no plugin facts, which is not a failure. */
function failure(read: ApiResult<unknown>) {
  if (read.ok || forbiddenPermission(read.error) === 'plugins:use') return null
  return read.error
}

/**
 * The plugin facts the Agent Skills section needs for a saved project: the per-skill override
 * summary and the `project.skills.row` contributions. A failed or refused fetch of either
 * resolves to "nothing" here — the section must never break on a core page (RV-52) — and
 * `error` says what failed ("… (code · HTTP n)"), for a hint with Retry (`reload`). Null
 * projectId (create mode) fetches nothing.
 *
 * State is only ever set from a finished fetch, filed under its project: a reload keeps the
 * current rows on screen until the new answer replaces them (so a focused Versions button
 * stays put), while a project switch shows nothing from the old project. No effect sets state
 * synchronously.
 */
export function usePluginSkillOverrides(projectId: string | null | undefined) {
  const [reloads, setReloads] = useState(0)
  const [loaded, setLoaded] = useState<Loaded | null>(null)

  useEffect(() => {
    if (!projectId) return
    let live = true
    const read = (url: string, fallback: string) =>
      settle(() => fetchJson<unknown>(url, { cache: 'no-store' }, fallback), fallback)
    Promise.all([
      read(`/api/plugins/overrides/summary?projectId=${encodeURIComponent(projectId)}`, 'Plugin skill versions could not be loaded'),
      read('/api/plugins/contributions', 'Plugin items could not be loaded'),
    ])
      .then(([summaryRead, contributionsRead]) => {
        if (!live) return
        const summary = summaryRead.ok ? summaryRead.value : null
        const contributions = contributionsRead.ok ? contributionsRead.value : null
        const failed = failure(summaryRead) ?? failure(contributionsRead)
        const bySkill = new Map<string, SkillSummary>()
        if (summary && Array.isArray((summary as SummaryModel).skills)) {
          for (const s of (summary as SummaryModel).skills) bySkill.set(s.skillId, s)
        }
        const rowActions: ProjectSkillRowAction[] = []
        if (Array.isArray(contributions)) {
          for (const c of contributions as { pluginId: string; displayName: string; projectSkillsRow?: ProjectSkillsRowContribution[] }[]) {
            for (const row of c.projectSkillsRow ?? []) {
              rowActions.push({ ...row, pluginId: c.pluginId, pluginDisplayName: c.displayName })
            }
          }
        }
        setLoaded({ projectId, bySkill, rowActions, error: failed ? failed.message : null })
      })
      .catch(() => {
        if (live) setLoaded({ projectId, ...NONE, error: 'Plugin items could not be loaded' })
      })
    return () => {
      live = false
    }
  }, [projectId, reloads])

  const reload = useCallback(() => setReloads((n) => n + 1), [])

  const current = projectId && loaded && loaded.projectId === projectId ? loaded : null
  return {
    bySkill: current?.bySkill ?? NONE.bySkill,
    rowActions: current?.rowActions ?? NONE.rowActions,
    ready: !!current,
    error: current?.error ?? null,
    reload,
  }
}
