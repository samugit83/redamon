/**
 * Delete a deleted project's Agent Workspace (its files, staging and running
 * workspace jobs) through the agent. Called only after the project row is gone:
 * the agent itself refuses unless the web app answers 404 for the project.
 *
 * Best-effort, like stopping the triage run on delete: an unreachable agent
 * must never fail the delete. Server-side only.
 */
import { agentFetch } from '@/lib/agentFetch'

export async function purgeProjectWorkspace(projectId: string): Promise<void> {
  try {
    const res = await agentFetch('/workspace/project-purge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ projectId }),
    }, { timeoutMs: 60_000 })
    if (!res.ok) {
      let code = `status_${res.status}`
      try {
        const body = await res.json() as { code?: unknown }
        if (typeof body?.code === 'string') code = body.code
      } catch { /* no JSON body */ }
      console.warn(`[project-delete] workspace purge refused for ${projectId}: ${code}`)
    }
  } catch (e) {
    console.warn(`[project-delete] workspace purge failed for ${projectId}: ${e instanceof Error ? e.name : 'error'}`)
  }
}
