/**
 * The user's selectable models, the one /api/models read every picker shares.
 * Its own module because ModelPicker and FeatureModelGate both need it, and the
 * gate already imports the picker.
 */
import { ApiError, fetchJson } from '@/lib/apiError'
import type { ModelOption } from '@/app/graph/components/AIAssistantDrawer/modelUtils'

export type ModelsByProvider = Record<string, ModelOption[]>

export const MODELS_LOAD_FAILED = 'Failed to load models'

const isModelGroups = (data: unknown): data is ModelsByProvider =>
  !!data && typeof data === 'object' && !Array.isArray(data) && !(data as { error?: unknown }).error

/**
 * The models grouped by provider. Without a userId the agent lists only the models of
 * the providers set in its environment. Throws an ApiError: its code tells the agent
 * not running (agent_unreachable) from the agent failing (agent_error).
 *
 * With `projectId`, the models of that project's OWNER (GET /api/projects/[id]/owner-catalog
 * ?models=1, step 5.7): what a co-owner's pickers offer, since the project runs on the owner's
 * providers. The route answers them at Manage only; below it the pickers never ask.
 */
export async function fetchModelOptions(
  userId?: string | null,
  options: { projectId?: string | null } = {},
): Promise<ModelsByProvider> {
  if (options.projectId) {
    const body = await fetchJson<{ models?: unknown }>(
      `/api/projects/${encodeURIComponent(options.projectId)}/owner-catalog?models=1`,
      { cache: 'no-store' },
      MODELS_LOAD_FAILED,
    )
    if (!isModelGroups(body?.models)) throw new ApiError({ reason: MODELS_LOAD_FAILED, status: 200, code: 'invalid_response' })
    return body.models
  }
  const data = await fetchJson<unknown>('/api/models', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userId ? { userId } : {}),
    cache: 'no-store',
  }, MODELS_LOAD_FAILED)
  if (!isModelGroups(data)) {
    throw new ApiError({ reason: MODELS_LOAD_FAILED, status: 200, code: 'invalid_response' })
  }
  return data
}
