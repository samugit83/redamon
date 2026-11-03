import { LOOP_MODEL_LABEL, isLoopModel } from '@/lib/agentInTheLoop'

export interface ModelOption {
  id: string
  name: string
  context_length: number | null
  description: string
}

export function formatContextLength(ctx: number | null): string {
  if (!ctx) return ''
  if (ctx >= 1_000_000) return `${(ctx / 1_000_000).toFixed(1)}M`
  if (ctx >= 1_000) return `${Math.round(ctx / 1_000)}K`
  return String(ctx)
}

export function getDisplayName(modelId: string, allModels: Record<string, ModelOption[]>): string {
  for (const models of Object.values(allModels)) {
    const found = models.find(m => m.id === modelId)
    if (found) return found.name
  }
  // The loop model is listed only while the switch is on; its name must not
  // turn back into an id when the list is empty or still loading.
  if (isLoopModel(modelId)) return LOOP_MODEL_LABEL
  return modelId
}
