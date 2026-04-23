import type {
  ThinkingItem,
  ToolExecutionItem,
  PlanWaveItem,
  DeepThinkItem,
  TimelineItem,
  FireteamItem,
  FireteamMemberPanel,
  FireteamMemberStatus,
} from './AgentTimeline'

// Re-export AgentTimeline types so consumers only need one import path
export type {
  ThinkingItem,
  ToolExecutionItem,
  PlanWaveItem,
  DeepThinkItem,
  TimelineItem,
  FireteamItem,
  FireteamMemberPanel,
  FireteamMemberStatus,
}

export type Phase = 'informational' | 'exploitation' | 'post_exploitation'

export interface Message {
  type: 'message'
  id: string
  role: 'user' | 'assistant'
  content: string
  toolUsed?: string | null
  toolOutput?: string | null
  error?: string | null
  phase?: Phase
  timestamp: Date
  isGuidance?: boolean
  isReport?: boolean
  responseTier?: 'conversational' | 'summary' | 'full_report'
}

export interface FileDownloadItem {
  type: 'file_download'
  id: string
  timestamp: Date
  filepath: string
  filename: string
  description: string
  source: string
}

export type ChatItem =
  | Message
  | ThinkingItem
  | ToolExecutionItem
  | PlanWaveItem
  | FileDownloadItem
  | DeepThinkItem
  | FireteamItem

export interface AIAssistantDrawerProps {
  isOpen: boolean
  onClose: () => void
  userId: string
  projectId: string
  sessionId: string
  onResetSession?: () => string
  onSwitchSession?: (sessionId: string) => void
  modelName?: string
  onModelChange?: (modelId: string) => void
  toolPhaseMap?: Record<string, string[]>
  stealthMode?: boolean
  onToggleStealth?: (newValue: boolean) => void
  deepThinkEnabled?: boolean
  onToggleDeepThink?: (newValue: boolean) => void
  onRefetchGraph?: () => void
  isOtherChainsHidden?: boolean
  onToggleOtherChains?: () => void
  hasOtherChains?: boolean
  requireToolConfirmation?: boolean
  graphViewCypher?: string
}
