import type {
  ThinkingItem,
  ToolExecutionItem,
  PlanWaveItem,
  DeepThinkItem,
  TimelineItem,
  FireteamItem,
  FireteamMemberPanel,
  FireteamMemberStatus,
  LatsSearchItem,
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
  LatsSearchItem,
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
  projectId?: string
}

export type ChatItem =
  | Message
  | ThinkingItem
  | ToolExecutionItem
  | PlanWaveItem
  | FileDownloadItem
  | DeepThinkItem
  | FireteamItem
  | LatsSearchItem

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
  onRefetchGraph?: () => void
  isOtherChainsHidden?: boolean
  onToggleOtherChains?: () => void
  hasOtherChains?: boolean
  requireToolConfirmation?: boolean
  graphViewCypher?: string
  onOpenFileSystem?: () => void
  // A node-scoped first message to send once a fresh session connects. The
  // `token` changes per request so re-selecting the same node re-fires.
  pendingNodeQuery?: PendingNodeQuery | null
  onPendingNodeQueryConsumed?: () => void
}

export interface PendingNodeQuery {
  token: number
  nodeLabel: string
  context: string
  request: string
}
