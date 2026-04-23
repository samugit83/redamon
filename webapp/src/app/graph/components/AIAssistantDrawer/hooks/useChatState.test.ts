/**
 * Unit tests for useChatState groupedChatItems logic.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/hooks/useChatState.test.ts
 *
 * The grouping logic is extracted as a pure function matching the useMemo in useChatState.
 */

import { describe, test, expect } from 'vitest'
import type { ChatItem, Message, FileDownloadItem } from '../types'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from '../AgentTimeline'

// ---------------------------------------------------------------------------
// Pure extraction of groupedChatItems logic (mirrors useChatState.ts useMemo)
// ---------------------------------------------------------------------------

type GroupedItem = {
  type: 'message' | 'timeline' | 'file_download'
  content: Message | Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> | FileDownloadItem
}

function groupChatItems(chatItems: ChatItem[]): GroupedItem[] {
  const result: GroupedItem[] = []
  let currentTimelineGroup: Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> = []

  chatItems.forEach((item) => {
    if ('role' in item) {
      if (currentTimelineGroup.length > 0) {
        result.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      result.push({ type: 'message', content: item as Message })
    } else if ('type' in item && item.type === 'file_download') {
      if (currentTimelineGroup.length > 0) {
        result.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      result.push({ type: 'file_download', content: item as FileDownloadItem })
    } else if ('type' in item && (item.type === 'thinking' || item.type === 'tool_execution' || item.type === 'plan_wave' || item.type === 'deep_think')) {
      currentTimelineGroup.push(item as ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem)
    }
  })

  if (currentTimelineGroup.length > 0) {
    result.push({ type: 'timeline', content: currentTimelineGroup })
  }

  return result
}

// ---------------------------------------------------------------------------
// Factories
// ---------------------------------------------------------------------------

let idCounter = 0
const nextId = () => `id-${++idCounter}`

function makeMessage(overrides: Partial<Message> = {}): Message {
  return {
    type: 'message',
    id: nextId(),
    role: 'assistant',
    content: 'Hello',
    timestamp: new Date(),
    ...overrides,
  }
}

function makeThinking(overrides: Partial<ThinkingItem> = {}): ThinkingItem {
  return {
    type: 'thinking',
    id: nextId(),
    timestamp: new Date(),
    thought: 'Thinking...',
    ...overrides,
  }
}

function makeTool(overrides: Partial<ToolExecutionItem> = {}): ToolExecutionItem {
  return {
    type: 'tool_execution',
    id: nextId(),
    timestamp: new Date(),
    tool_name: 'execute_nmap',
    tool_args: {},
    status: 'running',
    output_chunks: [],
    ...overrides,
  }
}

function makeWave(overrides: Partial<PlanWaveItem> = {}): PlanWaveItem {
  return {
    type: 'plan_wave',
    id: nextId(),
    timestamp: new Date(),
    wave_id: `wave-${nextId()}`,
    plan_rationale: 'Parallel recon',
    tool_count: 0,
    tools: [],
    status: 'running',
    ...overrides,
  }
}

function makeDeepThink(overrides: Partial<DeepThinkItem> = {}): DeepThinkItem {
  return {
    type: 'deep_think',
    id: nextId(),
    timestamp: new Date(),
    thought: 'Deep analysis...',
    ...overrides,
  }
}

function makeFileDownload(overrides: Partial<FileDownloadItem> = {}): FileDownloadItem {
  return {
    type: 'file_download',
    id: nextId(),
    filepath: '/tmp/report.md',
    filename: 'report.md',
    description: 'Report file',
    source: 'agent',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('groupChatItems – empty and single items', () => {
  test('empty input returns empty array', () => {
    expect(groupChatItems([])).toEqual([])
  })

  test('single message → one message group', () => {
    const msg = makeMessage()
    const result = groupChatItems([msg])
    expect(result).toHaveLength(1)
    expect(result[0].type).toBe('message')
    expect(result[0].content).toBe(msg)
  })

  test('single thinking item → one timeline group', () => {
    const t = makeThinking()
    const result = groupChatItems([t])
    expect(result).toHaveLength(1)
    expect(result[0].type).toBe('timeline')
    expect(result[0].content).toEqual([t])
  })

  test('single file_download → one file_download group', () => {
    const f = makeFileDownload()
    const result = groupChatItems([f])
    expect(result).toHaveLength(1)
    expect(result[0].type).toBe('file_download')
    expect(result[0].content).toBe(f)
  })
})

describe('groupChatItems – timeline grouping', () => {
  test('consecutive timeline items are merged into one group', () => {
    const t1 = makeThinking()
    const t2 = makeTool()
    const t3 = makeWave()
    const result = groupChatItems([t1, t2, t3])
    expect(result).toHaveLength(1)
    expect(result[0].type).toBe('timeline')
    expect(result[0].content).toEqual([t1, t2, t3])
  })

  test('message after thinking items flushes timeline first', () => {
    const t = makeThinking()
    const msg = makeMessage()
    const result = groupChatItems([t, msg])
    expect(result).toHaveLength(2)
    expect(result[0].type).toBe('timeline')
    expect(result[0].content).toEqual([t])
    expect(result[1].type).toBe('message')
    expect(result[1].content).toBe(msg)
  })

  test('message before thinking items: message then timeline', () => {
    const msg = makeMessage()
    const t = makeTool()
    const result = groupChatItems([msg, t])
    expect(result).toHaveLength(2)
    expect(result[0].type).toBe('message')
    expect(result[1].type).toBe('timeline')
    expect(result[1].content).toEqual([t])
  })

  test('timeline items trailing at end are emitted', () => {
    const msg = makeMessage()
    const t1 = makeTool()
    const t2 = makeDeepThink()
    const result = groupChatItems([msg, t1, t2])
    expect(result).toHaveLength(2)
    expect(result[0].type).toBe('message')
    expect(result[1].type).toBe('timeline')
    expect((result[1].content as any[]).length).toBe(2)
  })

  test('all four timeline item types grouped together', () => {
    const t = makeThinking()
    const tool = makeTool()
    const wave = makeWave()
    const dt = makeDeepThink()
    const result = groupChatItems([t, tool, wave, dt])
    expect(result).toHaveLength(1)
    expect(result[0].type).toBe('timeline')
    expect((result[0].content as any[]).length).toBe(4)
  })
})

describe('groupChatItems – interleaved sequences', () => {
  test('message → timeline → message produces 3 groups', () => {
    const m1 = makeMessage({ id: 'm1', role: 'user', content: 'Hi' })
    const t = makeThinking()
    const m2 = makeMessage({ id: 'm2', role: 'assistant', content: 'Ok' })
    const result = groupChatItems([m1, t, m2])
    expect(result).toHaveLength(3)
    expect(result[0].type).toBe('message')
    expect(result[1].type).toBe('timeline')
    expect(result[2].type).toBe('message')
  })

  test('two separate timeline groups around a message', () => {
    const t1 = makeThinking()
    const m = makeMessage()
    const t2 = makeTool()
    const result = groupChatItems([t1, m, t2])
    expect(result).toHaveLength(3)
    expect(result[0].type).toBe('timeline')
    expect(result[1].type).toBe('message')
    expect(result[2].type).toBe('timeline')
    // Groups are separate arrays
    expect(result[0].content).not.toBe(result[2].content)
  })

  test('realistic sequence: user → thinking+tool → assistant → file_download', () => {
    const user = makeMessage({ role: 'user', content: 'Scan 10.0.0.1' })
    const thinking = makeThinking()
    const tool = makeTool()
    const assistant = makeMessage({ role: 'assistant', content: 'Done' })
    const file = makeFileDownload()

    const result = groupChatItems([user, thinking, tool, assistant, file])
    expect(result).toHaveLength(4)
    expect(result[0].type).toBe('message')
    expect(result[1].type).toBe('timeline')
    expect((result[1].content as any[]).length).toBe(2)
    expect(result[2].type).toBe('message')
    expect(result[3].type).toBe('file_download')
  })
})

describe('groupChatItems – file_download breaks timeline', () => {
  test('file_download between two tool items creates three groups', () => {
    const t1 = makeTool()
    const f = makeFileDownload()
    const t2 = makeTool()
    const result = groupChatItems([t1, f, t2])
    expect(result).toHaveLength(3)
    expect(result[0].type).toBe('timeline')
    expect(result[0].content).toEqual([t1])
    expect(result[1].type).toBe('file_download')
    expect(result[2].type).toBe('timeline')
    expect(result[2].content).toEqual([t2])
  })
})

describe('groupChatItems – isolation (no shared references)', () => {
  test('two separate timeline groups do not share the same array reference', () => {
    const t1 = makeThinking()
    const m = makeMessage()
    const t2 = makeTool()
    const result = groupChatItems([t1, m, t2])
    const group1 = result[0].content as any[]
    const group2 = result[2].content as any[]
    expect(group1).not.toBe(group2)
    expect(group1[0]).toBe(t1)
    expect(group2[0]).toBe(t2)
  })
})
