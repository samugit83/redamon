import { useCallback } from 'react'
import type { ChatItem, FireteamItem } from '../types'
import type { PlanWaveItem } from '../AgentTimeline'
import type { TodoItem } from '@/lib/websocket-types'
import { PHASE_CONFIG, formatModelDisplay } from '../phaseConfig'
import type { Phase } from '../types'

interface DownloadMarkdownDeps {
  chatItems: ChatItem[]
  currentPhase: Phase
  iterationCount: number
  modelName: string
  todoList: TodoItem[]
}

export function useDownloadMarkdown(deps: DownloadMarkdownDeps) {
  const { chatItems, currentPhase, iterationCount, modelName, todoList } = deps

  const handleDownloadMarkdown = useCallback(() => {
    if (chatItems.length === 0) return

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const lines: string[] = []

    // Header
    lines.push('# AI Agent Session Report')
    lines.push('')
    lines.push(`**Date:** ${new Date().toLocaleString()}  `)
    lines.push(`**Phase:** ${PHASE_CONFIG[currentPhase].label}  `)
    if (iterationCount > 0) lines.push(`**Step:** ${iterationCount}  `)
    if (modelName) lines.push(`**Model:** ${formatModelDisplay(modelName)}  `)
    lines.push('')
    lines.push('---')
    lines.push('')

    // Todo list snapshot
    if (todoList.length > 0) {
      lines.push('## Task List')
      lines.push('')
      todoList.forEach((item: TodoItem) => {
        const icon = item.status === 'completed' ? '[x]' : item.status === 'in_progress' ? '[-]' : '[ ]'
        const desc = item.description || item.content || item.activeForm || 'No description'
        lines.push(`- ${icon} ${desc}`)
      })
      lines.push('')
      lines.push('---')
      lines.push('')
    }

    // Chat timeline
    lines.push('## Session Timeline')
    lines.push('')

    chatItems.forEach(item => {
      if ('role' in item) {
        // Message
        const time = item.timestamp.toLocaleTimeString()
        if (item.role === 'user') {
          lines.push(`### User  \`${time}\``)
          if (item.isGuidance) lines.push('> *[Guidance]*')
        } else {
          lines.push(`### Assistant  \`${time}\``)
          if (item.responseTier === 'full_report') lines.push('> **[Report]**')
          else if (item.responseTier === 'summary') lines.push('> **[Summary]**')
        }
        lines.push('')
        lines.push(item.content)
        lines.push('')
        if (item.error) {
          lines.push(`> **Error:** ${item.error}`)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'thinking') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Thinking  \`${time}\``)
        lines.push('')
        if (item.thought) {
          lines.push(`> ${item.thought}`)
          lines.push('')
        }
        if (item.reasoning) {
          lines.push('<details>')
          lines.push('<summary>Reasoning</summary>')
          lines.push('')
          lines.push(item.reasoning)
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        if (item.updated_todo_list && item.updated_todo_list.length > 0) {
          lines.push('<details>')
          lines.push('<summary>Todo List Update</summary>')
          lines.push('')
          item.updated_todo_list.forEach(todo => {
            const icon = todo.status === 'completed' ? '[x]' : todo.status === 'in_progress' ? '[-]' : '[ ]'
            const desc = todo.description || todo.content || todo.activeForm || ''
            lines.push(`- ${icon} ${desc}`)
          })
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'deep_think') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Deep Think  \`${time}\``)
        lines.push('')
        lines.push(`> **Trigger:** ${item.trigger_reason}`)
        lines.push('')
        if (item.analysis) {
          lines.push(item.analysis)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'tool_execution') {
        const time = item.timestamp.toLocaleTimeString()
        const statusIcon = item.status === 'success' ? 'OK' : item.status === 'error' ? 'FAIL' : 'RUNNING'
        lines.push(`### Tool: \`${item.tool_name}\`  \`${time}\`  [${statusIcon}]`)
        lines.push('')

        // Arguments
        if (item.tool_args && Object.keys(item.tool_args).length > 0) {
          lines.push('**Arguments**')
          lines.push('')
          Object.entries(item.tool_args).forEach(([key, value]) => {
            lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
          })
          lines.push('')
        }

        // Raw Output
        const rawOutput = item.output_chunks.join('')
        if (rawOutput) {
          lines.push('<details>')
          lines.push('<summary>Raw Output</summary>')
          lines.push('')
          lines.push('```')
          lines.push(rawOutput)
          lines.push('```')
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }

        // Analysis
        if (item.final_output) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(item.final_output)
          lines.push('')
        }

        // Actionable Findings
        if (item.actionable_findings && item.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          item.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }

        // Recommended Next Steps
        if (item.recommended_next_steps && item.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          item.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }

        lines.push('---')
        lines.push('')
      } else if (item.type === 'plan_wave') {
        const waveItem = item as PlanWaveItem
        const time = waveItem.timestamp.toLocaleTimeString()
        const statusIcon = waveItem.status === 'success' ? 'OK' : waveItem.status === 'error' ? 'FAIL' : waveItem.status === 'partial' ? 'PARTIAL' : 'RUNNING'
        lines.push(`### Wave — ${waveItem.tool_count} tools  \`${time}\`  [${statusIcon}]`)
        lines.push('')
        if (waveItem.plan_rationale) {
          lines.push(`> ${waveItem.plan_rationale}`)
          lines.push('')
        }
        // Export each nested tool
        waveItem.tools.forEach(tool => {
          const toolStatusIcon = tool.status === 'success' ? 'OK' : tool.status === 'error' ? 'FAIL' : 'RUNNING'
          lines.push(`#### Tool: \`${tool.tool_name}\`  [${toolStatusIcon}]`)
          lines.push('')
          if (tool.tool_args && Object.keys(tool.tool_args).length > 0) {
            lines.push('**Arguments**')
            lines.push('')
            Object.entries(tool.tool_args).forEach(([key, value]) => {
              lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
            })
            lines.push('')
          }
          const rawToolOutput = tool.output_chunks.join('')
          if (rawToolOutput) {
            lines.push('<details>')
            lines.push('<summary>Raw Output</summary>')
            lines.push('')
            lines.push('```')
            lines.push(rawToolOutput)
            lines.push('```')
            lines.push('')
            lines.push('</details>')
            lines.push('')
          }
          if (tool.final_output) {
            lines.push('**Analysis**')
            lines.push('')
            lines.push(tool.final_output)
            lines.push('')
          }
          if (tool.actionable_findings && tool.actionable_findings.length > 0) {
            lines.push('**Actionable Findings**')
            lines.push('')
            tool.actionable_findings.forEach(f => lines.push(`- ${f}`))
            lines.push('')
          }
          if (tool.recommended_next_steps && tool.recommended_next_steps.length > 0) {
            lines.push('**Recommended Next Steps**')
            lines.push('')
            tool.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
            lines.push('')
          }
        })
        // Wave-level analysis
        if (waveItem.interpretation) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(waveItem.interpretation)
          lines.push('')
        }
        if (waveItem.actionable_findings && waveItem.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          waveItem.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }
        if (waveItem.recommended_next_steps && waveItem.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          waveItem.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'fireteam') {
        const ft = item as FireteamItem
        const time = ft.timestamp.toLocaleTimeString()
        const wall = ft.wall_clock_seconds !== undefined ? ` · ${ft.wall_clock_seconds.toFixed(1)}s` : ''
        lines.push(`### Fireteam — ${ft.members.length} members  \`${time}\`  [${ft.status.toUpperCase()}${wall}]`)
        lines.push('')
        if (ft.plan_rationale) {
          lines.push(`> ${ft.plan_rationale}`)
          lines.push('')
        }
        if (ft.status_counts && Object.keys(ft.status_counts).length > 0) {
          const counts = Object.entries(ft.status_counts)
            .map(([k, v]) => `${v} ${k}`).join(' · ')
          lines.push(`**Status counts:** ${counts}`)
          lines.push('')
        }
        ft.members.forEach(m => {
          lines.push(`#### Member: ${m.name}  \`${m.member_id}\`  [${m.status.toUpperCase()}]`)
          lines.push('')
          if (m.task) {
            lines.push(`> ${m.task}`)
            lines.push('')
          }
          const meta: string[] = []
          if (m.skills && m.skills.length > 0) meta.push(`skills: ${m.skills.join(', ')}`)
          if (m.iterations_used > 0) meta.push(`${m.iterations_used} iter`)
          if (m.tokens_used > 0) meta.push(`${m.tokens_used} tok`)
          const toolCount = (m.tools?.length || 0)
            + (m.planWaves?.reduce((n, w) => n + (w.tools?.length || 0), 0) || 0)
          if (toolCount > 0) meta.push(`${toolCount} tools`)
          if (m.findings_count > 0) meta.push(`${m.findings_count} findings`)
          if (meta.length > 0) {
            lines.push(`*${meta.join(' · ')}*`)
            lines.push('')
          }
          if (m.completion_reason && m.status !== 'success') {
            lines.push(`**Completion reason:** ${m.completion_reason}`)
            lines.push('')
          }
          if (m.error_message) {
            lines.push(`> **Error:** ${m.error_message}`)
            lines.push('')
          }
          if (m.latest_thought) {
            lines.push(`*Latest thought:* ${m.latest_thought}`)
            lines.push('')
          }
          // Render member's tool calls
          m.tools?.forEach(tool => {
            const toolStatusIcon = tool.status === 'success' ? 'OK' : tool.status === 'error' ? 'FAIL' : 'RUNNING'
            lines.push(`##### Tool: \`${tool.tool_name}\`  [${toolStatusIcon}]`)
            lines.push('')
            if (tool.tool_args && Object.keys(tool.tool_args).length > 0) {
              Object.entries(tool.tool_args).forEach(([k, v]) => {
                lines.push(`- **${k}:** \`${typeof v === 'string' ? v : JSON.stringify(v)}\``)
              })
              lines.push('')
            }
            const rawOutput = tool.output_chunks?.join('') || ''
            if (rawOutput) {
              lines.push('<details><summary>Raw Output</summary>')
              lines.push('')
              lines.push('```')
              lines.push(rawOutput)
              lines.push('```')
              lines.push('')
              lines.push('</details>')
              lines.push('')
            }
            if (tool.final_output) {
              lines.push(tool.final_output)
              lines.push('')
            }
          })
          // Render member's nested plan waves
          m.planWaves?.forEach(wave => {
            const waveStatus = wave.status === 'success' ? 'OK' : wave.status === 'error' ? 'FAIL' : wave.status === 'partial' ? 'PARTIAL' : 'RUNNING'
            lines.push(`##### Plan Wave — ${wave.tool_count} tools  [${waveStatus}]`)
            lines.push('')
            if (wave.plan_rationale) {
              lines.push(`> ${wave.plan_rationale}`)
              lines.push('')
            }
            wave.tools?.forEach(tool => {
              const toolStatusIcon = tool.status === 'success' ? 'OK' : tool.status === 'error' ? 'FAIL' : 'RUNNING'
              lines.push(`- \`${tool.tool_name}\` [${toolStatusIcon}]`)
            })
            lines.push('')
          })
        })
        lines.push('---')
        lines.push('')
      } else if (item.type === 'file_download') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### File Download  \`${time}\``)
        lines.push('')
        lines.push(`- **File:** ${item.filename}`)
        lines.push(`- **Path:** \`${item.filepath}\``)
        lines.push(`- **Source:** ${item.source}`)
        lines.push(`- **Description:** ${item.description}`)
        lines.push('')
        lines.push('---')
        lines.push('')
      }
    })

    // Download
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redamon-session-${timestamp}.md`
    a.click()
    URL.revokeObjectURL(url)
  }, [chatItems, currentPhase, iterationCount, modelName, todoList])

  return { handleDownloadMarkdown }
}
