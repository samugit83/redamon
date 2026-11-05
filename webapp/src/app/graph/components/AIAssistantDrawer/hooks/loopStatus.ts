/**
 * What the chat drawer shows for an Agent in the Loop run: the status word, the
 * chip, and the notices. Pure, so every state is unit-tested; every string the
 * person reads lives here.
 */
import type { LoopStatusPayload } from '@/lib/websocket-types'

export const LOOP_WIKI_URL = 'https://github.com/samugit83/redamon/wiki/Agent-in-the-Loop'
export const LOOP_SETTINGS_URL = '/settings?tab=mcp-tokens'

export const LOOP_CHIP_LABEL = 'Agent in the Loop'
export const LOOP_CHIP_TOOLTIP =
  'Claude Code, Codex or another MCP agent is answering each step. Approvals stay with you, ' +
  'and dangerous tools ask you while the project\'s "Require Tool Confirmation" is on.'

export const LOOP_UNATTENDED_LABEL = 'Unattended: dangerous tools run without your confirmation'
export const LOOP_UNATTENDED_TOOLTIP =
  'Unattended run: "Require Tool Confirmation" is off for this project. The external agent ' +
  'answering this chat (Claude Code, Codex, or any process holding its MCP token) runs ' +
  'dangerous tools such as kali_shell, metasploit, hydra and nmap without asking you. It ' +
  'reads text written by the target at every step, and that text can steer it. No person ' +
  'confirms a dangerous action before it reaches the target. Anthropic and OpenAI expect ' +
  'unattended automation to use an API key, not a subscription login. Turn the switch back on ' +
  'in the project settings to confirm each dangerous tool.'

export const LOOP_FIRST_USE =
  'No agent is connected. Start Claude Code or Codex with the Agent in the Loop skill and say ' +
  '"Drive my RedAmon session".'
export const LOOP_ACT_AS =
  'This chat is answered by the external agent of the user you are acting as. Your own token ' +
  'cannot drive it.'

const PURPOSE_LABEL: Record<string, string> = {
  think: 'next action',
  deep_think: 'deep think',
  lats_expand: 'exploit-path search',
  fireteam_member: 'fireteam member',
  classify: 'request classification',
  scope_guardrail: 'scope check',
  cypher: 'graph query',
  report: 'final report',
}

export interface LoopNotice {
  tone: 'info' | 'warning' | 'error'
  text: string
  /** The first-use notice links the setup guide and the token settings. */
  links?: boolean
}

export interface LoopDisplay {
  /** Replaces the rotating word while the run is loading; null keeps it. */
  statusWord: string | null
  /** The run uses Agent in the Loop: show the chip. */
  chip: boolean
  /** The run's tool confirmation is off: mark the chip with the risk icon. */
  unattended: boolean
  notices: LoopNotice[]
}

const NONE: LoopDisplay = { statusWord: null, chip: false, unattended: false, notices: [] }

function errorNotice(detail: LoopStatusPayload['detail']): LoopNotice | null {
  switch (detail.code) {
    case 'loop_step_declined':
      return {
        tone: 'warning',
        text: detail.reason
          ? `Your agent declined this step: ${detail.reason}`
          : 'Your agent declined this step.',
      }
    case 'loop_step_not_answered':
      return { tone: 'error', text: 'Your agent did not answer in time. The run ended.' }
    case 'loop_no_driver':
      return {
        tone: 'error',
        text: 'No agent answered within 5 minutes. Start your agent and send the message again.',
      }
    default:
      return null
  }
}

export function loopDisplay(
  status: LoopStatusPayload | null | undefined,
  opts: { actingAs?: boolean } = {},
): LoopDisplay {
  if (!status) return NONE
  // Strictly false: an agent that predates the field sends nothing, and says nothing.
  const unattended = status.toolConfirmation === false
  const notices: LoopNotice[] = []
  let statusWord: string | null = null
  const step = status.step

  if (status.state === 'error') {
    const notice = errorNotice(status.detail ?? {})
    if (notice) notices.push(notice)
  } else if (status.state === 'finished' || status.state === 'stopped') {
    return { statusWord: null, chip: true, unattended, notices: [] }
  } else if (step?.state === 'claimed') {
    const purpose = PURPOSE_LABEL[step.purpose] ?? step.purpose
    statusWord = step.iteration != null
      ? `Your agent is answering · ${purpose} · iteration ${step.iteration}`
      : `Your agent is answering · ${purpose}`
  } else if (step?.state === 'open') {
    statusWord = 'Waiting for your agent…'
    if (status.driver && !status.driver.connected) {
      notices.push({ tone: 'info', text: LOOP_FIRST_USE, links: true })
    }
  } else if (status.state === 'running_tool' && status.detail?.tool) {
    statusWord = `RedAmon is running ${status.detail.tool}`
  }

  if (opts.actingAs && status.state !== 'error') {
    notices.push({ tone: 'info', text: LOOP_ACT_AS })
  }
  return { statusWord, chip: true, unattended, notices }
}

/** "answered via laptop (rdmn_mcp_ab12…)" for a thinking card, or null. */
export function answeredViaLine(answeredBy: { token_prefix?: string; token_name?: string } | null | undefined): string | null {
  if (!answeredBy) return null
  const name = (answeredBy.token_name ?? '').trim()
  const prefix = (answeredBy.token_prefix ?? '').trim()
  if (!name && !prefix) return null
  if (name && prefix) return `answered via ${name} (${prefix}…)`
  return `answered via ${name || `${prefix}…`}`
}
