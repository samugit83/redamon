/**
 * What the drawer hid when the person answered one of the agent's requests, and how to put it
 * back when the agent refuses the answer (step 3.9b review, finding 3; step 5.4 review).
 *
 * The drawer hides the card and shows the decision at once. A refusal leaves the request open on
 * the agent, and no request frame comes again (unlike an `mcp_toolset_busy` refusal), so the card
 * is restored from here, the optimistic decision line goes, and the chat says why: the permission
 * the answer needed (`permission_required`), a decision-time check that did not answer
 * (`decision_check_unavailable`, which refuses the owner too), or the agent's own sentence for a
 * code this drawer does not know. Each answer replaces its kind's entry; the agent's frame names
 * the refused answer (`answer`, and the Fireteam wave and member).
 */
import { PERMISSIONS, isPermissionId } from '@/lib/authz/permissions'
import type {
  ApprovalRequestPayload, QuestionRequestPayload, ToolConfirmationRequestPayload,
} from '@/lib/websocket-types'
import { agentErrorText, reopensPendingRequest } from './agentErrorText'
import type { ChatItem, FireteamItem } from '../types'
import type { PlanWaveItem } from '../AgentTimeline'

export interface AnswerUndo {
  approval: { request: ApprovalRequestPayload; messageId: string } | null
  /** With what the person entered, so a refused answer need not be typed again. */
  question: {
    request: QuestionRequestPayload; messageId: string; answerText: string; selectedOptions: string[]
  } | null
  toolConfirmation: {
    request: ToolConfirmationRequestPayload | null
    /** The card as it was before a reject marked it; null when the answer left it as it was. */
    item: ChatItem | null
    toolId: string | null
    waveId: string | null
  } | null
  /** By `fireteamUndoKey(wave, member)`: the member's pending wave and where it sat. */
  fireteam: Record<string, { wave: PlanWaveItem; waveIdx: number }>
}

export const emptyAnswerUndo = (): AnswerUndo => ({ approval: null, question: null, toolConfirmation: null, fireteam: {} })

export const fireteamUndoKey = (waveId: string, memberId: string) => `${waveId}\u0000${memberId}`

export const DECISION_CHECK_UNAVAILABLE_TEXT = 'RedAmon could not confirm your permission to take this decision, '
  + 'so your answer was not applied. The request is open again: try again in a moment.'

interface RefusalBase {
  kind: 'permission' | 'unavailable' | 'other'
  permission: string
  /** The chat's sentence for it. */
  text: string
}

export type RefusedAnswer =
  | RefusalBase & { answer: 'approval' | 'tool_confirmation' | 'question' }
  | RefusalBase & { answer: 'fireteam_member_confirmation'; waveId: string; memberId: string }

interface RefusalPayload {
  message?: unknown
  code?: unknown
  recoverable?: unknown
  permission?: unknown
  answer?: unknown
  wave_id?: unknown
  member_id?: unknown
}

/**
 * The answer a recoverable frame naming one refused, whatever the code; null for any other
 * frame, and for `mcp_toolset_busy`, whose request the agent sends again itself.
 */
export function refusedAnswer(payload: RefusalPayload | null | undefined): RefusedAnswer | null {
  if (!payload || payload.recoverable !== true || reopensPendingRequest(payload)) return null
  const permission = typeof payload.permission === 'string' ? payload.permission : ''
  const why: RefusalBase = payload.code === 'permission_required'
    ? { kind: 'permission', permission, text: permissionRefusalText(permission) }
    : payload.code === 'decision_check_unavailable'
      ? { kind: 'unavailable', permission, text: DECISION_CHECK_UNAVAILABLE_TEXT }
      : { kind: 'other', permission, text: agentErrorText(payload) }
  if (payload.answer === 'approval' || payload.answer === 'tool_confirmation' || payload.answer === 'question') {
    return { answer: payload.answer, ...why }
  }
  if (payload.answer === 'fireteam_member_confirmation'
      && typeof payload.wave_id === 'string' && typeof payload.member_id === 'string') {
    return { answer: payload.answer, ...why, waveId: payload.wave_id, memberId: payload.member_id }
  }
  return null
}

/** The chat's sentence for a refused answer: the permission by id and by what it allows. */
export function permissionRefusalText(permission: string): string {
  const name = isPermissionId(permission) ? permission : 'a permission'
  const what = isPermissionId(permission) ? ` ("${PERMISSIONS[permission].description.replace(/\.$/, '')}")` : ''
  return `Your answer was not applied: it needs ${name}${what}, which you do not hold on this project. `
    + 'The request stays open for someone who holds it.'
}

export const withoutItem = (items: ChatItem[], id: string): ChatItem[] => items.filter((it) => it.id !== id)

/** `item` back in place of the card with its id (a reject had marked it). */
export const withItemRestored = (items: ChatItem[], item: ChatItem): ChatItem[] =>
  items.map((it) => (it.id === item.id ? item : it))

/**
 * The member's pending wave back where it sat: an approve had dropped it, a reject had marked
 * it. Unchanged when the wave or the member is gone (the wave ended meanwhile).
 */
export function withFireteamWaveRestored(
  items: ChatItem[], fireteamId: string, memberId: string, undo: { wave: PlanWaveItem; waveIdx: number },
): ChatItem[] {
  const ftIdx = items.findIndex((it) => it.type === 'fireteam' && (it as FireteamItem).fireteam_id === fireteamId)
  if (ftIdx < 0) return items
  const ft = items[ftIdx] as FireteamItem
  const mIdx = ft.members.findIndex((m) => m.member_id === memberId)
  if (mIdx < 0) return items
  const member = ft.members[mIdx]
  const kept = member.planWaves.filter((w) => w.id !== undo.wave.id)
  const at = Math.min(undo.waveIdx, kept.length)
  const planWaves = [...kept.slice(0, at), undo.wave, ...kept.slice(at)]
  const members = [...ft.members.slice(0, mIdx), { ...member, planWaves }, ...ft.members.slice(mIdx + 1)]
  const next = items.slice()
  next[ftIdx] = { ...ft, members }
  return next
}
