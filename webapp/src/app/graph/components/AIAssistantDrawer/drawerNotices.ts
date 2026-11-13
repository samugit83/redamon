/**
 * The texts the chat drawer shows for failures that used to pass in silence:
 * a session list or delete that failed, a delete that left its agent running,
 * and a decision clicked while the socket was down.
 */
import type { ConversationAction, ConversationDeleteWarning } from '@/hooks/useConversations'

/** Toast titles for a failed session action; the list's own failure is shown in the history panel. */
export const CONVERSATION_FAILURE_TITLE: Record<Exclude<ConversationAction, 'list'>, string> = {
  create: 'Could not create the session record',
  delete: 'Could not delete the session',
  load: 'Could not open the session',
  update: 'Could not update the session',
  share: 'Could not change the session sharing',
}

function warningText(w: ConversationDeleteWarning): string {
  const cause = [w.code, w.status ? `HTTP ${w.status}` : null].filter(Boolean).join(' · ')
  return w.step === 'agent_stop'
    ? `its agent could not be stopped and may still be running (${cause})`
    : `its attack-chain nodes could not be removed from the graph (${cause})`
}

/** "Session deleted, but its agent could not be stopped and may still be running (agent_unreachable)." */
export function deleteWarningsText(warnings: ConversationDeleteWarning[]): string {
  return `Session deleted, but ${warnings.map(warningText).join('; ')}.`
}

export const DECISION_NOT_SENT =
  'Not connected to the agent: your decision was not sent. Wait for the connection to come back, then decide again.'
