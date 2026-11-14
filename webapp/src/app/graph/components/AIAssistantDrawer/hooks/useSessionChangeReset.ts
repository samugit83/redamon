import { useEffect, type MutableRefObject } from 'react'

/**
 * Clears the drawer when the live session id changes (a new chat, "Ask agent" from a node), but
 * not on the one change a restore makes: a restore puts a timeline on screen, sets
 * `isRestoringConversation`, then moves the socket (to the session it opened, or, for a read-only
 * session, to a fresh one of the viewer's own), and that change must keep the timeline.
 */
export function useSessionChangeReset(
  sessionId: string,
  isRestoringConversation: MutableRefObject<boolean>,
  reset: () => void,
) {
  useEffect(() => {
    if (isRestoringConversation.current) {
      isRestoringConversation.current = false
      return
    }
    reset()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])
}
