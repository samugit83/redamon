import { useEffect, useEffectEvent } from 'react'

/**
 * A browser-wide notice that a user's skills or a project's skill toggles changed, so every
 * open window (the project form, the chat drawer, Global Settings) refreshes instead of
 * holding a map that a later save would write back.
 *
 * A BroadcastChannel delivers a post to every OTHER channel object of the same name, in this
 * tab too (never to the one that posted), so with it each listener hears a post exactly once.
 * Where there is no BroadcastChannel, a listener set in this module stands in, for this tab only.
 */
export const USER_SKILLS_CHANNEL = 'redamon:user-skills'

export interface UserSkillsChange {
  /** The project whose toggles changed, if any. */
  projectId?: string | null
}

type Listener = (change: UserSkillsChange) => void
const local = new Set<Listener>()
const hasChannel = () => typeof BroadcastChannel !== 'undefined'

export function postUserSkillsChanged(change: UserSkillsChange = {}): void {
  if (!hasChannel()) {
    for (const l of [...local]) l(change)
    return
  }
  try {
    const ch = new BroadcastChannel(USER_SKILLS_CHANNEL)
    ch.postMessage(change)
    ch.close()
  } catch {
    for (const l of [...local]) l(change)
  }
}

export function useUserSkillsChanged(onChange: Listener): void {
  const notify = useEffectEvent(onChange)
  useEffect(() => {
    const listener: Listener = (c) => notify(c)
    let ch: BroadcastChannel | null = null
    if (hasChannel()) {
      try {
        ch = new BroadcastChannel(USER_SKILLS_CHANNEL)
        ch.onmessage = (e: MessageEvent) => {
          listener(e.data && typeof e.data === 'object' ? (e.data as UserSkillsChange) : {})
        }
      } catch {
        ch = null
      }
    }
    // The fallback set is used only when this tab has no channel to listen on.
    if (!ch) local.add(listener)
    return () => {
      local.delete(listener)
      ch?.close()
    }
  }, [])
}
