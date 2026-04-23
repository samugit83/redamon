import { useEffect, useRef } from 'react'

/**
 * Custom hook for running animation frames with optional frame skipping.
 * @param callback - Function to call on each animation frame, receives current time in seconds
 * @param enabled - Whether the animation should run
 * @param frameSkip - Number of frames to skip between invocations (default 2 = ~20fps)
 */
export function useAnimationFrame(
  callback: (time: number) => void,
  enabled: boolean,
  frameSkip: number = 2
) {
  const callbackRef = useRef(callback)

  // Update callback ref on each render to avoid stale closures
  useEffect(() => {
    callbackRef.current = callback
  }, [callback])

  useEffect(() => {
    if (!enabled) return

    let count = 0
    let animationId: number

    const animate = () => {
      if (count % (frameSkip + 1) === 0) {
        const time = Date.now() / 1000
        callbackRef.current(time)
      }
      count++
      animationId = requestAnimationFrame(animate)
    }

    animationId = requestAnimationFrame(animate)

    return () => {
      cancelAnimationFrame(animationId)
    }
  }, [enabled, frameSkip])
}
