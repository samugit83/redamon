import { useCallback, useEffect, useRef, useState, useMemo } from 'react'

export interface GraphInstance {
  camera?: () => { position: { distanceTo: (point: { x: number; y: number; z: number }) => number } }
  pauseAnimation: () => unknown
  resumeAnimation: () => unknown
  renderer?: () => { domElement: HTMLElement }
  controls?: () => {
    addEventListener: (type: string, listener: () => void) => void
    removeEventListener: (type: string, listener: () => void) => void
  }
}

/** Keep the library's own interaction/simulation loop, but let static 3D scenes sleep. */
export function useGraphRendering(
  continuous: boolean,
  pauseWhenIdle: boolean,
  onCameraChange?: (graph: GraphInstance) => void,
) {
  // The two graph packages expose different imperative APIs.
  const graphRef = useRef<any>(null)
  const [instance, setInstance] = useState<GraphInstance | null>(null)
  const continuousRef = useRef(continuous)
  const cameraChangeRef = useRef(onCameraChange)
  const actions = useRef({ wake: (_layoutChanged = false) => {}, stop: () => {}, tick: () => {} })
  continuousRef.current = continuous
  cameraChangeRef.current = onCameraChange

  // These packages type ref as an object, so observe attachment through its setter.
  const bindGraphRef = useMemo<{ current: any }>(() => ({
    get current() { return graphRef.current },
    set current(graph: GraphInstance | null | undefined) {
      graphRef.current = graph ?? null
      setInstance(graph ?? null)
    },
  }), [])
  const invalidate = useCallback((layoutChanged = false) => actions.current.wake(layoutChanged), [])
  const onEngineStop = useCallback(() => actions.current.stop(), [])
  const onEngineTick = useCallback(() => actions.current.tick(), [])

  useEffect(() => {
    if (!instance) return
    let engineRunning = true
    let interacting = false
    let wakeTimer: ReturnType<typeof setTimeout> | undefined
    let idleTimer: ReturnType<typeof setTimeout> | undefined

    const clearTimers = () => {
      clearTimeout(wakeTimer)
      clearTimeout(idleTimer)
      wakeTimer = idleTimer = undefined
    }
    const sleepWhenIdle = () => {
      clearTimeout(idleTimer)
      // Defer past the library's current tick: it queues its next RAF AFTER onEngineStop.
      // Control change events keep this grace period alive through inertial movement.
      idleTimer = setTimeout(() => {
        if (pauseWhenIdle && !engineRunning && !interacting && !continuousRef.current) {
          instance.pauseAnimation()
        }
      }, 100)
    }
    const wake = (layoutChanged = false) => {
      if (layoutChanged) engineRunning = true
      clearTimeout(idleTimer)
      if (document.hidden || wakeTimer !== undefined) return
      // resumeAnimation renders synchronously; defer so camera/hover handlers finish first.
      wakeTimer = setTimeout(() => {
        wakeTimer = undefined
        instance.resumeAnimation()
        cameraChangeRef.current?.(instance)
        sleepWhenIdle()
      }, 0)
    }
    const change = () => {
      cameraChangeRef.current?.(instance)
      wake()
    }
    const start = () => { interacting = true; wake() }
    const end = () => { interacting = false; wake() }
    const visibility = () => {
      if (document.hidden) {
        interacting = false
        clearTimers()
        instance.pauseAnimation()
      } else {
        wake()
      }
    }
    actions.current = {
      wake,
      stop: () => { engineRunning = false; cameraChangeRef.current?.(instance); sleepWhenIdle() },
      tick: () => { engineRunning = true; cameraChangeRef.current?.(instance) },
    }

    const canvas = instance.renderer?.().domElement
    const controls = instance.controls?.()
    controls?.addEventListener('start', start)
    controls?.addEventListener('end', end)
    controls?.addEventListener('change', change)
    canvas?.addEventListener('pointerdown', start, { passive: true })
    canvas?.addEventListener('pointermove', change, { passive: true })
    canvas?.addEventListener('pointerleave', change, { passive: true })
    canvas?.addEventListener('wheel', change, { passive: true })
    window.addEventListener('pointerup', end)
    window.addEventListener('pointercancel', end)
    window.addEventListener('blur', end)
    document.addEventListener('visibilitychange', visibility)
    visibility()

    return () => {
      clearTimers()
      actions.current = { wake: () => {}, stop: () => {}, tick: () => {} }
      controls?.removeEventListener('start', start)
      controls?.removeEventListener('end', end)
      controls?.removeEventListener('change', change)
      canvas?.removeEventListener('pointerdown', start)
      canvas?.removeEventListener('pointermove', change)
      canvas?.removeEventListener('pointerleave', change)
      canvas?.removeEventListener('wheel', change)
      window.removeEventListener('pointerup', end)
      window.removeEventListener('pointercancel', end)
      window.removeEventListener('blur', end)
      document.removeEventListener('visibilitychange', visibility)
      instance.pauseAnimation()
    }
  }, [instance, pauseWhenIdle])

  useEffect(() => { invalidate() }, [continuous, invalidate])

  return { graphRef, bindGraphRef, invalidate, onEngineStop, onEngineTick }
}
