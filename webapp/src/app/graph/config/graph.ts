// Force simulation settings (legacy -- used as base, see getAdaptiveForceConfig)
export const FORCE_CONFIG = {
  alphaDecay: 0.02,
  velocityDecay: 0.4,
  collisionRadius: 20,
  collisionStrength: 1,
  collisionIterations: 3,
  cooldownTime: 15000,
  cooldownTicks: 300,
} as const

// Adaptive force config based on node count
export function getAdaptiveForceConfig(nodeCount: number) {
  if (nodeCount > 5000) return { cooldownTime: 3000,  cooldownTicks: 50,  collisionIterations: 1, warmupTicks: 100 }
  if (nodeCount > 2000) return { cooldownTime: 5000,  cooldownTicks: 100, collisionIterations: 2, warmupTicks: 50  }
  if (nodeCount > 500)  return { cooldownTime: 10000, cooldownTicks: 200, collisionIterations: 3, warmupTicks: 30  }
  return                        { cooldownTime: 15000, cooldownTicks: 300, collisionIterations: 3, warmupTicks: 0   }
}

// Performance tiers based on node count
export type PerformanceTier = 'full' | 'reduced' | 'minimal' | 'ultra-minimal'

export function getPerformanceTier(nodeCount: number): PerformanceTier {
  if (nodeCount <= 1000) return 'full'
  if (nodeCount <= 2000) return 'reduced'
  if (nodeCount <= 5000) return 'minimal'
  return 'ultra-minimal'
}

export const TIER_CONFIG = {
  full:            { sphereSegments: 16, enableGlow: true,  enableWireframe: true,  enableLabels: true,  enableParticles: true,  ringSegments: 32, lodDistances: [100, 300] as const },
  reduced:         { sphereSegments: 8,  enableGlow: true,  enableWireframe: false, enableLabels: true,  enableParticles: true,  ringSegments: 16, lodDistances: [80, 200] as const },
  minimal:         { sphereSegments: 6,  enableGlow: false, enableWireframe: false, enableLabels: true,  enableParticles: false, ringSegments: 8,  lodDistances: [50, 150] as const },
  'ultra-minimal': { sphereSegments: 4,  enableGlow: false, enableWireframe: false, enableLabels: true,  enableParticles: false, ringSegments: 6,  lodDistances: [30, 100] as const },
} as const

// Animation settings
export const ANIMATION_CONFIG = {
  criticalSpeed: 10,
  highSpeed: 3,
  glowPulseRange: { min: 0.85, max: 1.15 },
  glowOpacityRange: { min: 0.2, max: 0.6 },
  glow2DPulseRange: { min: 0, max: 1 },
  glow2DRadiusExtra: { base: 2, pulse: 3 },
  initDelay: 300,
} as const

// Zoom settings
export const ZOOM_CONFIG = {
  labelVisibilityThreshold: 1.5,
} as const

// 3D specific settings
export const THREE_CONFIG = {
  sphereSegments: 16,
  ringSegments: 32,
  nodeOpacity: 0.9,
  glowRingOpacity: 0.4,
  selectionRingOpacity: 0.9,
  selectionRingScale: { inner: 1.4, outer: 1.6 },
  glowRingScale: { inner: 1.15, outer: 1.4 },
} as const
