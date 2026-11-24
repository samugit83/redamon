// d3-force ships no types and @types/d3-force is not installed: this declares
// only what GraphCanvas2D uses. Remove it if @types/d3-force is ever added.
declare module 'd3-force' {
  interface CollideForce {
    radius(radius: number): CollideForce
    strength(strength: number): CollideForce
    iterations(iterations: number): CollideForce
  }
  export function forceCollide(): CollideForce
}
