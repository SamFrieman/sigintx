/// <reference types="vite/client" />

declare module 'cobe' {
  export interface GlobeOptions {
    devicePixelRatio?: number
    width?: number
    height?: number
    phi?: number
    theta?: number
    dark?: number
    diffuse?: number
    mapSamples?: number
    mapBrightness?: number
    baseColor?: [number, number, number]
    markerColor?: [number, number, number]
    glowColor?: [number, number, number]
    markers?: { location: [number, number]; size: number }[]
    arcs?: {
      startLat: number; startLng: number
      endLat: number;   endLng: number
      arcAlt?: number
      color?: [number, number, number, number]
    }[]
    onRender?: (state: Record<string, unknown>) => void
  }

  export interface Globe {
    destroy: () => void
  }

  export default function createGlobe(
    canvas: HTMLCanvasElement,
    options: GlobeOptions,
  ): Globe
}
