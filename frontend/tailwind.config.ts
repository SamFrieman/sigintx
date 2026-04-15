import type { Config } from 'tailwindcss'

const config: Config = {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['Orbitron', 'monospace'],
        heading: ['Rajdhani', 'sans-serif'],
        mono: ['Share Tech Mono', 'monospace'],
        code: ['IBM Plex Mono', 'monospace'],
      },
      colors: {
        // Primitive layer
        'prim-black': {
          900: '#030609',
          800: '#060d18',
          700: '#091422',
          600: '#0d1c30',
          500: '#112540',
        },
        'prim-cyan': { 400: '#00d4ff', 300: '#33ddff', 200: '#80eaff' },
        'prim-green': { 400: '#00ff88', 300: '#33ffaa' },
        'prim-red': { 400: '#ff2255', 300: '#ff5577' },
        'prim-amber': { 400: '#ffaa00', 300: '#ffc040' },
        'prim-purple': { 400: '#aa44ff', 300: '#cc77ff' },
        'prim-white': {
          100: '#e8f0ff',
          200: '#b0c8e8',
          300: '#6888aa',
          400: '#304860',
          500: '#182838',
        },
      },
      backgroundColor: {
        base: '#030609',
        surface: '#060d18',
        card: '#091422',
        'card-hover': '#0d1c30',
        elevated: '#112540',
      },
      borderColor: {
        base: '#182838',
        accent: 'rgba(0,212,255,0.25)',
        glow: 'rgba(0,212,255,0.08)',
      },
      keyframes: {
        'pulse-dot': {
          '0%, 100%': { opacity: '1', transform: 'scale(1)' },
          '50%':      { opacity: '0.4', transform: 'scale(0.8)' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateY(-8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        scanline: {
          '0%':   { top: '-5%' },
          '100%': { top: '105%' },
        },
        glow: {
          '0%, 100%': { boxShadow: '0 0 6px rgba(0,212,255,0.3)' },
          '50%':       { boxShadow: '0 0 20px rgba(0,212,255,0.7)' },
        },
      },
      animation: {
        'pulse-dot': 'pulse-dot 1.5s ease-in-out infinite',
        'slide-in':  'slide-in 0.25s ease-out',
        'fade-in':   'fade-in 0.3s ease-out',
        scanline:    'scanline 4s linear infinite',
        glow:        'glow 2s ease-in-out infinite',
      },
      backgroundImage: {
        'grid-cyan': 'linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px)',
        'scanline':  'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,212,255,0.012) 2px, rgba(0,212,255,0.012) 4px)',
        vignette:    'radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.7) 100%)',
      },
      backgroundSize: {
        grid: '50px 50px',
      },
    },
  },
  plugins: [],
}

export default config
