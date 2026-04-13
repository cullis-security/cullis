/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/dashboard/templates/**/*.html',
    './mcp_proxy/dashboard/templates/**/*.html',
  ],
  theme: {
    extend: {
      colors: {
        surface: {
          950: '#0a0f1a',
          900: '#111827',
          800: '#1a1f2e',
          700: '#252b3d',
        },
        accent: {
          400: '#00e5c7',
          500: '#00c9ae',
          600: '#00ad96',
        },
        info: {
          400: '#0ea5e9',
          500: '#0284c7',
        },
      },
      fontFamily: {
        heading: ['Chakra Petch', 'sans-serif'],
        body: ['DM Sans', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  // Safelist dynamic classes that may be generated at runtime (toasts, status badges)
  safelist: [
    'bg-emerald-900/90', 'border-emerald-700/50', 'text-emerald-300',
    'bg-red-900/90', 'border-red-700/50', 'text-red-300',
    'bg-accent-400', 'pulse-dot', 'bg-gray-700',
  ],
  plugins: [],
};
