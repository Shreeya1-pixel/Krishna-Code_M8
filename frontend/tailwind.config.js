/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          DEFAULT: '#005bb5',
          dark: '#004488',
          hover: '#0066cc',
          light: '#e6f0fa',
        },
        surface: {
          DEFAULT: '#ffffff',
          muted: '#f8f9fa',
          soft: '#f5f6f8',
        },
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'Helvetica',
          'Arial',
          'sans-serif',
        ],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      boxShadow: {
        card: '0 2px 8px rgba(0,0,0,.08)',
        soft: '0 1px 2px rgba(0,0,0,.05)',
      },
    },
  },
  plugins: [],
}
