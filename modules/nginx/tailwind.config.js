/** @type {import('tailwindcss').Config} */
// Tailwind build config for the IntactAI dashboard.
// Run `bash modules/nginx/build-tailwind.sh` from the repo root to
// rebuild html/css/tailwind.css after adding new utility classes.
//
// DaisyUI 4 is added as the component + theme layer (build-time only; no
// runtime JS). The "intactdark" theme below is the single source of truth
// for the dashboard's colors — a clean, professional GitHub-dark palette
// that keeps the TenRoot brand hues (red/blue/green/yellow) while dropping
// the old neon/cyberpunk treatment.
module.exports = {
  content: [
    'html/index.html',
    'html/cases.html',
    'html/downloads.html',
    'html/partials/**/*.html',
    'html/js/**/*.js',
  ],
  theme: {
    extend: {},
  },
  // Classes built dynamically in JS string templates (e.g. severity colors
  // assembled as `'border-' + x + '-500'`) can't be statically detected, so
  // keep them from being purged.
  safelist: [
    { pattern: /^(bg|text|border)-(red|blue|green|yellow|purple|orange|slate|gray)-(300|400|500|600|700|900)$/ },
    { pattern: /^badge-(error|warning|success|info|ghost|primary|secondary|accent)$/ },
    { pattern: /^btn-(primary|secondary|accent|neutral|ghost|error|warning|success|info|sm|xs|md)$/ },
    { pattern: /^alert-(error|warning|success|info)$/ },
  ],
  plugins: [require('daisyui')],
  daisyui: {
    logs: false,
    themes: [
      {
        intactdark: {
          'color-scheme': 'dark',
          primary: '#3b82f6',
          'primary-content': '#f0f6fc',
          secondary: '#f85149',
          'secondary-content': '#ffffff',
          accent: '#a371f7',
          'accent-content': '#ffffff',
          neutral: '#1c232c',
          'neutral-content': '#e6edf3',
          'base-100': '#161b22',
          'base-200': '#1c232c',
          'base-300': '#0d1117',
          'base-content': '#e6edf3',
          info: '#58a6ff',
          'info-content': '#0d1117',
          success: '#3fb950',
          'success-content': '#0d1117',
          warning: '#d29922',
          'warning-content': '#0d1117',
          error: '#f85149',
          'error-content': '#ffffff',
          '--rounded-box': '0.5rem',
          '--rounded-btn': '0.375rem',
          '--rounded-badge': '0.375rem',
          '--border-btn': '1px',
          '--tab-radius': '0.375rem',
          '--animation-btn': '0.15s',
          '--animation-input': '0.15s',
          '--btn-focus-scale': '1',
        },
      },
    ],
  },
};
