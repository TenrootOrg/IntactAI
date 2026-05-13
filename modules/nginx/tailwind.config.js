/** @type {import('tailwindcss').Config} */
// Tailwind build config for the IntactAI dashboard.
// Run `bash modules/nginx/build-tailwind.sh` from the repo root to
// rebuild html/css/tailwind.css after adding new utility classes.
module.exports = {
  content: [
    'html/index.html',
    'html/js/**/*.js',
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
