/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './public/authenticate.html',
    './public/admin.html',
  ],
  theme: {
    extend: {}
  },
  plugins: [require('autoprefixer')],
}