import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// Frontend is served separately and talks to the Sigil API via `/api/*`.
// In dev, proxy that to a local `sigil run` (override with SIGIL_API).
// In prod, an nginx reverse-proxy plays the same role (see deploy/).
const API_TARGET = process.env.SIGIL_API ?? 'http://127.0.0.1:8080'

const proxy = {
  '/api': {
    target: API_TARGET,
    changeOrigin: true,
    rewrite: (p: string) => p.replace(/^\/api/, ''),
  },
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
})
