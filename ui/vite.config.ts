/// <reference types="vitest/config" />
import path from 'node:path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/*
 * Dev-server proxy for the Spring Boot backend (ported from the old Angular
 * `src/proxy.conf.js`).
 *
 * The backend host differs by where the dev server runs:
 *   - inside the devcontainer, the backend is on the Docker host -> host.docker.internal
 *   - directly on your machine                                   -> localhost
 *
 * Override with API_TARGET, e.g. `API_TARGET=http://localhost:8080 npm run dev`.
 */
const apiTarget =
  process.env.API_TARGET ||
  (process.env.DEVCONTAINER ? 'http://host.docker.internal:8080' : 'http://localhost:8080');

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: true, // bind 0.0.0.0 so the devcontainer port-forward works
    port: 4200,
    strictPort: true,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
        secure: false,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  preview: {
    host: true,
    port: 4200,
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
  },
});
