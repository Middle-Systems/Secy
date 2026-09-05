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

/**
 * Split the heavy, rarely-changing vendor code into a handful of named chunks
 * so the browser can cache them independently and the entry stays small.
 *
 * `recharts` (+ its d3 / victory-vendor / lodash transitive deps) and
 * `tanstack-table` are only pulled in by lazily-loaded route views, so they
 * land in async chunks that are never part of the initial page load. Only
 * `react`, `tanstack` (router + query) and `radix` are needed by the eager
 * app shell.
 */
function manualChunks(id: string): string | undefined {
  if (!id.includes('/node_modules/')) return undefined;

  // React runtime + the class-name utilities (`cn`) that the whole UI — shell
  // and every view — depends on eagerly. Pinning the utils here keeps Rollup
  // from folding them into the lazy `recharts` vendor chunk.
  if (
    /\/node_modules\/(react|react-dom|scheduler|clsx|tailwind-merge|class-variance-authority|tailwindcss-animate|use-sync-external-store)\//.test(
      id,
    )
  ) {
    return 'react';
  }
  // TanStack Table is only used by the (lazy) list views — keep it out of the
  // eager router/query chunk.
  if (/\/node_modules\/@tanstack\/(react-table|table-core)\//.test(id)) {
    return 'tanstack-table';
  }
  if (id.includes('/node_modules/@tanstack/')) return 'tanstack';
  if (
    /\/node_modules\/(recharts|recharts-scale|victory-vendor|d3-[a-z-]+|internmap|react-smooth|react-is|lodash|decimal\.js-light|fast-equals|eventemitter3)\//.test(
      id,
    )
  ) {
    return 'recharts';
  }
  if (
    id.includes('/node_modules/@radix-ui/') ||
    id.includes('/node_modules/@floating-ui/')
  ) {
    return 'radix';
  }

  return undefined;
}

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    rollupOptions: {
      output: { manualChunks },
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
