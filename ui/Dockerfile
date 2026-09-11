# syntax=docker/dockerfile:1
#
# Multi-stage build for the Secy UI (Vite 6 / React 18 / TypeScript).
#
# Build stage: Node 20, matching the devcontainer image per CLAUDE.md ("The devcontainer
# image is Node 20 + JDK 17"). Runtime stage: static files served by nginx, with a
# reverse-proxy rule for /api/** (see nginx.conf) — there's no Vite dev server in a built
# image, so nginx has to take over the job vite.config.ts's `server.proxy` does in dev.

# --- Build stage -------------------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /workspace

# package.json + lockfile first so `npm ci` is cached in its own layer.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
# `npm run build` = `tsc --noEmit && vite build` -> dist/
RUN npm run build

# --- Runtime stage -------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /workspace/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=5 \
    CMD wget --quiet --tries=1 --spider http://localhost/ || exit 1

# nginx:alpine's own ENTRYPOINT/CMD already run nginx in the foreground; nothing to override.
