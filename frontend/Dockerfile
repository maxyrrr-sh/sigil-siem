# syntax=docker/dockerfile:1
#
# Sigil web console — built static SPA served by nginx (served separately from
# the API; nginx reverse-proxies /api → the sigil service). Build from REPO ROOT:
#   docker build -f frontend/Dockerfile -t sigil-web:latest .

FROM node:22-slim AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine AS runtime
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
