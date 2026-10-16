# SentinelX dashboard
#
# Multi-stage build. Build context is the REPO ROOT (matches the api/worker
# services), so paths below are relative to the repo root, not dashboard/:
#
#   docker build -f dashboard/Dockerfile -t sentinelx-dashboard .

# --- build stage: compile the React app ---
FROM node:20-alpine AS build
WORKDIR /app

COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY dashboard/ ./
RUN npm run build

# --- serve stage: static files behind nginx ---
FROM nginx:alpine
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
