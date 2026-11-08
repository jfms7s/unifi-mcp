# The build stage only compiles TypeScript to platform-independent JavaScript,
# so it runs natively on the builder. Under QEMU, its full `npm ci` (dev deps
# included) intermittently died with "qemu: uncaught target signal 4 (Illegal
# instruction)" and hung the arm64 build until the job was cancelled.
FROM --platform=$BUILDPLATFORM node:25-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:25-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
# Numeric, not `USER node`: a Kubernetes runAsNonRoot check can't resolve a
# user name to a uid. 1000:1000 is node:22-alpine's `node` user.
USER 1000:1000
EXPOSE 3000
ENV UNIFI_MCP_TRANSPORT=http
CMD ["node", "dist/index.js"]
