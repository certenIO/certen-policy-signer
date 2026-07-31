# certen-external-policy-signer — you run this image, and it holds YOUR key. Nothing here is custodial:
# the signer asks your policy engine for a decision and signs only on an approval.
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
# Both scripts `npm ci`'s prepare hook runs must exist before it fires: the patch fixes accumulate.js's
# Time.encode, and the build no-ops here (src/ arrives below, so this layer stays cacheable).
COPY scripts/fix-accumulate-encoding.mjs scripts/build.mjs ./scripts/
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build         # esbuild bundle -> dist/signer.cjs (inlines the patched accumulate.js)

FROM node:20-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json* ./
# only pino is external at runtime (kept out of the bundle). --ignore-scripts: the patch is already
# baked into the bundle, and this stage has no scripts/ dir to run it from anyway.
RUN npm install --omit=dev --no-save --ignore-scripts pino@^9 && npm cache clean --force
COPY --from=build /app/dist ./dist
# The durable store (store.path) lives here. Own it as `node` in the image so an empty volume mounted
# over it inherits that ownership — otherwise the non-root process cannot write its state.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["node", "dist/signer.cjs"]
CMD ["/config/config.yaml"]
