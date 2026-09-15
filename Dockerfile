# certen-external-policy-signer — you run this image, and it holds YOUR key. Nothing here is custodial:
# the signer asks your policy engine for a decision and signs only on an approval.
FROM node:20-slim AS build
WORKDIR /app
# A compiler for the ONE native addon, pkcs11js (the pkcs11 key source), built explicitly below.
RUN apt-get update  && apt-get install -y --no-install-recommends python3 make g++  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
COPY scripts/fix-accumulate-encoding.mjs scripts/build.mjs scripts/build-pkcs11js.sh ./scripts/
# No dependency install script runs (supply chain). The two things they would have done are explicit steps:
# the accumulate.js Time.encode patch, and the pinned pkcs11js build (read first; see the script and
# docs/KEY-SOURCES.md).
RUN npm ci --ignore-scripts && node scripts/fix-accumulate-encoding.mjs
RUN sh scripts/build-pkcs11js.sh
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
# pkcs11js is external to the bundle (a native addon): its loader and the addon compiled in the build stage.
COPY --from=build /app/node_modules/pkcs11js/package.json /app/node_modules/pkcs11js/index.js ./node_modules/pkcs11js/
COPY --from=build /app/node_modules/pkcs11js/build/Release/pkcs11.node ./node_modules/pkcs11js/build/Release/pkcs11.node
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
