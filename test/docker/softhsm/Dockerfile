# SoftHSM2 integration test image for the pkcs11 key source. `npm run test:pkcs11` builds and runs it.
# Everything secret about the token (user PIN, SO PIN) is generated inside the running container by run.sh
# and exists only in its environment; the keys are generated inside the token, non-extractable.
FROM node:20-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
COPY scripts/fix-accumulate-encoding.mjs scripts/build.mjs scripts/build-pkcs11js.sh ./scripts/
# No install scripts run. The accumulate.js patch and the one native addon are explicit steps.
RUN npm ci --ignore-scripts && node scripts/fix-accumulate-encoding.mjs
RUN sh scripts/build-pkcs11js.sh
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    PKCS11_TOKEN_LABEL=orchid-seat-fictional
CMD ["sh", "test/docker/softhsm/run.sh"]
