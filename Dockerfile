# ATTEST — production image
#
# The circuit is pre-built and committed, so this image needs no circom, no
# Rust and no 4.6 MB ptau ceremony file at deploy time. The host only needs to
# run Node and prove against the committed zkey/wasm.

FROM node:20-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev


FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

# Non-root: this service writes decision records, so it should not be able to
# write anywhere else.
RUN groupadd -r attest && useradd -r -g attest attest

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public

# The committed seed record. Without this the image has no record to load and
# falls back to proving six decisions live on every boot — slow cold starts and
# a different chain every restart.
COPY seed ./seed
COPY circuits/build/policy_final.zkey ./circuits/build/policy_final.zkey
COPY circuits/build/verification_key.json ./circuits/build/verification_key.json
COPY circuits/build/policy_js ./circuits/build/policy_js
COPY circuits/policy.circom ./circuits/policy.circom

# Records live here. Mount a volume here if you want them to survive a redeploy;
# without one the app reseeds on boot, which is correct but not persistent.
ENV ATTEST_DATA_DIR=/app/data
RUN mkdir -p /app/data && chown -R attest:attest /app

USER attest
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
