# syntax=docker/dockerfile:1
#
# Sigil SIEM — single-binary image (DESIGN §13.4).
# Multi-stage: build the `sigil` binary on the Rust toolchain, then ship a slim
# runtime. BuildKit cache mounts keep the cargo registry + target dir warm
# across rebuilds. Build from the repo root:  docker build -t sigil:latest .

# ---- builder ------------------------------------------------------------
FROM rust:1.96-bookworm AS builder
WORKDIR /build

# Copy the whole workspace; the cache mounts below make incremental rebuilds
# cheap despite the broad COPY.
COPY . .

# Release build of just the CLI (pulls sigil-plugin-wasm without the heavy
# wasmtime runtime via the workspace dep's default-features = false). The `s3`
# feature is enabled so the binary can honor an `object_store: { kind: s3 }`
# config (the bundled configs/sigil.yaml points at the MinIO service).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release -p sigil-cli --features s3 && \
    cp target/release/sigil /usr/local/bin/sigil

# ---- runtime ------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates: outbound TLS for the webhook alert sink (rustls).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home sigil

COPY --from=builder /usr/local/bin/sigil /usr/local/bin/sigil
COPY configs /opt/sigil/configs
RUN mkdir -p /opt/sigil/data && chown -R sigil:sigil /opt/sigil

USER sigil
WORKDIR /opt/sigil

# 8080 = query API / UI · 5514 = syslog (udp + tcp)
EXPOSE 8080 5514/udp 5514/tcp

# Paths are relative to WORKDIR so `configs/rules` and `./data` resolve.
ENTRYPOINT ["sigil"]
CMD ["run", "--config", "configs/sigil.yaml", "--api-addr", "0.0.0.0:8080"]
