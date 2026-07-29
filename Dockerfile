FROM node:24.4.1-bookworm-slim AS web-builder
WORKDIR /src
COPY ui/package.json ui/package-lock.json ui/
RUN --mount=type=cache,id=aegisproxy-npm,target=/root/.npm \
    cd ui && npm ci
COPY ui ui
COPY config/schema/admin-openapi.yaml config/schema/admin-openapi.yaml
RUN cd ui \
    && cp src/generated/api.ts /tmp/api.ts \
    && npm run generate \
    && cmp /tmp/api.ts src/generated/api.ts \
    && npm run typecheck \
    && npm exec vite build

FROM rust:1.97-bookworm AS builder
WORKDIR /src
RUN apt-get update \
    && apt-get install --no-install-recommends -y cmake \
    && rm -rf /var/lib/apt/lists/*
COPY . .
COPY --from=web-builder /src/ui/dist ui/dist
RUN --mount=type=cache,id=aegisproxy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=aegisproxy-target,target=/src/target \
    cargo build --locked --release --bin rust-proxy --features web-ui \
    && cp target/release/rust-proxy /tmp/rust-proxy

FROM builder AS test
RUN --mount=type=cache,id=aegisproxy-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=aegisproxy-target,target=/src/target \
    cargo test --locked --workspace --all-features

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -o 65532 -g 65532 /var/lib/aegisproxy
COPY --from=builder /tmp/rust-proxy /usr/local/bin/rust-proxy
USER 65532:65532
WORKDIR /var/lib/aegisproxy
ENTRYPOINT ["/usr/local/bin/rust-proxy"]
CMD ["run", "--config", "/etc/aegisproxy/config.toml"]
