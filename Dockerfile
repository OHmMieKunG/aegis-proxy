FROM rust:1.97-bookworm AS builder
WORKDIR /src
RUN apt-get update \
    && apt-get install --no-install-recommends -y cmake \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --bin rust-proxy \
    && cp target/release/rust-proxy /tmp/rust-proxy

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
