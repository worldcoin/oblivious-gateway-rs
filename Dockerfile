# syntax=docker/dockerfile:1

# Build stage: aws-lc-rs (via rustls) needs cmake and a C/C++ toolchain to
# build its bundled BoringSSL; the base Rust image on Debian bookworm keeps
# glibc compatible with the distroless runtime image below.
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  clang \
  pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

COPY --from=builder /build/target/release/oblivious-gateway /usr/local/bin/oblivious-gateway

EXPOSE 8080
# Default config path via env rather than CMD, so it can be overridden with
# -e and extra flags passed to `docker run` don't drop it.
ENV OBLIVIOUS_GATEWAY_CONFIG=/etc/oblivious-gateway/gateway.toml
ENTRYPOINT ["/usr/local/bin/oblivious-gateway"]
