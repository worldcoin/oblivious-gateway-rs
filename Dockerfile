# syntax=docker/dockerfile:1

# Build stage: aws-lc-rs (via rustls) needs cmake and a C/C++ toolchain to
# build its bundled BoringSSL; the base Rust image on Debian bookworm keeps
# glibc compatible with the distroless runtime image below.
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  clang \
  pkg-config \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked && \
  strip target/release/oblivious-gateway

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/oblivious-gateway /usr/local/bin/oblivious-gateway

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/oblivious-gateway"]
CMD ["--config", "/etc/oblivious-gateway/gateway.toml"]
