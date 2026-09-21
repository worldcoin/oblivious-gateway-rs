# oblivious-gateway-rs

A standalone Rust implementation of an [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)
Oblivious HTTP (OHTTP) gateway. It decapsulates encrypted OHTTP requests,
translates the enclosed Binary HTTP ([RFC 9292](https://www.rfc-editor.org/rfc/rfc9292.html))
message to an ordinary HTTP request, forwards it to an allowlisted target,
and encapsulates the response.

This project is an independent implementation, functionally modeled on
Cloudflare's [`privacy-gateway-server-go`](https://github.com/cloudflare/privacy-gateway-server-go)
(BSD-3-Clause; see `NOTICE`), with a deliberately compatible X25519 key
derivation so operators who reuse the same seed keep the same public key.
See `docs/DESIGN.md` for the full accepted scope and design record.

## Status

Implemented per the approved v0 design on the `kempy/v0-gateway` branch.
Not published, deployed, or load-tested; see [Known limitations](#known-limitations--effective-defaults).

## Features

- X25519 and X-Wing key encapsulation (HKDF-SHA256 + AES-128-GCM), derived
  from operator-provided master seeds at startup.
- Multiple overlapping key generations: every loaded generation can
  decrypt; only generations marked `advertise = true` appear in
  `/ohttp-keys`, supporting load-old-and-new-then-retire rotation.
- Go-compatible X25519 derivation (final seed byte XORed with `0xff`
  before derivation; see `docs/adr/0001-preserve-x25519-seed-derivation.md`),
  verified against a fixture captured from the vendored Go reference.
- TOML startup configuration; seeds may come from inline hex (testing
  only), an environment variable, or a mounted file.
- Fail-closed target allowlisting, checked once against the initial
  destination; redirects are followed via the HTTP client's own
  default, finite redirect policy (see
  `docs/adr/0002-trust-allowed-targets-to-redirect.md`).
- Optional target scheme/host rewrites.
- Optional incoming HTTPS and direct mTLS (client-certificate
  verification), via `rustls`. Outgoing HTTPS uses ordinary certificate
  validation.
- Prometheus metrics (via the `metrics` facade) on a separate,
  independently configurable listener.
- Graceful shutdown: stops accepting new connections and drains
  in-flight requests within a configurable grace period.

## Quickstart

```sh
cp config/gateway.example.toml config/gateway.toml
export OBLIVIOUS_GATEWAY_SEED_GEN0=$(openssl rand -hex 32)
cargo run -- --config config/gateway.toml
```

By default the gateway requires `forwarding.allowed_targets` to be
non-empty. To run without any target restriction (development only), pass
`--allow-any-target`; the process logs a startup warning when this is set.

## Endpoints

| Path (configurable) | Method | Behavior |
|---|---|---|
| `/gateway` | `POST` | Decrypts an OHTTP request, forwards the inner request, returns an encrypted OHTTP response. Requires `Content-Type: message/ohttp-req`. |
| `/ohttp-keys` | any | RFC 9458 `application/ohttp-keys` list of currently *advertised* public key configurations, in configuration order (X25519 then X-Wing per generation). Randomized 12–36h private `Cache-Control`. |
| `/health` | any | Unconditional liveness once startup validation and key loading succeed. Does not poll backends. |
| `/metrics` (separate listener) | `GET` | Prometheus scrape endpoint. |

Unknown routes return 404. `/gateway` errors before decapsulation succeeds
(bad content type, unreadable body, unknown key ID, decapsulation/
encapsulation failure) are plaintext outer HTTP errors (400 or 401 for an
unknown key). Errors after successful decapsulation — malformed inner
request (400), forbidden target (403), upstream failure (500) — are
returned *inside* the encrypted response, with the outer HTTP status held
at 200, matching the Go reference's error model.

## Configuration

See `config/gateway.example.toml` for a fully commented example. Key
sections:

- `[server]`: listen address, endpoint paths, shutdown grace period, and
  an optional `[server.tls]` block (`cert_file`, `key_file`, and an
  optional `client_ca_file` to require mTLS).
- `[metrics]`: optional; omit to disable Prometheus metrics entirely.
- `[forwarding]`: `allowed_targets` (exact `host[:port]`, matched against
  the inner request's Host) and optional `[forwarding.rewrites]`.
- `[[generations]]`: one or more key generations, each with
  `x25519_key_id`, `xwing_key_id` (must be globally unique, 0–255), an
  `advertise` flag (default `true`), and a `seed` source
  (`{ hex = "..." }`, `{ env = "VAR_NAME" }`, or `{ file = "/path" }`).
  Seeds must be at least 32 bytes of hex-decoded entropy.

Configuration is loaded once at startup; there is no hot reload. All
startup-time problems (duplicate key IDs, empty generation list, missing
or short seeds, colliding endpoint paths, missing TLS files) fail fast
with a structured log message and a non-zero exit code before the process
starts serving traffic.

### Key rotation runbook

1. Add a new `[[generations]]` entry with `advertise = true` and a new
   seed, keeping the existing generation(s) loaded. Restart.
2. Once clients have adopted the new generation (via `/ohttp-keys` or an
   embedded-client release), set the old generation's `advertise = false`
   and restart; it still decrypts existing traffic.
3. Once the operator is confident no client still needs the old
   generation, remove it from the configuration and restart. There is no
   automatic retirement or identifier reuse; both are operator decisions.

## Observability

Metrics (Prometheus, low-cardinality labels only — no URLs, headers,
bodies, seeds, or client identifiers):

- `ohttp_gateway_requests_total{route,outcome,outer_status,kem}` (counter)
- `ohttp_gateway_request_duration_seconds{route,outcome,kem}` (histogram)
- `ohttp_gateway_upstream_duration_seconds{outcome}` (histogram)
- `ohttp_gateway_target_status_total{status_class}` (counter; the
  encrypted target's status class, tracked separately from the outer
  HTTP status)
- `ohttp_gateway_in_flight{route}` (gauge)
- `ohttp_gateway_keys_loaded_total` / `ohttp_gateway_keys_advertised{kem}`
  (gauges)

Logs are structured (JSON via `tracing-subscriber`) to stdout. Control
verbosity with `RUST_LOG` (defaults to `info`).

## Building, testing, linting

```sh
cargo build --locked
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

The test suite (`cargo test`) covers: the Go-compatible X25519 derivation
fixture (`src/keys.rs`), startup configuration validation, full encrypted
`/gateway` round trips for both X25519 and X-Wing against a local target,
allowlist/forbidden-target/redirect/rewrite behavior, overlapping
decrypt-only generations, malformed-payload handling, Prometheus telemetry
accounting, and TLS/mTLS accept/reject behavior against locally generated
test-only certificates under `tests/fixtures/tls/`. All tests run against
local fixtures; none depend on live external services.

## Docker

```sh
docker build -t oblivious-gateway .
docker run --rm -p 8080:8080 -p 9090:9090 \
  -e OBLIVIOUS_GATEWAY_SEED_GEN0=<hex seed> \
  -v "$(pwd)/config/gateway.toml:/etc/oblivious-gateway/gateway.toml:ro" \
  oblivious-gateway
```

The image is a multi-stage build: a Debian-based builder stage (needed for
`aws-lc-rs`'s bundled BoringSSL, which requires `cmake` and a C toolchain)
producing a stripped release binary, copied into a `distroless/cc`
nonroot runtime image with no shell.

## Known limitations / effective defaults

Per the approved v0 scope, several behaviors intentionally use library
defaults rather than custom configuration; they were inspected rather than
assumed to match the Go reference:

- **Request body size**: axum's `Bytes` extractor (used for the OHTTP
  request body) enforces its documented default 2 MiB limit; this is not
  configurable in v0. The Go reference has no body-size cap at all, so
  this is a stricter default, not a looser one.
- **Timeouts**: the outbound `reqwest::Client` uses no default connect or
  overall request timeout, and the inbound `axum`/`axum-server` listener
  has no default read/write timeout — matching the Go reference's
  `http.Client{}` / `http.ListenAndServe`, which also have none. Custom
  timeout configuration is deferred to a follow-up.
- **Redirects**: `reqwest`'s default redirect policy is a limit of 10
  hops (verified against its 0.13.5 source), not Go's default client
  behavior exactly, but both are finite. The allowlist is checked only
  against the initial destination (ADR 0002); an allowed target that
  redirects can reach any destination it chooses, including internal
  addresses. Operators should only allowlist targets they trust to
  behave this way.
- **No hot reload or scheduled rotation**: configuration and keys load
  once at startup; rotation is a manual, restart-based runbook (above).
- **No SSRF/DNS/address-family policy**: exact host allowlisting does not
  prevent an allowed hostname resolving to a private or link-local
  address, matching the Go reference's posture; this is unchanged v0
  scope, not a regression.
- **No numerical performance/throughput acceptance criteria**: deferred at
  the design stage; only "avoid unnecessary serialization" was targeted,
  not benchmarked.
- **No automated dependency license/vulnerability scanning in CI**: the
  full dependency license set was reviewed manually once (recorded in
  `NOTICE`); it is not re-checked automatically on every change. Adding
  `cargo deny` or `cargo audit` to CI is a reasonable follow-up.
- **No response body size cap on the outbound (target) side**: `reqwest`
  reads the full target response into memory before re-encoding it as
  BHTTP; there is no explicit response-size limit in v0, matching the Go
  reference.

## License

BSD-3-Clause. See `LICENSE` and `NOTICE` (the latter records the
functional relationship to the Go reference implementation and the
dependency license review).
