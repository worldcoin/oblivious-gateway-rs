# oblivious-gateway-rs

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

> ⚠️ **Active development. Not ready for production use.** ⚠️

A standalone Rust [RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html)
Oblivious HTTP (OHTTP) gateway: decapsulates an encrypted OHTTP request,
translates the enclosed [Binary HTTP](https://www.rfc-editor.org/rfc/rfc9292.html)
message to an ordinary HTTP request, forwards it to an allowlisted target,
and encapsulates the response.

Independent implementation; see `NOTICE` for its relationship to
Cloudflare's [`privacy-gateway-server-go`](https://github.com/cloudflare/privacy-gateway-server-go)
and [`GLOSSARY.md`](GLOSSARY.md) for terminology. Not published, deployed,
or load-tested.

## Quickstart

```sh
cp config/gateway.example.toml config/gateway.toml
export OBLIVIOUS_GATEWAY_SEED=$(openssl rand -hex 32)
cargo run -- --config config/gateway.toml
```

`forwarding.allowed_targets` must be non-empty unless you pass
`--allow-any-target` (development only; logs a startup warning).

Both flags can also be set from the environment:
`OBLIVIOUS_GATEWAY_CONFIG=<path>` and
`OBLIVIOUS_GATEWAY_ALLOW_ANY_TARGET=true`. A command-line flag takes
precedence over its environment variable.

## Endpoints

| Path | Method | Behavior |
|---|---|---|
| `/gateway` | `POST` | Decrypt → forward → re-encrypt. Requires `Content-Type: message/ohttp-req`. |
| `/ohttp-keys` | any | `application/ohttp-keys` list of advertised key configs. |
| `/health` | `GET` | Liveness only; does not poll backends. |
| `/metrics` (separate listener) | `GET` | Prometheus scrape endpoint. |

Unknown routes → 404. Pre-decryption failures are plaintext outer 400s
(RFC 9458 §9.5's `ohttp-key` problem type — not the Go reference's 401 for
an unknown key). Post-decryption failures (malformed request 400,
forbidden target 403, upstream failure 500) are inside the encrypted
response with the outer status held at 200.

## Configuration

See [`config/gateway.example.toml`](config/gateway.example.toml) for a
fully commented example: `[server]` (listen address, optional
`[server.tls]` for HTTPS), `[metrics]` (optional), `[forwarding]`
(`allowed_targets`, optional `rewrites`), and one or more `[[generations]]`.

Each `[[generations]]` entry is one operator-provided secret **seed**
(inline hex, env var, or file — required, ≥32 bytes), plus optional
`x25519`/`xwing` **key ID** overrides (`{ key_id = N }`, 0–255, unique
across every generation). The seed determines the actual cryptographic
keys: it derives one X25519 key and one X-Wing key (see `GLOSSARY.md` for
the exact transform). The key IDs are unrelated to the seed and to each
other beyond needing to be unique — they're RFC 9458 wire labels used to
select which key a request was encrypted against, not derived from the
seed itself.

Every generation requires an explicit `x25519.key_id`, including the first.
`xwing.key_id` defaults to the X25519 ID + 128, wrapping, and can be
overridden. IDs remain stable when generations are reordered or removed;
duplicate IDs are rejected at startup. `advertise` defaults to `true`;
set it to `false` to retain a generation for decryption only.

Every generation's seed is **required**; there is no auto-generated
fallback if it's missing — startup fails fast instead (`missing field
'seed'`, non-zero exit). This is a deliberate departure from the Go
reference, which silently generates a random ephemeral seed when unset;
that's a footgun in any multi-replica deployment, since each replica would
then get a *different* key and the fleet's advertised public key (and
which key decrypts which client's traffic) would depend on which replica
handled the request.

Loaded once at startup, no hot reload; invalid config fails fast with a
structured log and non-zero exit. **Rotation runbook**: add a new
generation (`advertise = true`) with a *new*, independently generated
seed — never derived from an existing generation's seed — restart; once
clients have adopted it, set the old one's `advertise = false`, restart
(it still decrypts); once safe, delete it and restart. No automatic
retirement.

## Observability

Prometheus via the `metrics` facade, bounded labels only (route, outcome,
KEM, key ID, status class — never URLs/headers/bodies/seeds):
`ohttp_gateway_requests_total`, `_request_duration_seconds`,
`_upstream_duration_seconds`, `_target_status_total`, `_in_flight`,
`_keys_loaded_total`, `_keys_advertised`. Structured JSON logs to stdout
(`RUST_LOG`, default `info`).

Enable `RUST_LOG=info,oblivious_gateway=debug` for one `gateway request completed`
entry per handled `/gateway` request, including rejections. Fields include
`target`, inner `method`/`inner_status` when available, `outer_status`,
`duration_ms` and `outcome`. Timing ends when the handler produces the response,
not when the client receives it. Cancelled handlers without a response do not
emit a completion entry. Inner status includes gateway-generated encrypted errors;
`success` means forwarding succeeded, not necessarily an inner 2xx status.

Target names are opt-in and refer to the original destination, before rewrites
or redirects:

```toml
[forwarding.target_labels]
"indexer.example" = "indexer"
"recovery.example" = "recovery"
```

Unmapped targets omit the field. Labels do not grant allowlist access. Use only
non-sensitive names: logs never copy request authorities, paths, queries, headers
or bodies. Non-standard methods are logged as `OTHER`. These fields are not added
to metrics. Debug logging is per-request and can generate substantial volume.

## Building, testing, Docker

```sh
cargo build --locked && cargo test --locked
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
cargo deny check licenses && cargo deny check bans sources && cargo deny check advisories

docker build -t oblivious-gateway .
docker run --rm -p 8080:8080 -p 9090:9090 \
  -e OBLIVIOUS_GATEWAY_SEED=<hex seed> \
  -v "$(pwd)/config/gateway.toml:/etc/oblivious-gateway/gateway.toml:ro" \
  oblivious-gateway
```

Tests use only local fixtures (`tests/fixtures/tls/`) and in-process
targets — no live external services. Covers: the Go-compatible X25519
fixture, config validation, full X25519/X-Wing round trips, allowlist/
redirect/rewrite behavior, decrypt-only generations, telemetry, and
TLS accept. Docker image: Debian builder (for `aws-lc-rs`) →
`distroless/cc` nonroot runtime.

## CI and releases

`.github/workflows/ci.yml` runs fmt/clippy, build/test, `cargo deny`
(licenses/bans/sources hard-gated, advisories soft-gated since a new
RUSTSEC entry with no fix yet shouldn't block unrelated PRs), and a
Docker build-and-health-check, all on our self-hosted runners.
`validate-pr.yml` enforces conventional-commit PR titles.

This repo is private and does not publish to GHCR or any public
registry. `ecr-release.yaml` publishes to our own private ECR
(`oblivious-gateway-rs`, `eu-central-1`) on a published GitHub Release
tagged `vX.Y.Z`, via the shared `worldcoin/gh-actions/ecr-build-and-push`
action (same pattern as `world-chain-rundler`).

## Known limitations

- **Body size**: axum's `Bytes` extractor caps requests at 2 MiB.
- **Outbound timeouts**: hardcoded 10s connect / 30s request timeout
  (`src/forward.rs`) — a deliberate departure from "use library defaults"
  to avoid unbounded resource exhaustion. Not yet operator-configurable.
  Inbound, a client gets 30s to send the Encapsulated Request body
  (`src/gateway.rs`); other inbound timeouts are the server library's
  defaults.
- **Redirects trusted**: allowlist checked only on the initial
  destination (deliberate — see `GLOSSARY.md`); an allowed target can
  redirect anywhere, including internal addresses.
- **No SSRF protection on the initial hostname**: exact string match only
  — an allowlisted hostname resolving to a private/link-local/metadata
  address (now, or via DNS rebinding) is not blocked. Same gap as the Go
  reference; not in accepted v0 scope, so not closed here.
- **No hot reload / scheduled rotation** — restart-based only, by design.
- **No performance/throughput target** — deferred at design time.
- **Advisory scanning is soft-gated** — `cargo deny check advisories` runs
  in CI but `continue-on-error`, so a new RUSTSEC entry is visible but
  doesn't block merges (licenses/bans/sources are hard-gated).

## License

BSD-3-Clause. See `LICENSE` and `NOTICE`
