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
and [`GLOSSARY.md`](GLOSSARY.md) for terminology. Local load testing does
not establish production readiness or capacity for a particular deployment.

## Quickstart

```sh
cp config/gateway.example.toml config/gateway.toml
# Edit forwarding.allowed_targets and any rewrites for your target services.
export OBLIVIOUS_GATEWAY_SEED=$(openssl rand -hex 32)
cargo run --locked -- --config config/gateway.toml
```

This creates a new installation. Keep its seed in a secret manager or a
protected file for subsequent starts; generating a different seed changes
the public keys and invalidates existing client configurations. Never
commit a seed to source control. Each replica serving the same keys needs
the same seeds and key IDs.

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

Unknown routes → 404; methods other than POST on `/gateway` → 405 with
`Allow: POST`. Invalid content types, unreadable/oversized request bodies,
unknown keys and decryption failures → plaintext outer 400. Unknown-key
status follows RFC 9458 §9.5's recommendation; the body is plain text,
not an `application/problem+json` document.

After decryption, malformed requests (including an inner `Expect:
100-continue`) return encrypted 400, forbidden targets 403, upstream
timeouts 504, and other upstream failures 500. These responses retain outer
status 200. If response encryption itself fails, the gateway returns a
plaintext outer 400 instead.

## Configuration

See [`config/gateway.example.toml`](config/gateway.example.toml) for a
fully commented example: `[server]` (listen address, optional
`[server.tls]` for HTTPS), `[metrics]` (optional), `[forwarding]`
(`allowed_targets`, optional `rewrites`), and one or more `[[generations]]`.

Each `[[generations]]` entry is one operator-provided secret **seed**
(hex-encoded inline, in an env var, or in a file — required, ≥32 decoded
bytes), a required `x25519.key_id`, and an optional `xwing.key_id`
(`{ key_id = N }`, 0–255, unique across every generation).
The seed determines the actual cryptographic keys: it derives one X25519
key and one X-Wing key (see `GLOSSARY.md` for the exact transform).
The key IDs are unrelated to the seed and to each other beyond needing
to be unique — they're RFC 9458 wire labels used to
select which key a request was encrypted against, not derived from the
seed itself.

Every generation requires an explicit `x25519.key_id`, including the first.
`xwing.key_id` defaults to the X25519 ID + 128, wrapping, and can be
overridden. IDs remain stable when generations are reordered or removed;
duplicate IDs are rejected at startup. `advertise` defaults to `true`;
set it to `false` to retain a generation for decryption only. It applies
to both KEMs; there is no per-KEM advertisement switch. Advertised entries
appear in generation order, X25519 then X-Wing within each generation.
Client selection policies vary, so do not assume that advertising both
means clients will prefer X25519. Both use HKDF-SHA256 and AES-128-GCM.

Every generation's seed is **required**; there is no auto-generated
fallback if it's missing — startup fails fast instead (`missing field
'seed'`, non-zero exit). This is a deliberate departure from the Go
reference, which silently generates a random ephemeral seed when unset;
that's a footgun in any multi-replica deployment, since each replica would
then get a *different* key and the fleet's advertised public key (and
which key decrypts which client's traffic) would depend on which replica
handled the request.

Loaded once at startup, no hot reload; invalid config fails fast with a
structured log and non-zero exit.

### Key rotation across replicas

1. Add a generation with a new, independently generated seed and unused
   key IDs. Set `advertise = false` and keep the old generation unchanged.
   Restart **every replica**, including any rollback pool, to load the new
   keys before any replica advertises them.
2. Confirm all replicas can decrypt requests using the new public configs.
   Set the new generation's `advertise = true` and roll out again.
3. Distribute the new public configs through your client configuration
   mechanism. Once appropriate, stop advertising the old generation with
   `advertise = false`, but retain it for decryption.
4. Remove the old generation only when no supported clients need it.
   Account for cached configs, in-flight requests and clients embedding
   configs in application releases. There is no automatic retirement.

Do not reuse retired key IDs while clients may still hold their configs.
After advertising new keys, a rollback must keep those keys loaded too.

### Forwarding and implementation compatibility

The allowlist matches the original BHTTP authority (or Host when authority
is absent), including any port, before rewrites. Rewrites replace the
destination scheme/host. The outbound `Host` comes from that resolved
destination, not the original client header. Verify virtual-host routing
when forwarding to a different hostname. Hop-by-hop headers and
client-supplied `Host`/`Content-Length` are stripped.

This is not a drop-in replacement for every Go gateway configuration.
X25519 derivation matches the Go reference's legacy transform, but
compatibility also requires the same seed, key ID and cipher suite.
Compare the individual encoded public config and test an encrypted round
trip before switching implementations. Same-seed **X-Wing keys are not
compatible** with the Go revision described in the [glossary](GLOSSARY.md#where-we-differ-from-the-go-reference).
Legacy X25519+Kyber768Draft00 and Go's `/ohttp-configs`, `/gateway-echo`
and `/gateway-metadata` endpoints are not implemented.

## Observability

Prometheus via the `metrics` facade, bounded labels only (route, outcome,
KEM, key ID, status class — never URLs/headers/bodies/seeds):
`ohttp_gateway_requests_total`, `_request_duration_seconds`,
`_upstream_duration_seconds`, `_target_status_total`, `_in_flight`,
`_keys_loaded_total`, `_keys_advertised`. Structured JSON logs to stdout
(`RUST_LOG`, default `info`).

Monitor gateway failure outcomes and target status classes, not only outer
HTTP status: encrypted errors can have outer status 200, and a forwarded
upstream 5xx still has gateway outcome `success`. Use an encrypted
end-to-end probe to check forwarding; `/health` only confirms liveness.
The `tracing` crate currently provides logging, not OpenTelemetry spans or
distributed trace export.

Enable `RUST_LOG=info,oblivious_gateway=debug` for one `gateway request completed`
entry per handled `/gateway` request, including rejections. Fields include
`target_host`, inner `method`/`inner_status` when available, `outer_status`,
`duration_ms` and `outcome`. Timing ends when the handler produces the response,
not when the client receives it. Cancelled handlers without a response do not
emit a completion entry. Inner status includes gateway-generated encrypted errors;
`success` means forwarding succeeded, not necessarily an inner 2xx status.

`target_host` is the matching `forwarding.allowed_targets` entry, i.e. the
original destination before rewrites or redirects. It is omitted for requests
whose host isn't allowlisted, and always with `--allow-any-target`, so a
client-supplied host is never logged. Paths, queries, headers and bodies are
never logged. Non-standard methods are logged as `OTHER`. These fields are not
added to metrics. Debug logging is per-request and can generate substantial
volume.

## Building, testing, Docker

Source builds require a Rust toolchain supporting edition 2024 and the
locked dependencies, plus a C/C++ toolchain and CMake for `aws-lc-rs`.
The Dockerfile pins the build toolchain and installs its native build
dependencies. Install `cargo-deny` separately to run the dependency checks.

```sh
cargo build --locked && cargo test --locked
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
cargo deny check licenses && cargo deny check bans sources && cargo deny check advisories
```

For Docker, prepare `config/gateway.toml` and export the seed as in the
quickstart. To scrape metrics through a published container port, change
`metrics.listen_addr` to `"0.0.0.0:9090"` in that config; the example's
loopback binding is only reachable inside the container. The following
publishes both ports on the **host's loopback interface** for local use:

```sh
docker build -t oblivious-gateway .
docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 \
  -e OBLIVIOUS_GATEWAY_SEED \
  -v "$(pwd)/config/gateway.toml:/etc/oblivious-gateway/gateway.toml:ro" \
  oblivious-gateway
```

The nonroot container must be able to read the mounted config and any
seed/TLS files. For remote access, configure the host bindings, TLS or a
TLS-terminating proxy, and firewall/network policies explicitly. Do not
expose the unauthenticated metrics listener publicly.

Tests use only local fixtures (`tests/fixtures/tls/`) and in-process
targets — no live external services. Covers: the Go-compatible X25519
fixture, config validation, full X25519/X-Wing round trips, allowlist/
redirect/rewrite behavior, decrypt-only generations, telemetry, and
TLS accept. Docker image: Debian builder (for `aws-lc-rs`) →
`distroless/cc` nonroot runtime.

## Load testing

The manually dispatched [load-test workflow](.github/workflows/load-test.yml)
runs X25519 and X-Wing against a local nginx target at 1, 10, 100, 1,000
and 10,000 requests/sec. Duration defaults to 30 seconds per rate.
It records a direct-target baseline, probe results and gateway metrics.
The workflow uses the maintainers' runners and published OHTTP probe image;
adapt those dependencies for other environments.

Compare achieved throughput with offered load. All processes share a
runner, and probe latency includes client crypto, gateway and target time.
The probe checks decryption and inner HTTP success, not response-body
correctness. These short, small-response tests are not a maximum-capacity
measurement or a substitute for realistic payloads, TLS/relay paths,
sustained load, overload and rolling-deployment tests.

## Maintainer CI and releases

`.github/workflows/ci.yml` runs fmt/clippy, build/test, `cargo deny`
(licenses/bans/sources hard-gated, advisories soft-gated since a new
RUSTSEC entry with no fix yet shouldn't block unrelated PRs), and a
Docker build-and-health-check, all on our self-hosted runners.
`validate-pr.yml` enforces conventional-commit PR titles.

The publishing workflow is specific to the maintainers' infrastructure;
building or running the gateway does not require AWS or access to it.
[`ecr-release.yaml`](.github/workflows/ecr-release.yaml) publishes a
`linux/amd64` image to private ECR (`oblivious-gateway-rs`, `eu-central-1`)
using the shared `worldcoin/gh-actions/ecr-build-and-push` action. It does
not publish to GHCR or a public registry.

To release:

1. Choose a commit on `main` whose CI checks have passed. The release
   workflow checks main-branch ancestry, but does not itself gate on CI.
2. Publish a GitHub Release with an unused plain semver tag, such as
   `v0.1.0`, targeting that commit. A tag push or an unpublished draft is
   insufficient; suffixes such as `-rc.1` are rejected. For example, using
   the GitHub CLI from this checkout:

   ```sh
   # Set RELEASE_COMMIT to the full SHA of the tested commit on main.
   : "${RELEASE_COMMIT:?Set the tested main commit SHA}"
   gh release create v0.1.0 --target "$RELEASE_COMMIT" \
     --title "v0.1.0" --generate-notes
   ```

3. Wait for **Release private image** to succeed. Its job summary records
   the image URI, digest and source commit. Publishing requires the
   configured runner access and AWS permissions; a GitHub Release alone
   does not prove an image was published. Use a new version rather than
   overwriting an existing published image tag.
4. Deploy the resulting image through your deployment system separately.
   Publishing an image does not update a running gateway or client configs.

## Known limitations

- **Body size**: the handler caps the complete encrypted request at 2 MiB,
  including OHTTP/BHTTP overhead; oversized requests receive outer 400.
  Upstream response bodies are also capped at 2 MiB; exceeding that limit
  produces encrypted 500 with outer status 200. These are buffering limits,
  not streaming support, and are not operator-configurable.
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
- **No guaranteed performance/throughput target** — benchmark your own
  deployment and workload before setting capacity or latency targets.
- **Advisory scanning is soft-gated** — `cargo deny check advisories` runs
  in CI but `continue-on-error`, so a new RUSTSEC entry is visible but
  doesn't block merges (licenses/bans/sources are hard-gated).

## License

BSD-3-Clause. See `LICENSE` and `NOTICE`
