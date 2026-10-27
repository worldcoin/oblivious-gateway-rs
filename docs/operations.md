# Operating the gateway

## Configuration

Start with the [commented TOML example](../config/gateway.example.toml).
Configuration is loaded once at startup; changes require a restart.
Invalid configuration fails startup with a structured error and nonzero exit.

| Section | Settings |
|---|---|
| `[server]` | Listen address and shutdown grace period |
| `[server.tls]` | Optional certificate and private-key files |
| `[metrics]` | Optional separate Prometheus listener |
| `[forwarding]` | Target allowlist and scheme/host rewrites |
| `[[generations]]` | Seeds, key IDs and advertisement settings |

Use `--config <path>` or `OBLIVIOUS_GATEWAY_CONFIG` to select the file.
An allowlist is required unless `--allow-any-target` or
`OBLIVIOUS_GATEWAY_ALLOW_ANY_TARGET=true` is set. Unrestricted forwarding
is intended for development only. Command-line flags override environment
settings. Logging uses `RUST_LOG`, defaulting to `info`.

## Keys

Each generation derives one X25519 key and one X-Wing key. Both use
HKDF-SHA256 and AES-128-GCM.

- `seed`: required hex-encoded material, at least 32 decoded bytes, supplied
  inline, through an environment variable, or from a file. Use a secret
  manager or protected file outside local testing; never commit seeds.
- `x25519.key_id`: required, in the range 0–255.
- `xwing.key_id`: optional; defaults to the X25519 ID + 128, wrapping at 256.
- `advertise`: defaults to `true`. Setting it to `false` hides **both**
  public configs but keeps both keys loaded for decryption.

Key IDs must be unique across all loaded generations and stay stable when
generations are reordered or removed. They are wire labels, not seeds.
Replicas serving the same keys must use identical seeds and IDs; missing
seeds fail startup rather than creating ephemeral keys.

Public configs appear in generation order, X25519 then X-Wing within each
generation. Clients choose which supported entry to use; there is no
per-KEM advertisement switch. `/ohttp-keys` accepts any method and returns
`application/ohttp-keys` with a randomized private cache lifetime of 12–36 hours.

### Rotation

Every replica eligible to receive requests using a new key must load it
**before clients start using it**. Advertisement does not control decryption.

If client adoption is controlled, such as through application releases:

1. Add a generation with an independent seed, unused IDs and `advertise = true`.
   Keep the old generation's seed and IDs, with `advertise = false`.
2. Finish the rollout and verify old and new configs against every replica.
3. Release the new client configs. No further gateway restart is required.

If clients or probes fetch `/ohttp-keys` and immediately adopt new keys,
first load the new generation everywhere with `advertise = false`, leaving
the old advertisement unchanged. After verifying every replica, advertise
the new generation in a second rollout. This prevents requests encrypted
with a new key from reaching replicas that do not yet have it.

Retain old keys until no supported clients need them, accounting for caches,
in-flight requests and embedded configs. Do not reuse IDs while clients may
still hold their configs. Rollback pools must retain any keys clients can
use. There is no hot reload or automatic key retirement.

## Forwarding

The allowlist matches the original BHTTP authority, or Host when authority
is absent, including any port. Rewrites apply afterward and replace the
destination scheme/host. The outbound Host comes from the resolved target;
the original client Host is not retained. Hop-by-hop headers and supplied
Host/Content-Length headers are stripped. Request trailers are validated,
then dropped.

The gateway has no replay protection: a resent Encapsulated Request is
forwarded again. Targets with non-idempotent operations must tolerate or
reject duplicates themselves (RFC 9458 §6.5).

An allowed target is trusted to redirect elsewhere: redirect destinations
are not checked against the allowlist. There is no private-address or DNS
rebinding protection. Enforce network-level egress restrictions as needed.

This gateway is not a drop-in replacement for every Go configuration.
Compare public config entries and test encrypted round trips before
switching implementations. See [compatibility details](../GLOSSARY.md#where-we-differ-from-the-go-reference),
including same-seed X-Wing incompatibility and changed rewrite Host behavior.
Legacy X25519+Kyber768Draft00 and Go's `/ohttp-configs`, `/gateway-echo` and
`/gateway-metadata` endpoints are not implemented.

## Limits and errors

Limits are currently fixed, not operator-configurable:

| Limit | Value | Failure response |
|---|---|---|
| Encrypted request, including OHTTP/BHTTP overhead | 2 MiB | Outer 400 |
| Upstream response body | 2 MiB | Encrypted 500 |
| Inbound encrypted-body read | 30 seconds | Outer 400 |
| Upstream connect / total request | 10 / 30 seconds | Encrypted 504 on timeout |

Bodies are buffered, not streamed. Other inbound timeouts use the server
library's defaults.

Invalid content types, unreadable bodies, unknown keys and decryption
failures return plaintext outer 400. The unknown-key status follows RFC 9458
§9.5's recommendation, but the body is not `application/problem+json`.
Methods other than POST on `/gateway` return 405 with `Allow: POST`;
unknown routes return 404.

After decryption, malformed requests (including inner `Expect: 100-continue`)
return encrypted 400, forbidden targets 403, upstream timeouts 504 and other
upstream failures 500. These retain outer status 200. Failure to encrypt the
response instead returns plaintext outer 400. An outer `Expect: 100-continue`
is handled normally by the HTTP server.

## Monitoring

Prometheus metrics use the `ohttp_gateway_` prefix:

| Suffix | Measures |
|---|---|
| `requests_total` | Requests by route, outcome, outer status, KEM and key ID |
| `request_duration_seconds` | Gateway handler duration |
| `upstream_duration_seconds` | Forwarding duration |
| `target_status_total` | Upstream response status class |
| `in_flight` | Active handlers |
| `keys_loaded_total`, `keys_advertised` | Loaded and advertised key gauges |

Labels are bounded and exclude request content. Alert on failure outcomes
and upstream status classes, not only outer HTTP status. An upstream 5xx
can have gateway outcome `success` because forwarding succeeded. Use an
encrypted end-to-end probe; `/health` checks liveness only.

Histogram samples are folded into their buckets every 5 s, so gateway memory
stays bounded when scrapes are infrequent or stop entirely.

Logs are JSON on stdout. `RUST_LOG=info,oblivious_gateway=debug` enables a
completion entry per handled gateway request, including rejections, with
outcome, duration, outer status and inner method/status when available.
Timing ends when the handler produces its response; cancelled handlers
without a response do not emit a completion entry.

The logged `target_host` is the matching configured allowlist entry before
rewrites/redirects. It is omitted for unlisted hosts and unrestricted
forwarding. Paths, queries, headers, bodies and seeds are not logged;
nonstandard methods become `OTHER`. Debug logs can be high-volume.
Debug and trace output from the `ohttp` crate is always suppressed because
it includes response encryption keys.
There is no OpenTelemetry span instrumentation or distributed trace export.

## Docker

Prepare `config/gateway.toml` and export `OBLIVIOUS_GATEWAY_SEED` as in the
[quickstart](../README.md#quickstart). To publish the metrics port, set
`metrics.listen_addr = "0.0.0.0:9090"`; container loopback cannot be reached
through a published port. Bind the host ports to loopback for local use:

```sh
docker build -t oblivious-gateway .
docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 \
  -e OBLIVIOUS_GATEWAY_SEED \
  -v "$(pwd)/config/gateway.toml:/etc/oblivious-gateway/gateway.toml:ro" \
  oblivious-gateway
```

The image uses a nonroot distroless runtime. Mounted configuration, seed and
TLS files must be readable by that user. For remote access, configure host
bindings, TLS or a TLS-terminating proxy, and network policies explicitly.
The metrics listener has no authentication; do not expose it publicly.
