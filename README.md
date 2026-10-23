# oblivious-gateway-rs

A standalone Rust [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
gateway with X25519 and X-Wing support. Decrypts requests, forwards them to
allowlisted HTTP targets, and encrypts the responses.

> Active development. Not ready for production use.

## Quickstart

Requires Rust, a C/C++ toolchain and CMake. For containers, see
[Docker setup](docs/operations.md#docker).

```sh
cp config/gateway.example.toml config/gateway.toml
# Set forwarding.allowed_targets and any rewrites in gateway.toml.
export OBLIVIOUS_GATEWAY_SEED=$(openssl rand -hex 32)
cargo run --locked -- --config config/gateway.toml
```

This creates new keys. Preserve the seed securely for subsequent starts;
changing it invalidates existing client configs. Replicas serving the same
keys need identical seeds and key IDs.

## Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /gateway` | OHTTP requests (`Content-Type: message/ohttp-req`) |
| `/ohttp-keys` | Advertised public key configurations |
| `GET /health` | Process liveness, not backend readiness |
| `GET /metrics` | Prometheus metrics on a separate, optional listener |

Forwarding errors are encrypted inside an outer HTTP 200 response. Check
the decrypted status or gateway metrics, not just the outer status.

## Documentation

- [Configuration example](config/gateway.example.toml)
- [Operations](docs/operations.md) — keys, rotation, forwarding, limits and monitoring
- [Development](docs/development.md) — builds, tests, benchmarks and maintainer releases
- [Glossary and compatibility](GLOSSARY.md) — protocol terms and Go implementation differences

## License

[BSD-3-Clause](LICENSE). Independent implementation; see [NOTICE](NOTICE).
