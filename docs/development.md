# Development and releases

## Build and test

Use a Rust toolchain supporting edition 2024 and the locked dependencies,
plus a C/C++ toolchain and CMake for `aws-lc-rs`. The Dockerfile pins its
toolchain and installs native dependencies. Install `cargo-deny` separately
for dependency checks.

```sh
cargo build --locked && cargo test --locked
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
cargo deny check licenses && cargo deny check bans sources && cargo deny check advisories
```

Tests use local targets and TLS fixtures, not external services. Coverage
includes Go-compatible X25519 derivation, both KEMs, config validation,
forwarding, rotation, telemetry and TLS acceptance.

## Load tests

The manual [load-test workflow](../.github/workflows/load-test.yml) runs
X25519 and X-Wing against nginx at 1, 10, 100, 1,000 and 10,000 requests/sec,
defaulting to 30 seconds per rate. Artifacts include a direct-target baseline,
probe results, gateway metrics and environment details. It uses maintainer
runners and a published OHTTP probe image; adapt those for other environments.

Compare achieved throughput with offered load. Processes share a runner;
latency includes client crypto and target time. The probe checks decryption
and inner HTTP success, not body correctness. These short, small-response
tests establish neither maximum capacity nor production readiness. Validate
realistic payloads, TLS/relay paths, sustained load, overload and rolling
deployments separately. No throughput or latency target is guaranteed.

## Maintainer image releases

The [release workflow](../.github/workflows/ecr-release.yaml) is specific to
the maintainers' infrastructure. It publishes `linux/amd64` images to private
ECR (`oblivious-gateway-rs`, `eu-central-1`), not GHCR or a public registry.
Building and running the gateway does not require AWS access.

1. Choose a commit on `main` with passing CI. The release workflow checks
   main-branch ancestry, but does not itself gate on CI.
2. Publish a GitHub Release targeting that commit with an unused plain
   `vX.Y.Z` tag. A tag push or unpublished draft is insufficient; suffixes
   such as `-rc.1` are rejected. For example, from this checkout:

   ```sh
   # Set RELEASE_COMMIT to the full SHA of the tested commit on main.
   : "${RELEASE_COMMIT:?Set the tested main commit SHA}"
   gh release create v0.1.0 --target "$RELEASE_COMMIT" \
     --title "v0.1.0" --generate-notes
   ```

3. Wait for **Release private image** to succeed. Its job summary records
   the image URI, digest and source commit. Runner access and AWS permissions
   are required; creating the release alone does not prove publication.
   Use a new version instead of overwriting an existing image tag.
4. Deploy separately. Publishing an image does not update running gateways
   or client configurations.
