# Glossary

[RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html) terms used
throughout this codebase, plus this project's own additions where the RFC
has no name for something the code needs to talk about.

- **Client** — creates an Encapsulated Request, decapsulates its
  Encapsulated Response.
- **Oblivious Relay Resource** — forwards an Encapsulated Request to the
  gateway without decrypting it. Never call the gateway "the relay".
- **Oblivious Gateway Resource** ("the gateway") — decapsulates a request,
  forwards the contained request, encapsulates the response. Narrower than
  "this project": RFC 9458 §3 and §6.10 place key-configuration
  distribution (`/ohttp-keys`) outside it, and health/metrics aren't part
  of the RFC at all.
- **Target Resource** — what the decapsulated request is addressed to.
- **Encapsulated Request / Encapsulated Response** — the HPKE-encrypted
  wire format (`message/ohttp-req` / `message/ohttp-res`).
- **Key Configuration** — one gateway key's public config: KEM, supported
  KDF/AEAD pairs, public key. No secret material.
- **Key Identifier** — the byte selecting which Key Configuration a
  message uses.
- **Key Rotation** — moving from one gateway key to another, with an
  overlap window where both are accepted.

## Project-only terms

Not in RFC 9458:

- **Key Generation** — one X25519 key + one X-Wing key derived from a
  single master seed (`src/keys.rs`).
- **Key Ring** — every loaded key, plus the currently advertised subset
  (`src/keys.rs::KeyRing`).
- **Master Seed** — the secret an operator provides. Never call it a Key
  Configuration — that's public.
- **Outer Request / Outer Response** — the plain HTTP POST/response
  carrying an Encapsulated Request/Response (`src/error.rs::OuterError`).
  RFC 9458 has no name for this layer — it just says "the POST request".
  The plaintext binary HTTP message an Encapsulated Request protects
  *does* have an RFC name (§4.1: "a binary HTTP request message"), so the
  code uses that directly (`src/bhttp.rs::BinaryHttpRequest`) rather than
  inventing an "Inner" counterpart to "Outer" above.

## Where we differ from the Go reference

These comparisons refer to Cloudflare's `privacy-gateway-server-go` v0.0.4 at
[revision d63adf6](https://github.com/cloudflare/privacy-gateway-server-go/tree/d63adf6f333cb2c78fad41dff5b117c7c284645e).
Key derivation and key-ID conventions are implementation choices, not
requirements of RFC 9458. Do not infer full configuration or wire-behavior
parity from the shared protocol.

- **Unknown key ID → HTTP 400**, not the Go reference's 401. RFC 9458
  §9.5 registers the `ohttp-key` problem type with "Recommended HTTP
  Status Code: 400", and its own example (§5.3, Figure 7) is a literal
  `400 Bad Request`.
- **X25519 derivation uses the master seed with its final byte XORed
  `0xff`.** This reproduces the Go reference's legacy X25519 derivation
  input byte-for-byte, verified against a fixture captured from the Go
  module. Existing encoded client configs also require the same key ID
  and cipher suite; preserving the seed alone is not sufficient.
- **X-Wing derivation matches Go too.** The seed's final two bytes are
  XORed `0xff`, and SHAKE256 of the result is the 32-byte X-Wing
  decapsulation key, as in CIRCL. This is not HPKE's labeled
  `DeriveKeyPair`, so X-Wing keys are held and decapsulated in
  `src/xwing.rs` rather than by the `ohttp` crate. Verified against a
  fixture captured from Go v0.0.4. Go's additional X25519+Kyber768Draft00
  KEM is not supported.
- **The allowlist is checked once, against the initial target only.**
  Redirects are followed via the HTTP client's own default policy without
  re-checking. An allowed target is trusted to choose where it redirects,
  including internal addresses. RFC 9458 §6.10 separately recommends exactly this kind
  of target allowlist, though it says nothing about redirects.
- **A Key Generation's seed is required; there's no auto-generated
  fallback.** The Go reference generates a random ephemeral seed at
  startup if none is configured. We fail startup instead (`missing field
  'seed'`) if a `[[generations]]` entry omits one. Go's fallback is a
  footgun for any multi-replica deployment: each replica would derive a
  *different* key from its own random seed, so the fleet's advertised
  public key — and which replica can decrypt which client's traffic —
  would depend on which process happened to serve a given request.
- **Key IDs are explicit per generation, laid out like Go's.** Go derives
  all IDs from one `CONFIGURATION_ID` c: Kyber at c, X25519 at
  `(c - 128) % 255` and X-Wing at `(c - 192) % 255`. Here every generation
  requires `x25519.key_id`; for Go's c use `c + 128` (mod 256), e.g. 128
  for c = 0. `xwing.key_id` defaults to the X25519 ID − 64 (wrapping),
  which equals Go's X-Wing ID for every c except 127 and 191, where Go's
  `% 255` yields 0; set it explicitly there. Kyber's ID c is never served.
  IDs do not depend on generation order; duplicate IDs across all loaded
  keys are rejected at startup.
- **Advertisement order differs.** Go lists X-Wing, Kyber, then X25519.
  Here each advertised generation lists X25519 then X-Wing, in generation
  order. Clients that pick the first or last supported entry therefore
  choose differently between the two servers.
- **Rewrites change the outbound Host.** This gateway uses the resolved
  destination's Host, stripping the client-supplied header. The Go
  reference preserves the original Host when rewriting the destination.
  Backends using virtual-host routing must account for that difference.
- **Request and response limits are explicit.** See the
  [operating limits](docs/operations.md#limits-and-errors) for body limits and
  timeouts that differ from Go's default HTTP client behavior.

Source: <https://www.rfc-editor.org/rfc/rfc9458.html>
