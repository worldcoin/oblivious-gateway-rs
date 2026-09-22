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

## Where we knowingly diverge

- **Unknown key ID → HTTP 400**, not the Go reference's 401. RFC 9458
  §9.5 registers the `ohttp-key` problem type with "Recommended HTTP
  Status Code: 400", and its own example (§5.3, Figure 7) is a literal
  `400 Bad Request`.
- **X25519 derivation uses the master seed with its final byte XORed
  `0xff`**; X-Wing uses the seed unmodified. Not an RFC requirement — it
  reproduces the Go reference's legacy derivation input byte-for-byte
  (verified against a fixture captured from the vendored Go module), so
  an operator reusing a seed keeps the same public key for clients that
  embed or cache it.
- **The allowlist is checked once, against the initial target only.**
  Redirects are followed via the HTTP client's own default policy without
  re-checking. An allowed target is trusted to choose where it redirects,
  including internal addresses — deliberate, matching the Go reference,
  not an oversight. RFC 9458 §6.10 separately recommends exactly this kind
  of target allowlist, though it says nothing about redirects.

Source: <https://www.rfc-editor.org/rfc/rfc9458.html>
