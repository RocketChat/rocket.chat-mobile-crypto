# @rocket.chat/mobile-crypto

A first-party React Native TurboModule that provides the native cryptographic
primitives (SHA, HMAC, PBKDF2, AES, RSA, secure random) the Rocket.Chat mobile
app relies on. It is a published, maintained package — not an abandoned fork
pinned at a commit.

## Language

**Mobile Crypto**:
This library — the native crypto provider consumed by the Rocket.Chat mobile app.
_Avoid_: "the fork", "the pinned lib" (it is first-party and published).

**E2E encryption**:
Rocket.Chat end-to-end message and file encryption — the downstream feature that
consumes Mobile Crypto's primitives. The reason byte-level output compatibility matters.
_Avoid_: "E2E" unqualified (collides with end-to-end *testing*), "encryption" alone.

**Known-answer harness**:
The example app (`example/src/App.tsx`) — exercises every primitive with fixed
`expected:` values for deterministic ops and round-trip checks for randomized ones.
It is the conformance gate that proves a rebuild preserved behavior.
_Avoid_: "the test app", "the demo".

**Byte-compatible**:
Produces output identical to the previously shipped version for deterministic
operations (SHA, HMAC, PBKDF2, AES-CBC with fixed IV). Randomized operations
(RSA-OAEP, RSA-PSS) are validated by round-trip instead, since byte-equality is
not achievable for them.

## Relationships

- **E2E encryption** depends on **Mobile Crypto** producing **byte-compatible** output.
- The **Known-answer harness** verifies **Mobile Crypto** is **byte-compatible** after a rebuild.

## Flagged ambiguities

- "E2E" was ambiguous between end-to-end *encryption* (this project's domain) and
  end-to-end *testing* — resolved: in this repo "E2E" means encryption.
- "fork" (from the originating ticket) implied an abandoned pinned dependency —
  resolved: this is a maintained first-party package.
