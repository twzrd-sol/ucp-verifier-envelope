# algovoi-provenance conformance vectors

ML-DSA-65 (RFC 9964) JWS conformance vectors for the `com.algovoi.decision_provenance`
UCP Signal. Seven deterministic vectors covering the full two-layer verification model
defined in the envelope spec.

**Python, not npm.** Both existing profiles use `.mjs` generators; this one uses Python.

## Reproduce

```
pip install pqcrypto==0.3.4 cryptography rfc8785
python gen_vectors.py   # regenerates vectors/test-jwks.json and vectors/vectors.json
python verify.py        # verifies all 7 vectors; exits non-zero on any mismatch
```

Keys and signatures differ on each run (ML-DSA sign is randomised). The fixed epoch
makes payload bytes reproducible; outcomes are stable regardless.

## Algorithm

- **Signature alg:** `ML-DSA-65` — JOSE `alg` registered by RFC 9964; FIPS 204 parameter set 65.
- **JWS serialisation:** RFC 7515 compact (`header.payload.signature`).
- **Public key JWK:** RFC 9964 AKP form — `{"kty":"AKP","alg":"ML-DSA-65","pub":<b64url>}`.
- **Canonicalisation:** RFC 8785 (JCS) applied to the payload before base64url encoding.

## Signing-input rule

```
header_b64  = BASE64URL_NOPAD(utf8(header_json))
payload_b64 = BASE64URL_NOPAD(JCS(payload_json))      # RFC 8785
signing_input = ASCII(header_b64 + "." + payload_b64)
signature     = ML-DSA-65.sign(sk, signing_input)
compact_jws   = header_b64 + "." + payload_b64 + "." + BASE64URL_NOPAD(signature)
```

This is the same construction used by the production issuer for the classical halves
of its Ed25519 profiles, so the two stacks already interoperate on signing input before
any JOSE library ships AKP.

## Two-layer verification model

The **verifier** owns authenticity: is the signature genuine? The **consumer** owns scope:
is this credential about the transaction in hand?

Expired and wrong-session vectors carry intact signatures that the verifier accepts.
The consumer then rejects on scope. Collapsing scope into the verifier would silently
skip the consumer's own check for anyone verifying out of band.

## Hybrid key binding (vectors 6 and 7)

Hybrid vectors include a `cnf` claim (RFC 7800) inside the PQC-signed payload:

```json
{ "cnf": { "jkt": "<RFC 7638 JWK thumbprint of the Ed25519 public key>" } }
```

This binds the Ed25519 key inside material that can only be modified with the ML-DSA
private key. Without this binding the classical co-signature field is substitutable:
an attacker can replace `ed25519_pub` with their own key, produce a valid classical
co-signature, and only the ML-DSA half guards the claim. With `cnf.jkt`, swapping the
classical key requires a PQC re-sign.

`verify.py` enforces this: for any hybrid vector, authentication requires
(a) ML-DSA verify AND (b) `ed25519_pub` JWK thumbprint matches `cnf.jkt` AND
(c) Ed25519 co-signature verifies over the signing input.

## Vectors

| vector | what it tests | verifier | consumer | overall |
|---|---|---|---|---|
| valid | authentic sig, session matches, not expired | authentic | accept | accept |
| expired | authentic sig, exp in the past | authentic | reject (scope) | reject |
| wrong-session | authentic sig, session mismatch | authentic | reject (scope) | reject |
| rotated-key | kid absent from JWKS | reject | — | reject |
| bad-signature | bit-flip in decoded sig bytes | reject | — | reject |
| hybrid-classical-valid-pqc-invalid | Ed25519+cnf OK, ML-DSA corrupted | reject | — | reject |
| hybrid-substituted-classical-pqc-invalid | attacker's Ed25519, cnf.jkt mismatch, ML-DSA corrupted | reject | — | reject |

**bad-signature:** bit flipped in *decoded* signature bytes, not a base64 character.
In a no-pad tail, editing a base64 character can be a silent no-op due to the restricted
final-char alphabet; editing the decoded byte is unambiguous.

**hybrid vector 6** catches a verifier that silently falls back to the classical half when
ML-DSA fails. **hybrid vector 7** catches a verifier that falls back to Ed25519 without
checking the `cnf.jkt` binding. Together they test the full hybrid-fallback threat surface.

## Pre-interoperability status

Verification uses `pqcrypto.sign.ml_dsa_65.verify`, not a stock JOSE library. No
mainstream JOSE stack (including jwcrypto) ships AKP/ML-DSA support yet. This pack
graduates to interoperability the day a published third-party JOSE library verifies
these vectors cold without the pqcrypto primitive.

The Ed25519 half of the hybrid vectors verifies via PyCA `cryptography` — a mainstream
library. The classical half is fully stock-library verified today.

## Key sizes

| item | size |
|---|---|
| ML-DSA-65 public key | 1952 bytes |
| ML-DSA-65 signature | 3309 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |

## Caveats

- **Private-key format:** RFC 9964 AKP `priv` carries the 32-byte ML-DSA seed.
  `pqcrypto.generate_keypair()` returns the 4032-byte expanded secret key, not the seed,
  so no spec-faithful `priv` member is emitted. Only public JWKs are published.
- Keys are freshly generated per run. The fixed epoch (`NOW = 1_753_600_000`) makes
  payload bytes reproducible, but keys and signatures differ each run. Outcomes are stable.
- `kid` is an RFC 7638-style SHA-256 thumbprint over `{alg,kty,pub}` — a reasonable
  convention, not mandated by RFC 9964.
