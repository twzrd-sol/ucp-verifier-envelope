# TWZRD seller-observation profile (`xyz.twzrd.seller_observation`)

This directory is a local, dependency-free reference for the proposed
`xyz.twzrd.seller_observation` signal. It contains the draft profile, an issuer
guard, a compact-JWS verifier, deterministic fixture vectors, and tests proving
that a party-conflicted observation never reaches the signer.

It does not contain production key material.

```bash
npm run generate
npm test
```

The generator uses a fixed test-only seed so the six signed and issuer cases
reproduce byte for byte; the two party-refusal vectors (`party-conflicted`,
`party-undetermined`) are committed by hand and are not regenerated. Production credentials are signed with kid `twzrd-publication-ed25519-v1`,
published in the live JWKS at `https://twzrd.xyz/.well-known/jwks.json`. The
private key never enters Git.

## Registry

| field | value |
|---|---|
| signal | `xyz.twzrd.seller_observation` |
| profile | `xyz.twzrd.seller_observation/1` |
| issuer | `https://twzrd.xyz` |
| vectors | `vectors/vectors.json` |
| gate | `npm test` (10 unit tests, then `node verify.mjs` over the 8 committed vectors) |
| publication key | kid `twzrd-publication-ed25519-v1`, public JWK `{"kty":"OKP","crv":"Ed25519","x":"PHBN9pz8WMOnEqyEOjnjUD73tMKShQktNxalQbETrzw","kid":"twzrd-publication-ed25519-v1","use":"sig","alg":"EdDSA"}` (RFC 7638 thumbprint `5M0slkQkQfqwg7jGim06zIR73KcamUIPV8T9jB-3Yaw`) |

TWZRD owns the claim semantics, issuer implementation, party-exclusion rule,
production key lifecycle, and profile source of truth ([profile.md](profile.md)).
