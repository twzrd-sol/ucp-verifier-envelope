# Claim type: seller-observation (`xyz.twzrd.seller_observation`)

Issuer: TWZRD (`https://twzrd.xyz`). Owned and versioned by the issuer per
[GOVERNANCE.md](../../GOVERNANCE.md). The normative profile is
[`twzrd-observation/profile.md`](../../twzrd-observation/profile.md); vectors and
verifier are in [`twzrd-observation/`](../../twzrd-observation/).

## Summary

A checkout-session-scoped observation about a third-party seller: TWZRD admitted
a specific public-listing artifact and evidence bundle, bound by digest. It does
not attest seller identity, merchant authority, delivery, purchase completion,
or permission to spend.

| | |
|---|---|
| signal | `xyz.twzrd.seller_observation` |
| profile | `xyz.twzrd.seller_observation/1` |
| `typ` | `application/twzrd-seller-observation+jwt` |
| alg | EdDSA (Ed25519), RFC 7515 compact JWS |
| payload bytes | RFC 8785 (JCS) canonical JSON |
| pinned JWKS | `https://twzrd.xyz/.well-known/jwks.json` |
| publication kid | `twzrd-publication-ed25519-v1` |
| scope | session (`aud` = checkout session, `sub` = seller) |

## Non-party (issuer constraint, envelope section 8)

> TWZRD issues this signal only for subject transactions it does not operate,
> meter, settle, sponsor, or receive a fee from. Any payment for the TWZRD
> observation is separate from the transaction being assessed.

Enforced at issuance, fail closed: eight issuer roles (`seller_operator`,
`merchant`, `meter`, `facilitator`, `settler`, `sponsor`, `escrow_agent`,
`fee_recipient`) must each be known and false before signing. A true role
refuses with `party_conflict`, an unknown role with `party_status_unknown`;
both refuse before the signer is invoked.

## Conformance

`cd twzrd-observation && npm test`: 10 unit tests, then `node verify.mjs` over
the 8 committed vectors (valid, expired, wrong-session, bad-signature,
rotated-key, conflicted-observation, party-conflicted, party-undetermined), or
exit 1. No dependencies, no network.
