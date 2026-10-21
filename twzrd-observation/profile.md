# Draft claim type: seller observation (`xyz.twzrd.seller_observation`)

Status: draft, proposed to `trust-verdict/ucp-verifier-envelope`. Owned and
versioned by the issuer per [GOVERNANCE.md](../GOVERNANCE.md).

This is a buyer-facing, checkout-session-scoped observation about a third-party
seller. It lets a buyer or platform verify that TWZRD admitted a specific
public-listing artifact and evidence bundle, without calling TWZRD during
verification. It does not attest seller identity, merchant authority, delivery,
purchase completion, or permission to spend.

## Signal

| field | value |
|---|---|
| signal | `xyz.twzrd.seller_observation` |
| profile | `xyz.twzrd.seller_observation/1` |
| scope | one UCP checkout session and one seller |
| envelope | RFC 7515 compact JWS |
| algorithm | EdDSA / Ed25519 |
| payload bytes | RFC 8785 canonical JSON |
| `typ` | `application/twzrd-seller-observation+jwt` |
| issuer | `https://twzrd.xyz` |
| pinned JWKS | `https://twzrd.xyz/.well-known/jwks.json` |

The protected JWS header contains exactly the routing values `alg`, `kid`, and
`typ`. The envelope-level `kid` and `provider_jwks` are hints. A verifier pins
the signal, issuer, and JWKS URL out of band and never fetches the hint. The
selected JWK must be an Ed25519 `OKP` key with `alg: EdDSA`; when `use` is
present it must be `sig`.

## Signed claims

The JWS payload contains:

- standard binding claims: `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, and `jti`;
- `profile`, fixed to `xyz.twzrd.seller_observation/1`;
- `seller.id` and `seller.network`;
- `observation.kind`, fixed to `public_listing`, plus `observed_at`,
  `expires_at`, `artifact_spec`, `artifact_uri`, `artifact_digest`,
  `evidence_uri`, and `evidence_digest`;
- `policy_version`; and
- `party.classification`, fixed to `external`, `classified_at`, and the eight
  issuer-role booleans below.

The credential signs digests rather than raw page bodies or a resource URL. The
artifact and evidence bundle remain independently retrievable evidence. Their
digests keep the signal small and prevent URL query data from entering it.
The seller is a CAIP-10 account and its network is CAIP-2. The account's CAIP-2
prefix must equal the signed network. The JWS lifetime is at most five minutes
and may not extend beyond the referenced artifact. Observation and party
classification timestamps are RFC 3339 UTC instants and may not postdate
issuance, including by a fractional second.

## Non-party rule

TWZRD issues this signal only for subject transactions it does not operate,
meter, settle, sponsor, or receive a fee from. Any payment for the TWZRD
observation is separate from the transaction being assessed.

The issuer must classify all eight roles:

1. `seller_operator`
2. `merchant`
3. `meter`
4. `facilitator`
5. `settler`
6. `sponsor`
7. `escrow_agent`
8. `fee_recipient`

Every role must be known and false before signing, and an unmodeled role is an
unknown rather than something the issuer silently ignores. A true role returns
`party_conflict`; a missing or unclassified role returns
`party_status_unknown`. Both refusals occur before signer invocation and
produce no JWS. This rule excludes TWZRD-owned sellers, fixtures, and any rail or escrow in
which TWZRD takes one of these roles.

The signed `party` object makes the issuer's classification inspectable. It is
not independent proof of neutrality; the issuer implementation and its refusal
tests are the evidence that the promise is enforced.

## Consumer verification

The consumer:

1. selects this profile from its pinned signal allow-list;
2. ignores `provider_jwks` as an authority and resolves the protected-header
   `kid` only within the pinned TWZRD JWKS;
3. verifies Ed25519 over the compact-JWS signing input;
4. checks `iss`, `profile`, `typ`, the signed party assertion, and the validity
   window;
5. requires `aud` to equal the checkout session in hand and `sub` to equal the
   seller being evaluated; and
6. resolves the artifact separately and requires both signed digests to match.

An unknown key, bad signature, expired credential, wrong checkout session,
changed artifact, changed evidence, invalid party assertion, or unavailable
pinned key set rejects the signal.

## Conformance

The committed vectors contain eight cases:

| vector | expected result |
|---|---|
| valid | signature valid; consumer accepts |
| expired | signature valid; consumer rejects expiry |
| wrong-session | signature valid; consumer rejects scope |
| bad-signature | verifier rejects |
| rotated-key | verifier rejects unknown `kid` |
| conflicted-observation | issuer refuses before signing; signer count remains zero |
| party-conflicted | issuer refuses with `party_conflict`; signer count remains zero |
| party-undetermined | issuer refuses with `party_status_unknown`; signer count remains zero |

Run `npm test` in this directory. All checks are offline and use a clearly named
fixture key. The fixture key is not a candidate production key.
