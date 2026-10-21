import { createPublicKey, verify as verifyBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { IssuanceRefused, issueSellerObservation } from "./src/seller-observation.mjs";

const FORMAT = "application/twzrd-seller-observation+jwt";
const ISSUER = "https://twzrd.xyz";
const PROFILE = "xyz.twzrd.seller_observation/1";
const PARTY_ROLES = [
  "seller_operator", "merchant", "meter", "facilitator", "settler", "sponsor",
  "escrow_agent", "fee_recipient",
];

const jwks = JSON.parse(await readFile(new URL("./vectors/test-jwks.json", import.meta.url), "utf8"));
const pack = JSON.parse(await readFile(new URL("./vectors/vectors.json", import.meta.url), "utf8"));
let failures = 0;

// Deliberately independent of src/seller-observation.mjs: this verifier reads
// committed bytes and reimplements the profile checks rather than asking the
// generator's verifier whether its own output is valid.
function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  throw new TypeError("value is outside the profile's canonical JSON subset");
}

function decodeJson(segment) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new TypeError("not unpadded base64url");
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) throw new TypeError("non-canonical base64url");
  const value = JSON.parse(bytes.toString("utf8"));
  if (Buffer.from(canonical(value)).toString("base64url") !== segment) throw new TypeError("non-canonical JSON");
  return value;
}

function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function coldVerify(envelope, { expectedSession, now }) {
  if (envelope?.format !== FORMAT || typeof envelope?.jws !== "string") {
    return { signature_valid: false, accepted: false, reason: "invalid_envelope" };
  }
  const segments = envelope.jws.split(".");
  if (segments.length !== 3) return { signature_valid: false, accepted: false, reason: "invalid_jws" };

  let header;
  let payload;
  try {
    header = decodeJson(segments[0]);
    payload = decodeJson(segments[1]);
  } catch {
    return { signature_valid: false, accepted: false, reason: "invalid_jws" };
  }
  if (!exactKeys(header, ["alg", "kid", "typ"])
      || header.alg !== "EdDSA" || header.typ !== FORMAT || !header.kid) {
    return { signature_valid: false, accepted: false, reason: "invalid_header" };
  }
  if (envelope.kid !== undefined && envelope.kid !== header.kid) {
    return { signature_valid: false, accepted: false, reason: "hint_mismatch" };
  }

  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid
    && candidate.kty === "OKP" && candidate.crv === "Ed25519" && candidate.alg === "EdDSA");
  if (!jwk) return { signature_valid: false, accepted: false, reason: "unknown_kid" };

  let signatureValid = false;
  try {
    signatureValid = verifyBytes(
      null,
      Buffer.from(`${segments[0]}.${segments[1]}`, "ascii"),
      createPublicKey({ key: jwk, format: "jwk" }),
      Buffer.from(segments[2], "base64url"),
    );
  } catch {
    return { signature_valid: false, accepted: false, reason: "invalid_signature" };
  }
  if (!signatureValid) return { signature_valid: false, accepted: false, reason: "invalid_signature" };

  const claimsValid = payload?.iss === ISSUER
    && payload?.profile === PROFILE
    && payload?.sub === payload?.seller?.id
    && payload?.observation?.kind === "public_listing"
    && payload?.observation?.artifact_spec === "com.twzrd.shopping.listing_claims/1.1"
    && /^sha256:[0-9a-f]{64}$/.test(payload?.observation?.artifact_digest ?? "")
    && /^sha256:[0-9a-f]{64}$/.test(payload?.observation?.evidence_digest ?? "")
    && payload?.party?.classification === "external"
    && exactKeys(payload?.party?.roles, PARTY_ROLES)
    && PARTY_ROLES.every((role) => payload.party.roles[role] === false)
    && Number.isSafeInteger(payload?.iat)
    && payload?.nbf === payload.iat
    && Number.isSafeInteger(payload?.exp)
    && payload.exp > payload.iat
    && payload.exp - payload.iat <= 300
    && Number.isSafeInteger(payload?.observation?.expires_at)
    && payload.observation.expires_at >= payload.exp;
  if (!claimsValid) return { signature_valid: true, accepted: false, reason: "invalid_claims" };
  if (now < payload.nbf) return { signature_valid: true, accepted: false, reason: "not_yet_valid" };
  if (now >= payload.exp) return { signature_valid: true, accepted: false, reason: "expired" };
  if (payload.aud !== expectedSession) return { signature_valid: true, accepted: false, reason: "scope_mismatch" };
  return { signature_valid: true, accepted: true, reason: "ok" };
}

for (const [name, vector] of Object.entries(pack.vectors)) {
  let actual;
  if (vector.envelope) {
    actual = coldVerify(vector.envelope, {
      expectedSession: pack.expected_session,
      now: pack.reference_time,
    });
  } else {
    let signerInvocations = 0;
    let issued = true;
    let reason = "credential_was_issued";
    try {
      await issueSellerObservation(vector.issuance_input, {
        kid: jwks.keys[0].kid,
        sign: () => {
          signerInvocations += 1;
          return Buffer.alloc(64);
        },
      });
    } catch (error) {
      issued = false;
      reason = error instanceof IssuanceRefused ? error.code : error.message;
    }
    actual = { issued, reason, signer_invocations: signerInvocations };
  }

  const pass = JSON.stringify(actual) === JSON.stringify(vector.expected);
  if (!pass) failures += 1;
  console.log(`${pass ? "PASS" : "FAIL"} ${name}: ${JSON.stringify(actual)}`);
}

if (failures > 0) process.exitCode = 1;
else console.log(`all ${Object.keys(pack.vectors).length} vectors matched expected outcomes`);
