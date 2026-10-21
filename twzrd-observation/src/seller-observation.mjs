import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";

export const SIGNAL = "xyz.twzrd.seller_observation";
export const PROFILE = "xyz.twzrd.seller_observation/1";
export const FORMAT = "application/twzrd-seller-observation+jwt";
export const ISSUER = "https://twzrd.xyz";
export const JWKS_URI = "https://twzrd.xyz/.well-known/jwks.json";
export const MAX_CREDENTIAL_LIFETIME_SECONDS = 300;

export const PARTY_ROLES = Object.freeze([
  "seller_operator",
  "merchant",
  "meter",
  "facilitator",
  "settler",
  "sponsor",
  "escrow_agent",
  "fee_recipient",
]);

export class IssuanceRefused extends Error {
  constructor(code, details = []) {
    super(code);
    this.name = "IssuanceRefused";
    this.code = code;
    this.details = details;
  }
}

/** RFC 8785 for this profile's deliberately narrow JSON subset. */
export function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new TypeError("numbers must be safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item)}`).join(",")}}`;
  }
  throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
}

export function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

export function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function privateKeyFromSeed(seed) {
  const bytes = Buffer.from(seed);
  if (bytes.length !== 32) throw new TypeError("Ed25519 seed must be 32 bytes");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, bytes]), format: "der", type: "pkcs8" });
}

export function publicJwk(privateKey, kid) {
  return {
    ...createPublicKey(privateKey).export({ format: "jwk" }),
    kid,
    use: "sig",
    alg: "EdDSA",
  };
}

export function classifyPartyContext(partyContext) {
  if (!partyContext || typeof partyContext !== "object" || Array.isArray(partyContext)) {
    throw new IssuanceRefused("party_status_unknown", PARTY_ROLES);
  }
  const unknown = PARTY_ROLES.filter((role) => typeof partyContext[role] !== "boolean");
  const unsupported = Object.keys(partyContext)
    .filter((role) => !PARTY_ROLES.includes(role))
    .map((role) => `unsupported:${role}`);
  unknown.push(...unsupported);
  if (unknown.length > 0) throw new IssuanceRefused("party_status_unknown", unknown);
  const conflicts = PARTY_ROLES.filter((role) => partyContext[role] === true);
  if (conflicts.length > 0) throw new IssuanceRefused("party_conflict", conflicts);
  return Object.fromEntries(PARTY_ROLES.map((role) => [role, false]));
}

function requiredString(value, name) {
  if (typeof value !== "string" || value.length === 0) throw new TypeError(`${name} must be a non-empty string`);
  return value;
}

function unixSeconds(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${name} must be a non-negative integer`);
  return value;
}

function rfc3339Instant(value, name) {
  const text = requiredString(value, name);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?Z$/.exec(text);
  if (!match || match[1] === "0000") {
    throw new TypeError(`${name} must be an RFC 3339 UTC instant`);
  }
  const [, year, month, day, hour, minute, second, fraction = ""] = match;
  const parsed = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}Z`);
  if (!Number.isFinite(parsed)) throw new TypeError(`${name} must be an RFC 3339 UTC instant`);
  const date = new Date(parsed);
  if (
    date.getUTCFullYear() !== Number(year)
    || date.getUTCMonth() + 1 !== Number(month)
    || date.getUTCDate() !== Number(day)
    || date.getUTCHours() !== Number(hour)
    || date.getUTCMinutes() !== Number(minute)
    || date.getUTCSeconds() !== Number(second)
  ) {
    throw new TypeError(`${name} must be an RFC 3339 UTC instant`);
  }
  return {
    seconds: parsed / 1000,
    hasSubsecond: /[1-9]/.test(fraction),
  };
}

function instantIsAfterUnixSecond(instant, unixSecond) {
  return instant.seconds > unixSecond
    || (instant.seconds === unixSecond && instant.hasSubsecond);
}

export function buildPayload(input) {
  const roles = classifyPartyContext(input.party_context);
  const iat = unixSeconds(input.issued_at, "issued_at");
  const exp = unixSeconds(input.expires_at, "expires_at");
  if (exp <= iat) throw new TypeError("expires_at must be after issued_at");
  if (exp - iat > MAX_CREDENTIAL_LIFETIME_SECONDS) {
    throw new TypeError(`credential lifetime must not exceed ${MAX_CREDENTIAL_LIFETIME_SECONDS} seconds`);
  }

  const sellerId = requiredString(input.seller?.id, "seller.id");
  const network = requiredString(input.seller?.network, "seller.network");
  if (!/^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(network)) throw new TypeError("seller.network must be CAIP-2");
  if (!/^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/.test(sellerId)) {
    throw new TypeError("seller.id must be CAIP-10");
  }
  if (!sellerId.startsWith(`${network}:`)) throw new TypeError("seller.id network must match seller.network");
  const observedAt = requiredString(input.observation?.observed_at, "observation.observed_at");
  const observedAtInstant = rfc3339Instant(observedAt, "observation.observed_at");
  const observationExpiresAt = unixSeconds(input.observation?.expires_at, "observation.expires_at");
  if (instantIsAfterUnixSecond(observedAtInstant, iat)) throw new TypeError("observation cannot postdate issuance");
  if (observationExpiresAt < exp) throw new TypeError("credential cannot outlive its observation artifact");
  const artifactDigest = requiredString(input.observation?.artifact_digest, "observation.artifact_digest");
  const artifactUri = requiredString(input.observation?.artifact_uri, "observation.artifact_uri");
  const evidenceDigest = requiredString(input.observation?.evidence_digest, "observation.evidence_digest");
  const evidenceUri = requiredString(input.observation?.evidence_uri, "observation.evidence_uri");
  if (!/^sha256:[0-9a-f]{64}$/.test(artifactDigest)) throw new TypeError("artifact_digest must be sha256 hex");
  if (!/^sha256:[0-9a-f]{64}$/.test(evidenceDigest)) throw new TypeError("evidence_digest must be sha256 hex");
  if (!artifactUri.startsWith("twzrd://claims/")) throw new TypeError("artifact_uri must be a twzrd claims URI");
  if (!evidenceUri.startsWith("twzrd://claims/")) throw new TypeError("evidence_uri must be a twzrd claims URI");
  const partyClassifiedAt = requiredString(input.party_classified_at, "party_classified_at");
  const partyClassifiedInstant = rfc3339Instant(partyClassifiedAt, "party_classified_at");
  if (instantIsAfterUnixSecond(partyClassifiedInstant, iat)) {
    throw new TypeError("party classification cannot postdate issuance");
  }

  return {
    aud: requiredString(input.checkout_session, "checkout_session"),
    exp,
    iat,
    iss: ISSUER,
    jti: requiredString(input.jti, "jti"),
    nbf: iat,
    observation: {
      artifact_digest: artifactDigest,
      artifact_spec: "com.twzrd.shopping.listing_claims/1.1",
      artifact_uri: artifactUri,
      evidence_digest: evidenceDigest,
      evidence_uri: evidenceUri,
      expires_at: observationExpiresAt,
      kind: "public_listing",
      observed_at: observedAt,
    },
    party: {
      classification: "external",
      classified_at: partyClassifiedAt,
      roles,
    },
    policy_version: requiredString(input.policy_version, "policy_version"),
    profile: PROFILE,
    seller: { id: sellerId, network },
    sub: sellerId,
  };
}

export async function issueSellerObservation(input, { kid, sign }) {
  requiredString(kid, "kid");
  if (typeof sign !== "function") throw new TypeError("sign must be a function");

  // The party check happens while building the payload, before the signer is
  // reachable. A conflict or an unknown role therefore produces no credential.
  const payload = buildPayload(input);
  const protectedHeader = { alg: "EdDSA", kid, typ: FORMAT };
  const headerSegment = base64url(canonicalize(protectedHeader));
  const payloadSegment = base64url(canonicalize(payload));
  const signingInput = Buffer.from(`${headerSegment}.${payloadSegment}`, "ascii");
  const signature = Buffer.from(await sign(signingInput));
  if (signature.length !== 64) throw new TypeError("Ed25519 signer must return 64 bytes");

  return {
    format: FORMAT,
    jws: `${headerSegment}.${payloadSegment}.${base64url(signature)}`,
    kid,
    provider_jwks: JWKS_URI,
  };
}

export function localEd25519Signer(privateKey) {
  return (input) => signBytes(null, input, privateKey);
}

function decodeSegment(segment, name) {
  if (typeof segment !== "string" || !/^[A-Za-z0-9_-]+$/.test(segment)) {
    throw new TypeError(`${name} is not unpadded base64url`);
  }
  try {
    const decoded = Buffer.from(segment, "base64url");
    if (decoded.toString("base64url") !== segment) throw new TypeError(`${name} is not canonical base64url`);
    return decoded;
  } catch {
    throw new TypeError(`${name} is not base64url`);
  }
}

function parseJsonSegment(segment, name) {
  const bytes = decodeSegment(segment, name);
  try {
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (base64url(canonicalize(parsed)) !== segment) throw new TypeError(`${name} is not canonical JSON`);
    return parsed;
  } catch {
    throw new TypeError(`${name} is not JSON`);
  }
}

function hasExactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateSignedPayload(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return "invalid_claims";
  if (!hasExactKeys(payload, [
    "aud", "exp", "iat", "iss", "jti", "nbf", "observation", "party",
    "policy_version", "profile", "seller", "sub",
  ])) return "invalid_claims";
  if (!hasExactKeys(payload.seller, ["id", "network"])) return "invalid_claims";
  if (!hasExactKeys(payload.observation, [
    "artifact_digest", "artifact_spec", "artifact_uri", "evidence_digest",
    "evidence_uri", "expires_at", "kind", "observed_at",
  ])) return "invalid_claims";
  if (!hasExactKeys(payload.party, ["classification", "classified_at", "roles"])) return "invalid_claims";
  if (payload.iss !== ISSUER || payload.profile !== PROFILE || payload.sub !== payload.seller?.id) {
    return "invalid_claims";
  }
  if (payload.observation?.kind !== "public_listing") return "invalid_claims";
  if (payload.observation?.artifact_spec !== "com.twzrd.shopping.listing_claims/1.1") return "invalid_claims";
  if (!/^sha256:[0-9a-f]{64}$/.test(payload.observation?.artifact_digest ?? "")) return "invalid_claims";
  if (!/^sha256:[0-9a-f]{64}$/.test(payload.observation?.evidence_digest ?? "")) return "invalid_claims";
  if (!payload.observation?.artifact_uri?.startsWith("twzrd://claims/")) return "invalid_claims";
  if (!payload.observation?.evidence_uri?.startsWith("twzrd://claims/")) return "invalid_claims";
  if (payload.party?.classification !== "external") return "invalid_claims";
  try {
    classifyPartyContext(payload.party.roles);
  } catch {
    return "invalid_party_assertion";
  }
  for (const field of ["iat", "nbf", "exp"]) {
    if (!Number.isSafeInteger(payload[field]) || payload[field] < 0) return "invalid_claims";
  }
  if (payload.nbf !== payload.iat || payload.exp <= payload.iat) return "invalid_claims";
  if (payload.exp - payload.iat > MAX_CREDENTIAL_LIFETIME_SECONDS) return "invalid_claims";
  if (!Number.isSafeInteger(payload.observation.expires_at) || payload.observation.expires_at < payload.exp) {
    return "invalid_claims";
  }
  for (const field of ["aud", "jti", "policy_version", "sub"]) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) return "invalid_claims";
  }
  for (const value of [
    payload.seller.id,
    payload.seller.network,
    payload.observation.observed_at,
    payload.party.classified_at,
  ]) {
    if (typeof value !== "string" || value.length === 0) return "invalid_claims";
  }
  if (!/^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(payload.seller.network)) return "invalid_claims";
  if (!/^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/.test(payload.seller.id)) {
    return "invalid_claims";
  }
  if (!payload.seller.id.startsWith(`${payload.seller.network}:`)) return "invalid_claims";
  try {
    if (instantIsAfterUnixSecond(
      rfc3339Instant(payload.observation.observed_at, "observation.observed_at"),
      payload.iat,
    )) {
      return "invalid_claims";
    }
    if (instantIsAfterUnixSecond(
      rfc3339Instant(payload.party.classified_at, "party.classified_at"),
      payload.iat,
    )) {
      return "invalid_claims";
    }
  } catch {
    return "invalid_claims";
  }
  return null;
}

export function verifySellerObservation(envelope, { jwks, expectedSession, now }) {
  if (!envelope || typeof envelope !== "object" || envelope.format !== FORMAT || typeof envelope.jws !== "string") {
    return { signature_valid: false, accepted: false, reason: "invalid_envelope" };
  }
  const segments = envelope.jws.split(".");
  if (segments.length !== 3) return { signature_valid: false, accepted: false, reason: "invalid_jws" };

  let header;
  let payload;
  try {
    header = parseJsonSegment(segments[0], "protected header");
    payload = parseJsonSegment(segments[1], "payload");
  } catch {
    return { signature_valid: false, accepted: false, reason: "invalid_jws" };
  }
  if (!hasExactKeys(header, ["alg", "kid", "typ"]) || header.alg !== "EdDSA" || header.typ !== FORMAT || typeof header.kid !== "string") {
    return { signature_valid: false, accepted: false, reason: "invalid_header" };
  }
  if (envelope.kid !== undefined && envelope.kid !== header.kid) {
    return { signature_valid: false, accepted: false, reason: "hint_mismatch" };
  }
  const key = jwks?.keys?.find((candidate) => (
    candidate.kid === header.kid
    && candidate.alg === "EdDSA"
    && candidate.kty === "OKP"
    && candidate.crv === "Ed25519"
    && (candidate.use === undefined || candidate.use === "sig")
    && typeof candidate.x === "string"
  ));
  if (!key) return { signature_valid: false, accepted: false, reason: "unknown_kid" };

  let signatureValid = false;
  try {
    signatureValid = verifyBytes(
      null,
      Buffer.from(`${segments[0]}.${segments[1]}`, "ascii"),
      createPublicKey({ key, format: "jwk" }),
      decodeSegment(segments[2], "signature"),
    );
  } catch {
    return { signature_valid: false, accepted: false, reason: "invalid_signature" };
  }
  if (!signatureValid) return { signature_valid: false, accepted: false, reason: "invalid_signature" };

  const payloadError = validateSignedPayload(payload);
  if (payloadError) return { signature_valid: true, accepted: false, reason: payloadError, payload };
  if (!Number.isSafeInteger(now)) return { signature_valid: true, accepted: false, reason: "invalid_clock", payload };
  if (now < payload.nbf) return { signature_valid: true, accepted: false, reason: "not_yet_valid", payload };
  if (now >= payload.exp) return { signature_valid: true, accepted: false, reason: "expired", payload };
  if (payload.aud !== expectedSession) return { signature_valid: true, accepted: false, reason: "scope_mismatch", payload };
  return { signature_valid: true, accepted: true, reason: "ok", payload };
}
