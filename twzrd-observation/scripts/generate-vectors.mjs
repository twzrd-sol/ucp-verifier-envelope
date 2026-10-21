import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  IssuanceRefused,
  issueSellerObservation,
  localEd25519Signer,
  privateKeyFromSeed,
  publicJwk,
  sha256,
} from "../src/seller-observation.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const vectorsDir = join(root, "vectors");
const referenceTime = 1792497600; // 2026-10-20T12:00:00Z
const kid = "twzrd-seller-observation-test-2026-10";
const seed = createHash("sha256").update("TWZRD UCP seller observation TEST KEY v1").digest();
const privateKey = privateKeyFromSeed(seed);
const jwk = publicJwk(privateKey, kid);
const signer = localEd25519Signer(privateKey);

const baseInput = {
  checkout_session: "ucp:checkout:cs_external_001",
  expires_at: referenceTime + 270,
  issued_at: referenceTime - 30,
  jti: "urn:uuid:00000000-0000-4000-8000-000000000001",
  observation: {
    artifact_digest: sha256("fixture listing artifact"),
    artifact_uri: "twzrd://claims/example-seller",
    evidence_digest: sha256("fixture canonical evidence bundle"),
    evidence_uri: "twzrd://claims/example-seller/evidence",
    expires_at: referenceTime + 3600,
    observed_at: "2026-10-20T11:58:00Z",
  },
  party_classified_at: "2026-10-20T11:59:00Z",
  party_context: {
    seller_operator: false,
    merchant: false,
    meter: false,
    facilitator: false,
    settler: false,
    sponsor: false,
    escrow_agent: false,
    fee_recipient: false,
  },
  policy_version: "seller-observation-party-policy/1",
  seller: {
    id: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:Seller11111111111111111111111111111111111",
    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
  },
};

const issue = (input, useKid = kid) => issueSellerObservation(input, { kid: useKid, sign: signer });
const valid = await issue(baseInput);
const expired = await issue({
  ...baseInput,
  issued_at: referenceTime - 300,
  expires_at: referenceTime - 1,
  jti: "urn:uuid:00000000-0000-4000-8000-000000000002",
  observation: { ...baseInput.observation, observed_at: "2026-10-20T11:54:00Z" },
  party_classified_at: "2026-10-20T11:54:30Z",
});
const wrongSession = await issue({
  ...baseInput,
  checkout_session: "ucp:checkout:cs_other",
  jti: "urn:uuid:00000000-0000-4000-8000-000000000003",
});
const rotatedKey = await issue({
  ...baseInput,
  jti: "urn:uuid:00000000-0000-4000-8000-000000000004",
}, "twzrd-seller-observation-retired-test-key");

const signatureBytes = Buffer.from(valid.jws.split(".")[2], "base64url");
signatureBytes[0] ^= 0x01;
const badSignature = {
  ...valid,
  jws: `${valid.jws.split(".").slice(0, 2).join(".")}.${signatureBytes.toString("base64url")}`,
};

let signerInvocations = 0;
const conflictedInput = {
  ...baseInput,
  jti: "urn:uuid:00000000-0000-4000-8000-000000000006",
  party_context: { ...baseInput.party_context, facilitator: true },
};
let conflictReason = "credential_was_issued";
try {
  await issueSellerObservation(conflictedInput, {
    kid,
    sign: (input) => {
      signerInvocations += 1;
      return signer(input);
    },
  });
} catch (error) {
  if (error instanceof IssuanceRefused) conflictReason = error.code;
  else throw error;
}

const vectors = {
  profile: "xyz.twzrd.seller_observation/1",
  reference_time: referenceTime,
  expected_session: baseInput.checkout_session,
  vectors: {
    valid: {
      envelope: valid,
      expected: { signature_valid: true, accepted: true, reason: "ok" },
    },
    expired: {
      envelope: expired,
      expected: { signature_valid: true, accepted: false, reason: "expired" },
    },
    "wrong-session": {
      envelope: wrongSession,
      expected: { signature_valid: true, accepted: false, reason: "scope_mismatch" },
    },
    "bad-signature": {
      envelope: badSignature,
      expected: { signature_valid: false, accepted: false, reason: "invalid_signature" },
    },
    "rotated-key": {
      envelope: rotatedKey,
      expected: { signature_valid: false, accepted: false, reason: "unknown_kid" },
    },
    "conflicted-observation": {
      issuance_input: conflictedInput,
      expected: { issued: false, reason: conflictReason, signer_invocations: signerInvocations },
    },
  },
};

await mkdir(vectorsDir, { recursive: true });
await writeFile(join(vectorsDir, "test-jwks.json"), `${JSON.stringify({ keys: [jwk] }, null, 2)}\n`);
await writeFile(join(vectorsDir, "vectors.json"), `${JSON.stringify(vectors, null, 2)}\n`);
