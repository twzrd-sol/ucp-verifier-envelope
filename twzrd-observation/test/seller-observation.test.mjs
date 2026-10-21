import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  IssuanceRefused,
  PARTY_ROLES,
  issueSellerObservation,
  localEd25519Signer,
  privateKeyFromSeed,
  publicJwk,
  sha256,
  verifySellerObservation,
} from "../src/seller-observation.mjs";

const now = 1792497600;
const kid = "test-key";
const privateKey = privateKeyFromSeed(createHash("sha256").update("unit test key").digest());
const sign = localEd25519Signer(privateKey);
const jwks = { keys: [publicJwk(privateKey, kid)] };

const input = {
  checkout_session: "ucp:checkout:test",
  expires_at: now + 60,
  issued_at: now - 1,
  jti: "urn:test:1",
  observation: {
    artifact_digest: sha256("artifact"),
    artifact_uri: "twzrd://claims/test",
    evidence_digest: sha256("evidence"),
    evidence_uri: "twzrd://claims/test/evidence",
    expires_at: now + 3600,
    observed_at: "2026-10-20T11:59:00Z",
  },
  party_classified_at: "2026-10-20T11:59:30Z",
  party_context: Object.fromEntries(PARTY_ROLES.map((role) => [role, false])),
  policy_version: "test/1",
  seller: { id: "solana:test:seller", network: "solana:test" },
};

test("every party role refuses before the signer", async () => {
  for (const role of PARTY_ROLES) {
    let calls = 0;
    await assert.rejects(
      issueSellerObservation(
        { ...input, party_context: { ...input.party_context, [role]: true } },
        { kid, sign: () => { calls += 1; return Buffer.alloc(64); } },
      ),
      (error) => error instanceof IssuanceRefused && error.code === "party_conflict" && error.details.includes(role),
    );
    assert.equal(calls, 0, `${role} conflict reached signer`);
  }
});

test("an unclassified role refuses before the signer", async () => {
  const partyContext = { ...input.party_context };
  delete partyContext.settler;
  let calls = 0;
  await assert.rejects(
    issueSellerObservation(inputWith({ party_context: partyContext }), {
      kid,
      sign: () => { calls += 1; return Buffer.alloc(64); },
    }),
    (error) => error instanceof IssuanceRefused && error.code === "party_status_unknown",
  );
  assert.equal(calls, 0);
});

test("an unmodeled party role fails closed before the signer", async () => {
  let calls = 0;
  await assert.rejects(
    issueSellerObservation(inputWith({
      party_context: { ...input.party_context, transaction_broker: false },
    }), {
      kid,
      sign: () => { calls += 1; return Buffer.alloc(64); },
    }),
    (error) => error instanceof IssuanceRefused
      && error.code === "party_status_unknown"
      && error.details.includes("unsupported:transaction_broker"),
  );
  assert.equal(calls, 0);
});

test("a classified external observation signs once and verifies offline", async () => {
  let calls = 0;
  const envelope = await issueSellerObservation(input, {
    kid,
    sign: (bytes) => { calls += 1; return sign(bytes); },
  });
  assert.equal(calls, 1);
  const result = verifySellerObservation(envelope, { jwks, expectedSession: input.checkout_session, now });
  assert.equal(result.accepted, true);
  assert.equal(result.payload.party.classification, "external");
});

test("issuer refuses a seller account from another network before signing", async () => {
  let calls = 0;
  await assert.rejects(
    issueSellerObservation(inputWith({
      seller: { id: "solana:other:seller", network: "solana:test" },
    }), {
      kid,
      sign: () => { calls += 1; return Buffer.alloc(64); },
    }),
    /seller\.id network must match seller\.network/,
  );
  assert.equal(calls, 0);
});

test("issuer refuses a party classification after issuance before signing", async () => {
  let calls = 0;
  await assert.rejects(
    issueSellerObservation(inputWith({
      party_classified_at: "2026-10-20T11:59:59.000001Z",
    }), {
      kid,
      sign: () => { calls += 1; return Buffer.alloc(64); },
    }),
    /party classification cannot postdate issuance/,
  );
  assert.equal(calls, 0);
});

test("provider_jwks is an untrusted hint and is never fetched", async () => {
  const envelope = await issueSellerObservation(input, { kid, sign });
  envelope.provider_jwks = "http://127.0.0.1/latest/meta-data";
  const result = verifySellerObservation(envelope, { jwks, expectedSession: input.checkout_session, now });
  assert.equal(result.accepted, true);
});

test("verifier refuses a matching key that is not intended for signatures", async () => {
  const envelope = await issueSellerObservation(input, { kid, sign });
  const encryptionJwks = {
    keys: [{ ...jwks.keys[0], use: "enc" }],
  };
  const result = verifySellerObservation(envelope, {
    jwks: encryptionJwks,
    expectedSession: input.checkout_session,
    now,
  });
  assert.deepEqual(result, {
    signature_valid: false,
    accepted: false,
    reason: "unknown_kid",
  });
});

test("changing the signed payload invalidates the credential", async () => {
  const envelope = await issueSellerObservation(input, { kid, sign });
  const [header, payload, signature] = envelope.jws.split(".");
  const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  parsed.seller.id = "seller:attacker";
  envelope.jws = `${header}.${Buffer.from(JSON.stringify(parsed)).toString("base64url")}.${signature}`;
  const result = verifySellerObservation(envelope, { jwks, expectedSession: input.checkout_session, now });
  assert.deepEqual(
    { signature_valid: result.signature_valid, accepted: result.accepted, reason: result.reason },
    { signature_valid: false, accepted: false, reason: "invalid_signature" },
  );
});

function inputWith(overrides) {
  return { ...input, ...overrides };
}

test("committed vectors cover a clean credential and both party exclusions", async () => {
  const pack = JSON.parse(await readFile(new URL("../vectors/vectors.json", import.meta.url), "utf8"));
  const pinned = JSON.parse(await readFile(new URL("../vectors/test-jwks.json", import.meta.url), "utf8"));
  const clean = verifySellerObservation(pack.vectors.valid.envelope, {
    jwks: pinned,
    expectedSession: pack.expected_session,
    now: pack.reference_time,
  });
  assert.deepEqual(
    { signature_valid: clean.signature_valid, accepted: clean.accepted, reason: clean.reason },
    pack.vectors.valid.expected,
  );

  for (const name of ["party-conflicted", "party-undetermined"]) {
    const vector = pack.vectors[name];
    let calls = 0;
    await assert.rejects(
      issueSellerObservation(vector.issuance_input, {
        kid: pinned.keys[0].kid,
        sign: () => {
          calls += 1;
          return Buffer.alloc(64);
        },
      }),
      (error) => error instanceof IssuanceRefused && error.code === vector.expected.reason,
    );
    assert.equal(calls, vector.expected.signer_invocations);
    assert.equal(vector.expected.issued, false);
  }
});
