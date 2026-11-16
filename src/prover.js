/**
 * ATTEST · Groth16 prover
 *
 * Generates the proof that a logged decision followed the published policy,
 * without revealing the applicant's score or income.
 *
 * The witness builder mirrors circuits/policy.circom. If the agent's verdict
 * disagrees with the circuit's own evaluation, witness generation throws and no
 * proof exists — the failure mode is "cannot prove", never "proves something
 * false".
 */
const path = require("path");
const snarkjs = require("snarkjs");
const { POLICY } = require("./policy");

const BUILD = path.join(__dirname, "..", "circuits", "build");
const WASM = path.join(BUILD, "policy_js", "policy.wasm");
const ZKEY = path.join(BUILD, "policy_final.zkey");
const VK = path.join(BUILD, "verification_key.json");

/**
 * Map a 32-byte hex hash into the BN254 scalar field.
 *
 * SHA-256 produces 256 bits; the BN254 scalar field is only ~254 bits. If we
 * naively hand a 256-bit value to snarkjs it is silently reduced mod p, and
 * then the value in publicSignals no longer equals the value stored in the log —
 * which would make every proof look like it belonged to a different entry.
 *
 * We mask to 253 bits instead of reducing, so the mapping is explicit,
 * deterministic and idempotent. This is a binding tag, not a security
 * commitment: the real commitment to private data is the Poseidon inputCommit,
 * which is native to the field.
 */
const FIELD_MASK = (1n << 253n) - 1n;
function toField(hex) {
  return (BigInt(hex) & FIELD_MASK).toString();
}

/**
 * Build the witness input for one decision.
 * Private: score, dti, salt. Public: the rest.
 */
function buildWitness({ score, dti, salt, decision, reasonCode, inputCommit, entryHash }, policy = POLICY) {
  return {
    // private
    score: String(score),
    dti: String(dti),
    salt: String(salt),
    // public
    threshold: String(policy.threshold),
    maxDti: String(policy.maxDti),
    decision: String(decision),
    reasonCode: String(reasonCode),
    inputCommit: String(inputCommit),
    entryHash: toField(entryHash),
  };
}

/** Generate a Groth16 proof. Returns { proof, publicSignals }. */
async function prove(witnessInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    witnessInput,
    WASM,
    ZKEY
  );
  return { proof, publicSignals };
}

/** Verify locally against our own VK. Fast, and catches our own bugs early. */
async function verifyLocally(proof, publicSignals) {
  const vk = require(VK);
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

/**
 * The public signal layout, matching the circuit's declaration order.
 * Exported so the UI and the audit path can label each value honestly.
 */
const PUBLIC_SIGNAL_LAYOUT = [
  "threshold",
  "maxDti",
  "decision",
  "reasonCode",
  "inputCommit",
  "entryHash",
];

function decodePublicSignals(publicSignals) {
  const out = {};
  PUBLIC_SIGNAL_LAYOUT.forEach((name, i) => {
    out[name] = publicSignals[i];
  });
  return out;
}

module.exports = {
  toField,
  buildWitness,
  prove,
  verifyLocally,
  decodePublicSignals,
  PUBLIC_SIGNAL_LAYOUT,
  paths: { WASM, ZKEY, VK },
};
