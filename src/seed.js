/**
 * ATTEST · committed seed record
 *
 * WHY THIS EXISTS
 * ---------------
 * The host has no persistent disk, so a cold start would otherwise regenerate
 * the record from scratch: six fresh proofs, six fresh zkVerify submissions, a
 * different chain root, and different transaction hashes every time the
 * instance wakes. That means the record a reviewer reads in the submission is
 * not the record the running app shows. Bad.
 *
 * So we commit one real, anchored record to the repository and load it instead
 * of re-proving. Every visitor sees the same chain, the quoted transaction
 * hashes stay valid, cold starts are instant, and we stop re-submitting to
 * Kurier on every wake.
 *
 * WHAT THIS DOES NOT CHANGE
 * -------------------------
 * The proofs are still genuine Groth16 proofs over the same circuit — you
 * cannot fabricate one without running it, so their existence is itself
 * evidence the circuit ran. The anchors are real on-chain transactions that
 * really happened. And any decision added through the agent afterwards is
 * proven live, against the same circuit and verification key.
 *
 * test/seed.js verifies every committed proof against the current verification
 * key, so a future circuit rebuild cannot silently leave stale proofs behind.
 */
const fs = require("fs");
const path = require("path");
const chainLib = require("./chain");

const SEED_FILE = path.join(__dirname, "..", "seed", "record.json");

function load() {
  if (!fs.existsSync(SEED_FILE)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(SEED_FILE, "utf8"));
    if (!Array.isArray(parsed.entries) || parsed.entries.length === 0) return null;
    return parsed;
  } catch (err) {
    console.error(`[attest] seed record unreadable: ${err.message}`);
    return null;
  }
}

/**
 * Rebuild the published-anchor list from the entries.
 *
 * The live app pushes one anchor per decision, each holding the root of the
 * chain as it stood at that moment. Rather than store that twice, we
 * recompute it — it is a pure function of the entries.
 */
function reconstructAnchors(entries) {
  return entries.map((e, i) => {
    const a = (e.proof && e.proof.anchor) || {};
    return {
      at: e.timestamp,
      root: chainLib.computeRoot(entries.slice(0, i + 1)),
      length: i + 1,
      mode: a.mode || "local",
      status: a.status || "not_anchored",
      network: a.network || null,
      jobId: a.jobId || null,
      txHash: a.txHash || null,
    };
  });
}

module.exports = { load, reconstructAnchors, SEED_FILE };
