/**
 * ATTEST · append-only hash chain
 *
 * Each entry commits to the entry before it. Editing any historical entry
 * changes its hash, which breaks every link after it, which changes the root.
 * That is the tamper-evidence layer — and unlike the ZK layer, it costs nothing
 * per decision, which is why it runs on every single one.
 *
 * The chain root is what gets anchored (via zkVerify) so the record exists
 * outside our database, on a public ledger, where we cannot quietly rewrite it.
 */
const crypto = require("crypto");

const GENESIS = "0x" + "0".repeat(64);

/** Deterministic serialisation: sort keys so property order can't change a hash. */
function canonical(obj) {
  if (obj === null || typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonical).join(",") + "]";
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
}

function sha256hex(input) {
  return "0x" + crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * Compute the hash of an entry. Everything that matters is covered: the
 * committed inputs, the policy version, the verdict, the reason, and the link
 * to the previous entry. Changing any one of them changes the hash.
 */
function entryHash(entry) {
  return sha256hex(
    canonical({
      seq: entry.seq,
      timestamp: entry.timestamp,
      inputCommit: entry.inputCommit,
      policyId: entry.policyId,
      policyParams: entry.policyParams,
      decision: entry.decision,
      reasonCode: entry.reasonCode,
      prevHash: entry.prevHash,
    })
  );
}

/** Fold a chain of entries into a single root. */
function computeRoot(entries) {
  let root = GENESIS;
  for (const e of entries) {
    root = sha256hex(root + e.entryHash);
  }
  return root;
}

/**
 * Verify the whole chain from genesis.
 *
 * Returns every defect found rather than stopping at the first, so the UI can
 * show a complete picture of what was touched.
 */
function verifyChain(entries) {
  const defects = [];
  let prevHash = GENESIS;

  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];

    // 1. position must be unbroken
    if (e.seq !== i) {
      defects.push({
        seq: e.seq,
        index: i,
        type: "SEQ_GAP",
        detail: `entry at index ${i} claims seq ${e.seq}`,
      });
    }

    // 2. the link to the previous entry must hold
    if (e.prevHash !== prevHash) {
      defects.push({
        seq: e.seq,
        index: i,
        type: "LINK_BROKEN",
        detail: `entry ${e.seq} points at ${short(e.prevHash)}, chain expects ${short(prevHash)}`,
      });
    }

    // 3. the entry's own hash must match its stored content
    const recomputed = entryHash(e);
    if (recomputed !== e.entryHash) {
      defects.push({
        seq: e.seq,
        index: i,
        type: "CONTENT_ALTERED",
        detail: `entry ${e.seq} content does not match its recorded hash — it was edited after being written`,
      });
    }

    // 4. a sealed entry must carry its proof
    if (e.proof && e.proof.status === "proven" && !e.proof.publicSignals) {
      defects.push({
        seq: e.seq,
        index: i,
        type: "PROOF_MISSING",
        detail: `entry ${e.seq} claims to be proven but carries no public signals`,
      });
    }

    prevHash = e.entryHash;
  }

  // 5. the root must still match — this is the value anchored on-chain, so if
  //    it moved, the record we published is no longer the record we hold.
  const root = computeRoot(entries);
  const stored = entries.length ? entries[0].__storedRoot : null;
  if (stored && stored !== root) {
    defects.push({
      seq: null,
      index: null,
      type: "ROOT_MISMATCH",
      detail: `chain root is ${short(root)} but ${short(stored)} was anchored`,
    });
  }

  return {
    ok: defects.length === 0,
    defects,
    length: entries.length,
    root,
  };
}

function short(h) {
  if (!h) return "—";
  return h.slice(0, 10) + "…" + h.slice(-6);
}

/** Build the next entry, sealing it against the current chain tip. */
function append(entries, body) {
  const prev = entries.length ? entries[entries.length - 1].entryHash : GENESIS;
  const entry = {
    seq: entries.length,
    timestamp: new Date().toISOString(),
    inputCommit: body.inputCommit,
    policyId: body.policyId,
    policyParams: body.policyParams,
    decision: body.decision,
    reasonCode: body.reasonCode,
    prevHash: prev,
  };
  entry.entryHash = entryHash(entry);
  // The proof is attached after proving; it is deliberately NOT part of
  // entryHash, because the hash is sealed at write time and the proof is
  // produced against the sealed entry. That's what makes entryHash meaningful
  // as a binding tag inside the circuit.
  entry.proof = null;
  return entry;
}

module.exports = {
  GENESIS,
  entryHash,
  computeRoot,
  verifyChain,
  append,
  canonical,
  sha256hex,
  short,
};
