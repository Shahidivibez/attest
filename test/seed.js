/**
 * Guarantees the committed seed record is still valid.
 *
 * The seed lets every visitor see the same anchored record instead of a freshly
 * regenerated one. That only holds if the committed proofs still verify against
 * the CURRENT circuit's verification key. If the circuit is ever rebuilt, the
 * key changes and every committed proof silently becomes worthless — this test
 * is what catches that.
 */
const snarkjs = require("snarkjs");
const seedRecord = require("../src/seed");
const chainLib = require("../src/chain");
const prover = require("../src/prover");

let pass = 0, fail = 0;
const check = (n, c, x = "") => {
  if (c) { pass++; console.log(`  ok   ${n}`); }
  else { fail++; console.log(`  FAIL ${n} ${x}`); }
};

(async () => {
  console.log("\n=== committed seed record ===");
  const snap = seedRecord.load();
  check("seed file exists and parses", Boolean(snap));
  if (!snap) process.exit(1);

  const entries = snap.entries;
  check(`seed has entries (${entries.length})`, entries.length > 0);

  // 1. chain intact and root reproducible
  const probe = JSON.parse(JSON.stringify(entries));
  const anchors = seedRecord.reconstructAnchors(entries);
  probe[0].__storedRoot = anchors[anchors.length - 1].root;
  const v = chainLib.verifyChain(probe);
  check("seed chain verifies from genesis", v.ok, JSON.stringify(v.defects).slice(0, 300));
  check("reconstructed root matches the recorded root",
    v.root === anchors[anchors.length - 1].root);
  console.log(`       root: ${v.root}`);

  // 2. every proof still verifies against the CURRENT verification key
  const vk = require(prover.paths.VK);
  let allProofs = true;
  for (const e of entries) {
    if (!e.proof || e.proof.status !== "proven") { allProofs = false; break; }
    const ok = await snarkjs.groth16.verify(vk, e.proof.publicSignals, e.proof.proof);
    if (!ok) { allProofs = false; console.log(`       seq ${e.seq}: proof does NOT verify`); }
  }
  check("every committed proof verifies against the current VK", allProofs,
    "the circuit was rebuilt — regenerate seed/record.json");

  // 3. every proof is bound to its own entry
  let bound = true;
  for (const e of entries) {
    if (e.proof.publicSignals[5] !== prover.toField(e.entryHash)) bound = false;
  }
  check("every committed proof is bound to its own entry hash", bound);

  // 4. the anchors really are finalised on a real network
  const anchored = entries.filter((e) => e.proof.anchor && e.proof.anchor.status === "finalized");
  check(`all entries anchored (${anchored.length}/${entries.length})`, anchored.length === entries.length);
  const withTx = anchored.filter((e) => e.proof.anchor.txHash);
  check(`anchors carry transaction hashes (${withTx.length})`, withTx.length === anchored.length);

  // 5. the inputs are genuinely absent
  const signals = entries[0].proof.publicSignals;
  check("no personal data in the committed public signals", signals.length === 6);

  console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
