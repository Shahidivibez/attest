/**
 * Smoke test: the whole pipeline, end to end.
 * policy → commit → chain → prove → verify, then try to cheat it.
 */
const { evaluate, POLICY } = require("../src/policy");
const { inputCommit, randomSalt } = require("../src/poseidon");
const chainLib = require("../src/chain");
const prover = require("../src/prover");

let pass = 0;
let fail = 0;

function check(name, cond, extra = "") {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

async function sealDecision(entries, { score, dti }) {
  const verdict = evaluate({ score, dti });
  const salt = randomSalt();
  const commit = await inputCommit(score, dti, salt);

  const entry = chainLib.append(entries, {
    inputCommit: commit,
    policyId: POLICY.id,
    policyParams: { threshold: POLICY.threshold, maxDti: POLICY.maxDti },
    decision: verdict.decision,
    reasonCode: verdict.reasonCode,
  });
  entries.push(entry);

  const witness = prover.buildWitness({
    score, dti, salt,
    decision: verdict.decision,
    reasonCode: verdict.reasonCode,
    inputCommit: commit,
    entryHash: entry.entryHash,
  });

  const { proof, publicSignals } = await prover.prove(witness);
  const verified = await prover.verifyLocally(proof, publicSignals);

  entry.proof = { status: verified ? "proven" : "invalid", proof, publicSignals };
  return { entry, verdict, verified, publicSignals };
}

(async () => {
  console.log("\n=== 1. policy engine ===");
  check("score 700 / dti 3000 approves", evaluate({ score: 700, dti: 3000 }).decisionLabel === "APPROVE");
  check("score 500 rejects on score", evaluate({ score: 500, dti: 3000 }).reasonLabel === "SCORE_BELOW_THRESHOLD");
  check("score 700 / dti 5000 rejects on dti", evaluate({ score: 700, dti: 5000 }).reasonLabel === "DTI_EXCEEDED");
  // boundary: score == threshold is a pass, dti == maxDti is a pass
  check("boundary: score == threshold passes", evaluate({ score: 620, dti: 3000 }).decisionLabel === "APPROVE");
  check("boundary: dti == maxDti passes", evaluate({ score: 700, dti: 4200 }).decisionLabel === "APPROVE");
  // ordered rule: both would fail → reported as score, not dti
  check("ordered rule: both fail → SCORE_BELOW_THRESHOLD", evaluate({ score: 500, dti: 9000 }).reasonLabel === "SCORE_BELOW_THRESHOLD");

  console.log("\n=== 2. build a chain of real, proven decisions ===");
  const entries = [];
  const cases = [
    { score: 712, dti: 3100 },  // approve
    { score: 548, dti: 2800 },  // reject on score
    { score: 690, dti: 4890 },  // reject on dti
    { score: 820, dti: 1900 },  // approve
  ];
  for (const c of cases) {
    const r = await sealDecision(entries, c);
    console.log(`     seq ${r.entry.seq}: ${r.verdict.decisionLabel.padEnd(7)} ${r.verdict.reasonLabel.padEnd(22)} proof=${r.verified} entry=${chainLib.short(r.entry.entryHash)}`);
  }
  check("every decision produced a valid proof", entries.every((e) => e.proof.status === "proven"));

  console.log("\n=== 3. chain verification ===");
  let v = chainLib.verifyChain(entries);
  check("intact chain verifies", v.ok, JSON.stringify(v.defects));
  check("root is 32 bytes hex", /^0x[0-9a-f]{64}$/.test(v.root));

  console.log("\n=== 4. public signals expose no personal data ===");
  const decoded = prover.decodePublicSignals(entries[1].proof.publicSignals);
  console.log("     public:", JSON.stringify(decoded, null, 0).slice(0, 200));

  // Structural check, not a substring search. An earlier version of this test
  // searched the raw JSON for "548"/"2800", which false-failed roughly 1 run in
  // 4: those digit runs turn up by coincidence inside ~250 digits of random
  // field elements. Assert the actual property instead.
  const signals = entries[1].proof.publicSignals;
  check("exactly 6 public signals", signals.length === 6);
  check("the score is not among the public signals",
    !signals.some((s) => BigInt(s) === 548n));
  check("the DTI is not among the public signals",
    !signals.some((s) => BigInt(s) === 2800n));
  // The inputs live inside a field-element commitment, so they are not
  // recoverable by inspection — only by someone holding the blinding salt.
  check("inputs are held in a field-element commitment, not in the clear",
    BigInt(decoded.inputCommit) > 2n ** 128n);
  check("decision is public", decoded.decision === "0");
  check("entryHash in proof binds to the log entry", decoded.entryHash === prover.toField(entries[1].entryHash));

  console.log("\n=== 5. the demo: someone edits the database ===");
  const tampered = JSON.parse(JSON.stringify(entries));
  tampered[1].decision = 1;            // flip a rejection into an approval
  tampered[1].reasonCode = 0;
  const v2 = chainLib.verifyChain(tampered);
  check("tampering is detected", !v2.ok);
  check("it names the altered entry", v2.defects.some((d) => d.seq === 1 && d.type === "CONTENT_ALTERED"), JSON.stringify(v2.defects));
  console.log("     defects:", v2.defects.map((d) => `[${d.type}] ${d.detail}`).join(" | "));

  console.log("\n=== 6. the circuit refuses to lie ===");
  // Ask for a proof of an APPROVE for someone who should be rejected.
  const salt = randomSalt();
  const commit = await inputCommit(500, 2800, salt);
  let lied = false;
  let err = "";
  try {
    await prover.prove(prover.buildWitness({
      score: 500, dti: 2800, salt,
      decision: 1, reasonCode: 0,
      inputCommit: commit,
      entryHash: chainLib.sha256hex("x"),
    }));
  } catch (e) {
    lied = true;
    err = (e.message || String(e)).slice(0, 120);
  }
  check("forging an approval is impossible, not just discouraged", lied, "no error thrown!");
  console.log("     witness generation refused:", err);

  // And a mismatched commitment (swapping in convenient inputs) must also fail.
  let commitLied = false;
  try {
    await prover.prove(prover.buildWitness({
      score: 700, dti: 2000, salt,
      decision: 1, reasonCode: 0,
      inputCommit: await inputCommit(500, 2800, salt), // commitment to different data
      entryHash: chainLib.sha256hex("y"),
    }));
  } catch (e) { commitLied = true; }
  check("a fake commitment breaks the proof", commitLied);

  console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
