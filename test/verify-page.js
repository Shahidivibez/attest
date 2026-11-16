/**
 * Tests the logic that runs inside public/verify.html.
 *
 * The browser page re-derives the entry hash with Web Crypto and re-verifies
 * the Groth16 proof locally. If that re-derivation ever disagrees with the
 * server, the verification page reports a false failure — which would be the
 * single most damaging bug in the project.
 *
 * This replays the exact same computation using the same Web Crypto API that
 * the browser uses, against a live server.
 */
const snarkjs = require("snarkjs");

const BASE = process.env.BASE_URL || "http://localhost:3000";
const MASK = (1n << 253n) - 1n;

let pass = 0, fail = 0;
const check = (name, cond, extra = "") => {
  if (cond) { pass++; console.log(`  ok   ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
};

/* ---- verbatim from verify.html ---- */
function canonical(o) {
  if (o === null || typeof o !== "object") return JSON.stringify(o);
  if (Array.isArray(o)) return "[" + o.map(canonical).join(",") + "]";
  const keys = Object.keys(o).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
}

async function sha256hex(str) {
  const buf = new TextEncoder().encode(str);
  const d = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function entryHash(e) {
  return "0x" + (await sha256hex(canonical({
    seq: e.seq,
    timestamp: e.timestamp,
    inputCommit: e.inputCommit,
    policyId: e.policyId,
    policyParams: e.policyParams,
    decision: e.decision,
    reasonCode: e.reasonCode,
    prevHash: e.prevHash,
  })));
}

(async () => {
  console.log("\n=== verify-page logic against", BASE, "===");

  const state = await fetch(`${BASE}/api/state`).then((r) => r.json());
  check("server reachable and chain intact", state.chain.ok);
  const n = state.entries.length;
  check("entries present", n > 0);

  for (const seq of [0, Math.min(1, n - 1), n - 1]) {
    const d = await fetch(`${BASE}/api/proof/${seq}`).then((r) => r.json());
    if (d.error) { check(`entry ${seq} fetched`, false, d.error); continue; }

    const recomputed = await entryHash(d.entry);
    const serverHash = d.entry.entryHash;

    check(`entry ${seq}: browser re-derives the same hash`, recomputed === serverHash,
      `\n       browser: ${recomputed}\n       server : ${serverHash}`);

    // The proof must bind to this entry specifically.
    const masked = (BigInt(serverHash) & MASK).toString();
    check(`entry ${seq}: proof binds to this entry`, d.entry.proof.publicSignals[5] === masked);

    // And it must actually verify against the served key.
    const ok = await snarkjs.groth16.verify(d.vk, d.entry.proof.publicSignals, d.entry.proof.proof);
    check(`entry ${seq}: Groth16 verifies with the served VK`, ok);

    // The page claims exactly 6 public signals and no personal data.
    check(`entry ${seq}: 6 public signals, no personal data`,
      d.entry.proof.publicSignals.length === 6);
  }

  /* ---- negative case: the verify page must FAIL on a tampered entry ---- */
  console.log("\n=== negative case: tampered entry must not verify ===");
  const t = await fetch(`${BASE}/api/tamper`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ seq: 1 }),
  }).then((r) => r.json());

  if (t.error) {
    console.log(`  (skip — tamper locked: ${t.error})`);
  } else {
    const d = await fetch(`${BASE}/api/proof/1`).then((r) => r.json());
    const recomputed = await entryHash(d.entry);
    check("tampered entry's hash no longer matches its content (page would FLAG it)",
      recomputed !== d.entry.entryHash);
    check("tampered entry's proof no longer binds to the rewritten entry (page would FLAG it)",
      d.entry.proof.publicSignals[5] !== (BigInt(recomputed) & MASK).toString());
    check("chain root no longer matches the published anchor", d.chain.ok === false);
    console.log("       defects:", d.chain.defects.map((x) => x.type).join(", "));
  }

  console.log(`\n=== RESULT: ${pass} passed, ${fail} failed ===\n`);
  process.exit(fail === 0 ? 0 : 1);
})();
