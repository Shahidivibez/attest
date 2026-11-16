/**
 * ATTEST — attested decision log
 *
 * Three jobs:
 *   1. Run the decision agent; seal every decision into the hash chain with a
 *      Groth16 proof that it followed the published policy.
 *   2. Serve the audit UI and an independent verification page.
 *   3. Run the tamper demo — safely, on a public URL.
 *
 * PUBLIC-DEMO SAFETY
 * ------------------
 * This app is deployed to a public URL where anyone can click "tamper". An
 * unprotected tamper endpoint is a footgun: a visitor flips an entry, walks
 * away, and the next visitor (or judge) sees a broken record.
 *
 * So: tampering self-heals from a pristine snapshot (`DEMO_HEAL_MS`, default
 * 90s), is rate-limited per IP, and can be locked behind a token entirely
 * (`TAMPER_LOCKED=1`). The demo stays impressive and cannot be left vandalised.
 */
const express = require("express");
const path = require("path");

const { evaluate, POLICY, REASON } = require("./policy");
const { inputCommit, randomSalt } = require("./poseidon");
const chainLib = require("./chain");
const prover = require("./prover");
const zkverify = require("./zkverify");
const store = require("./store");

const PORT = process.env.PORT || 3000;
const HEAL_MS = Number(process.env.DEMO_HEAL_MS || 90_000);
const TAMPER_LOCKED = process.env.TAMPER_LOCKED === "1";
const DEMO_TOKEN = process.env.DEMO_TOKEN || "";

const app = express();
app.use(express.json());

app.use(express.static(path.join(__dirname, "..", "public")));

// Serve the snarkjs browser bundle so proofs can be verified client-side,
// in the visitor's browser, without trusting this server.
app.get("/vendor/snarkjs.min.js", (req, res) => {
  res.type("application/javascript").sendFile(
    path.join(__dirname, "..", "node_modules", "snarkjs", "build", "snarkjs.min.js")
  );
});

/* ------------------------------------------------------------------ */
/* self-healing demo state                                             */
/* ------------------------------------------------------------------ */

/** Restore the last known-good record if a tamper demo has been left running. */
function maybeHeal() {
  const meta = store.loadMeta();
  if (!meta.tamperedAt) return false;
  if (Date.now() - meta.tamperedAt < HEAL_MS) return false;

  const pristine = store.loadPristine();
  if (pristine) {
    store.saveEntries(pristine.entries);
    store.saveAnchors(pristine.anchors);
  }
  store.patchMeta({ tamperedAt: null, tamperSeq: null, healedAt: Date.now() });
  console.log("[attest] self-healed demo record after tamper window");
  return true;
}

function snapshotPristine() {
  store.savePristine({ entries: store.loadEntries(), anchors: store.loadAnchors() });
}

/** Tiny in-memory per-IP limiter so one visitor cannot churn the demo. */
const hits = new Map();
function limited(ip, max = 12, windowMs = 60_000) {
  const now = Date.now();
  const rec = hits.get(ip) || { count: 0, reset: now + windowMs };
  if (now > rec.reset) {
    rec.count = 0;
    rec.reset = now + windowMs;
  }
  rec.count++;
  hits.set(ip, rec);
  // occasionally prune so the map cannot grow without bound
  if (hits.size > 5000) hits.clear();
  return rec.count > max;
}

/** Gate for the destructive demo endpoints. */
function tamperGate(req, res, next) {
  if (TAMPER_LOCKED && req.get("x-demo-token") !== DEMO_TOKEN) {
    return res.status(401).json({ error: "demo endpoints locked", hint: "send x-demo-token" });
  }
  if (limited(req.ip)) {
    return res.status(429).json({ error: "too many demo operations, wait a minute" });
  }
  next();
}

/* ------------------------------------------------------------------ */
/* agent core                                                          */
/* ------------------------------------------------------------------ */

async function decide({ score, dti, subject = null }) {
  // Never append to a tampered record — the new entry would be sealed against
  // a history that has already been rewritten.
  maybeHeal();
  const meta = store.loadMeta();
  if (meta.tamperedAt) {
    const pristine = store.loadPristine();
    if (pristine) {
      store.saveEntries(pristine.entries);
      store.saveAnchors(pristine.anchors);
      store.patchMeta({ tamperedAt: null, tamperSeq: null, healedAt: Date.now() });
    }
  }

  const entries = store.loadEntries();
  const verdict = evaluate({ score, dti });

  const salt = randomSalt();
  const commit = await inputCommit(score, dti, salt);

  // 1. seal into the chain BEFORE proving, so the proof binds to this hash
  const entry = chainLib.append(entries, {
    inputCommit: commit,
    policyId: POLICY.id,
    policyParams: { threshold: POLICY.threshold, maxDti: POLICY.maxDti },
    decision: verdict.decision,
    reasonCode: verdict.reasonCode,
  });
  entries.push(entry);

  // 2. prove the sealed entry
  let proofResult;
  try {
    const witness = prover.buildWitness({
      score, dti, salt,
      decision: verdict.decision,
      reasonCode: verdict.reasonCode,
      inputCommit: commit,
      entryHash: entry.entryHash,
    });
    const { proof, publicSignals } = await prover.prove(witness);
    if (!(await prover.verifyLocally(proof, publicSignals))) {
      throw new Error("local verification failed");
    }
    const anchor = await zkverify.anchorProof({ proof, publicSignals });
    proofResult = { status: "proven", proof, publicSignals, anchor };
  } catch (err) {
    // Fail closed: an entry that cannot be proven is recorded as unproven,
    // never quietly marked as fine.
    proofResult = {
      status: "unproven",
      error: String(err.message || err).slice(0, 300),
      anchor: { mode: "none", status: "not_anchored" },
    };
  }

  entry.proof = proofResult;
  entry.subject = subject;
  store.saveEntries(entries);

  // 3. publish the new root. Deliberately a separate file from the record.
  const anchors = store.loadAnchors();
  anchors.push({
    at: new Date().toISOString(),
    root: chainLib.computeRoot(entries),
    length: entries.length,
    mode: proofResult.anchor?.mode || "local",
    status: proofResult.anchor?.status || "not_anchored",
    network: proofResult.anchor?.network || null,
  });
  store.saveAnchors(anchors);
  snapshotPristine();

  return { entry, verdict };
}

/* ------------------------------------------------------------------ */
/* read API                                                            */
/* ------------------------------------------------------------------ */

app.get("/api/state", (req, res) => {
  maybeHeal();
  const entries = store.loadEntries();
  const anchor = store.latestAnchor();
  const meta = store.loadMeta();

  // Verify the record we hold against the root we last published.
  const probe = JSON.parse(JSON.stringify(entries));
  if (probe.length && anchor) probe[0].__storedRoot = anchor.root;
  const chain = chainLib.verifyChain(probe);

  res.json({
    policy: POLICY,
    entries,
    chain,
    anchor,
    stats: {
      total: entries.length,
      proven: entries.filter((e) => e.proof?.status === "proven").length,
      unproven: entries.filter((e) => e.proof?.status !== "proven").length,
      anchored: entries.filter((e) => e.proof?.anchor?.status === "finalized").length,
      approved: entries.filter((e) => e.decision === 1).length,
      rejected: entries.filter((e) => e.decision === 0).length,
    },
    demo: {
      tampered: Boolean(meta.tamperedAt),
      tamperedAt: meta.tamperedAt || null,
      tamperSeq: meta.tamperSeq ?? null,
      healMs: HEAL_MS,
      healInMs: meta.tamperedAt ? Math.max(0, HEAL_MS - (Date.now() - meta.tamperedAt)) : null,
      locked: TAMPER_LOCKED,
    },
    zkverify: { configured: zkverify.configured(), ...zkverify.network() },
  });
});

app.get("/api/verify", (req, res) => {
  maybeHeal();
  const entries = store.loadEntries();
  const anchor = store.latestAnchor();
  const probe = JSON.parse(JSON.stringify(entries));
  if (probe.length && anchor) probe[0].__storedRoot = anchor.root;
  res.json({ chain: chainLib.verifyChain(probe), anchor });
});

/**
 * Everything a third party needs to verify a decision WITHOUT trusting us:
 * the raw proof, the public signals, the verification key, and the entry's
 * position in the chain. /verify does the checking in the visitor's browser.
 */
app.get("/api/proof/:seq", (req, res) => {
  const seq = Number(req.params.seq);
  const entries = store.loadEntries();
  const entry = entries.find((e) => e.seq === seq);
  if (!entry) return res.status(404).json({ error: `no entry with seq ${seq}` });

  const anchor = store.latestAnchor();
  const probe = JSON.parse(JSON.stringify(entries));
  if (probe.length && anchor) probe[0].__storedRoot = anchor.root;
  const chain = chainLib.verifyChain(probe);

  res.json({
    entry,
    vk: require(prover.paths.VK),
    chain: { ok: chain.ok, defects: chain.defects, root: chain.root, length: chain.length },
    anchor,
    policy: POLICY,
    signalLayout: prover.PUBLIC_SIGNAL_LAYOUT,
  });
});

/* ------------------------------------------------------------------ */
/* write API                                                           */
/* ------------------------------------------------------------------ */

app.post("/api/decide", async (req, res) => {
  try {
    const score = Number(req.body?.score);
    const dti = Number(req.body?.dti);
    if (!Number.isFinite(score) || !Number.isFinite(dti)) {
      return res.status(400).json({ error: "score and dti must be numbers" });
    }
    if (score < 0 || score > 1000 || dti < 0 || dti > 20000) {
      return res.status(400).json({ error: "score must be 0-1000, dti 0-20000" });
    }
    const { entry, verdict } = await decide({ score, dti, subject: req.body?.subject });
    res.json({ entry, verdict });
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

/**
 * THE DEMO — stage 1.
 *
 * Simulates an operator with write access editing history: a rejection becomes
 * an approval. Implemented as a raw write because that is what an attacker
 * would actually do. The stored hash is left stale, as it would be in reality.
 */
app.post("/api/tamper", tamperGate, (req, res) => {
  const entries = store.loadEntries();
  if (!entries.length) return res.status(409).json({ error: "record is empty" });

  const seq = Number(req.body?.seq ?? 1);
  const target = entries.find((e) => e.seq === seq);
  if (!target) return res.status(404).json({ error: `no entry with seq ${seq}` });

  if (target.decision === 1) {
    target.decision = 0;
    target.reasonCode = REASON.SCORE_BELOW_THRESHOLD;
  } else {
    target.decision = 1;
    target.reasonCode = REASON.APPROVED;
  }
  store.saveEntries(entries);
  store.patchMeta({ tamperedAt: Date.now(), tamperSeq: seq });

  res.json({
    tampered: seq,
    changedTo: target.decision === 1 ? "APPROVE" : "REJECT",
    note: "entry rewritten; stored hash left stale",
    healsInMs: HEAL_MS,
  });
});

/**
 * THE DEMO — stage 2.
 *
 * The sophisticated attacker: recompute this entry's hash and every link after
 * it, so the chain is internally consistent again. Still caught, because the
 * root we published lives in a different file.
 */
app.post("/api/tamper/reseal", tamperGate, (req, res) => {
  const entries = store.loadEntries();
  if (!entries.length) return res.status(409).json({ error: "record is empty" });

  const seq = Number(req.body?.seq ?? 1);
  const idx = entries.findIndex((e) => e.seq === seq);
  if (idx === -1) return res.status(404).json({ error: `no entry with seq ${seq}` });

  let prev = idx === 0 ? chainLib.GENESIS : entries[idx - 1].entryHash;
  for (let i = idx; i < entries.length; i++) {
    entries[i].prevHash = prev;
    entries[i].entryHash = chainLib.entryHash(entries[i]);
    prev = entries[i].entryHash;
  }
  store.saveEntries(entries);
  store.patchMeta({ tamperedAt: Date.now(), tamperSeq: seq });

  res.json({ resealed: true, fromSeq: seq, note: "chain recomputed end-to-end", healsInMs: HEAL_MS });
});

app.post("/api/reset", tamperGate, async (req, res) => {
  store.saveEntries([]);
  store.saveAnchors([]);
  store.savePristine(null);
  store.patchMeta({ tamperedAt: null, tamperSeq: null });
  const seeded = await seed();
  res.json({ ok: true, seeded: seeded.length });
});

/* ------------------------------------------------------------------ */
/* boot                                                                */
/* ------------------------------------------------------------------ */

const SEED = [
  { score: 712, dti: 3100 },
  { score: 548, dti: 2800 },
  { score: 690, dti: 4890 },
  { score: 820, dti: 1900 },
  { score: 634, dti: 4100 },
  { score: 571, dti: 3350 },
];

async function seed() {
  for (const s of SEED) await decide(s);
  return SEED;
}

app.get("/health", (req, res) =>
  res.json({
    ok: true,
    service: "attest",
    entries: store.loadEntries().length,
    zkverify: zkverify.configured() ? zkverify.network().network : "local",
  })
);

async function boot() {
  store.patchMeta({ bootedAt: Date.now() });

  if (store.loadEntries().length === 0) {
    console.log("[attest] empty store — seeding demo decisions");
    await seed();
  } else {
    // A cold start on an ephemeral filesystem can leave decisions.json but no
    // pristine snapshot. Rebuild it so self-healing still works.
    if (!store.loadPristine()) {
      console.log("[attest] no pristine snapshot — rebuilding");
      snapshotPristine();
    }
    // If we booted mid-tamper, do not present a broken record.
    const meta = store.loadMeta();
    if (meta.tamperedAt) {
      const pristine = store.loadPristine();
      if (pristine) {
        store.saveEntries(pristine.entries);
        store.saveAnchors(pristine.anchors);
      }
      store.patchMeta({ tamperedAt: null, tamperSeq: null });
      console.log("[attest] cleared tamper state from previous run");
    }
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[attest] listening on http://0.0.0.0:${PORT}`);
    console.log(`[attest] data dir: ${store.DATA_DIR}`);
    if (zkverify.configured()) {
      const n = zkverify.network();
      console.log(`[attest] zkVerify: Kurier configured -> ${n.network} (${n.baseUrl})`);
      // Register the circuit's VK up front so the first decision is not slowed
      // by a registration round trip.
      zkverify.ensureVkRegistered().catch((e) => console.log(`[attest] VK pre-registration failed: ${e.message}`));
    } else {
      console.log(`[attest] zkVerify: LOCAL only (set KURIER_API_KEY to anchor on-chain)`);
    }
    console.log(`[attest] tamper demo: ${TAMPER_LOCKED ? "locked behind token" : "open, self-heals in " + HEAL_MS / 1000 + "s"}`);
  });
}

if (require.main === module) boot();

module.exports = { app, decide };
