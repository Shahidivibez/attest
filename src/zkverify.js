/**
 * ATTEST · zkVerify anchoring via Kurier
 *
 * WHY THIS LAYER EXISTS
 * ---------------------
 * The hash chain proves the record is internally consistent. But "internally
 * consistent" is a claim about our own database. If we control the database and
 * the verifier, we control the story.
 *
 * Anchoring moves the claim outside our control: the Groth16 proof is submitted
 * to zkVerify, verified there against the verification key registered for this
 * circuit, and finalised on a public chain. The record we hold can then be
 * compared against a record we published and can no longer edit.
 *
 * NETWORKS
 * --------
 *   testnet → https://api-testnet.kurier.xyz/api/v1   FREE, full parity
 *   mainnet → https://api.kurier.xyz/api/v1           $0.005 per proof,
 *                                                     $0.001 per VK, paid in
 *                                                     USDC on Base via x402
 *
 * Set KURIER_API_URL to choose. Defaults to testnet because it costs nothing
 * and proves exactly the same thing.
 *
 * DEGRADED MODE
 * -------------
 * Without KURIER_API_KEY nothing is anchored, and we say so — in the API, in
 * the UI, and in the README. An unanchored record is still tamper-EVIDENT (the
 * chain catches edits); it is not tamper-PROOF against the operator. Those are
 * different guarantees and we do not blur them.
 */
const BASE_URL = process.env.KURIER_API_URL || "https://api-testnet.kurier.xyz/api/v1";

const NETWORK = BASE_URL.includes("testnet") ? "zkVerify testnet" : "zkVerify mainnet";

function configured() {
  return Boolean(process.env.KURIER_API_KEY);
}

function network() {
  return { baseUrl: BASE_URL, network: NETWORK, isTestnet: NETWORK.includes("testnet") };
}

let cachedVkHash = null;

/**
 * Register this circuit's verification key, or reuse one from the environment.
 *
 * Kurier registers a VK per circuit and returns a vkHash; subsequent proof
 * submissions reference that short hash instead of resending the whole key.
 * We do this lazily on first use so a fresh deployment needs nothing but an
 * API key in the environment — no terminal, no manual registration step.
 */
async function ensureVkRegistered() {
  if (cachedVkHash) return cachedVkHash;
  if (process.env.ATTEST_VK_HASH) {
    cachedVkHash = process.env.ATTEST_VK_HASH;
    return cachedVkHash;
  }

  const vk = require("../circuits/build/verification_key.json");
  const res = await fetch(`${BASE_URL}/register-vk/${process.env.KURIER_API_KEY}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      proofType: "groth16",
      proofOptions: { library: "snarkjs", curve: "bn128" },
      vk,
    }),
  });

  if (!res.ok) {
    const body = (await res.text()).slice(0, 300);
    throw new Error(`VK registration failed (HTTP ${res.status}): ${body}`);
  }

  const json = await res.json();
  if (!json.vkHash) throw new Error(`VK registration returned no vkHash: ${JSON.stringify(json).slice(0, 200)}`);

  cachedVkHash = json.vkHash;
  console.log(`[attest] VK registered on ${NETWORK}: ${cachedVkHash}`);
  if (json.warnings && json.warnings.length) {
    console.log(`[attest] registration warnings: ${json.warnings.join("; ")}`);
  }
  return cachedVkHash;
}

const FINAL_STATES = new Set(["finalized", "finalised", "completed", "success", "includedandfinalized"]);
const FAILED_STATES = new Set(["failed", "rejected", "error", "invalid"]);

/**
 * Submit a Groth16 proof and poll until it finalises.
 * @returns {{mode:string,status:string,jobId?:string,txHash?:string,error?:string}}
 */
async function anchorProof({ proof, publicSignals }) {
  if (!configured()) {
    return {
      mode: "local",
      status: "not_anchored",
      note: "KURIER_API_KEY not set — verified locally only, not anchored on-chain",
    };
  }

  try {
    const vkHash = await ensureVkRegistered();

    const submit = await fetch(`${BASE_URL}/submit-proof/${process.env.KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: vkHash },
      }),
    });

    if (submit.status === 402) {
      return {
        mode: "kurier",
        status: "payment_required",
        error:
          "mainnet requires x402 payment ($0.005/proof in USDC on Base). " +
          "Use the free testnet for the demo, or fund a wallet to settle on mainnet.",
      };
    }

    if (!submit.ok) {
      return {
        mode: "kurier",
        status: "submit_failed",
        error: `HTTP ${submit.status} ${(await submit.text()).slice(0, 300)}`,
      };
    }

    const job = await submit.json();
    const jobId = job.jobId || job.jobID || job.id;

    if (job.optimisticVerify === false) {
      return { mode: "kurier", status: "rejected_optimistically", jobId, error: "Kurier's optimistic verify rejected the proof" };
    }

    // Poll to a final state. "Included in a block" is not the same as final.
    const deadline = Date.now() + 120_000;
    let last = "submitted";
    while (jobId && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 4000));
      const s = await fetch(`${BASE_URL}/job-status/${process.env.KURIER_API_KEY}/${jobId}`);
      if (!s.ok) continue;
      const status = await s.json();
      last = String(status.status || "").toLowerCase();

      if (FINAL_STATES.has(last)) {
        return {
          mode: "kurier",
          status: "finalized",
          jobId,
          network: NETWORK,
          txHash: status.txHash || status.transactionHash || status.extrinsicHash || null,
        };
      }
      if (FAILED_STATES.has(last)) {
        return { mode: "kurier", status: "failed", jobId, error: JSON.stringify(status).slice(0, 300) };
      }
    }

    return {
      mode: "kurier",
      status: "pending",
      jobId,
      network: NETWORK,
      note: `submitted, last state "${last}" — not yet final`,
    };
  } catch (err) {
    return { mode: "kurier", status: "error", error: String(err.message || err).slice(0, 300) };
  }
}

module.exports = { anchorProof, configured, network, ensureVkRegistered };
