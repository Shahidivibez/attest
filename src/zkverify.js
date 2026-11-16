/**
 * ATTEST · zkVerify anchoring via Kurier
 *
 * WHY THIS LAYER EXISTS
 * ---------------------
 * The hash chain proves the record is internally consistent. But "internally
 * consistent" is a claim about our own database. If we control the database and
 * the verifier, we control the story.
 *
 * Anchoring moves the claim outside our control: we submit the Groth16 proof to
 * zkVerify, it verifies the proof against the verification key we registered,
 * and the result is finalized on a public chain. Now the record we hold can be
 * compared against a record we published — and cannot edit.
 *
 * DEGRADED MODE
 * -------------
 * Without KURIER_API_KEY this module reports `mode: "local"` and anchors
 * nothing. That state is surfaced honestly in the UI and in the API rather than
 * being silently implied to be on-chain. An unanchored record is still
 * tamper-EVIDENT (the chain catches edits); it is not tamper-PROOF against the
 * operator. Those are different guarantees and we do not blur them.
 */
const API_URL = "https://api.kurier.xyz/api/v1";

function configured() {
  return Boolean(process.env.KURIER_API_KEY);
}

/** The verification key hash of our circuit, registered once on Kurier. */
function vkHash() {
  return process.env.ATTEST_VK_HASH || null;
}

/**
 * Submit a Groth16 proof to Kurier and poll until the job finalizes.
 * @returns {{mode:string, status:string, jobId?:string, txHash?:string, error?:string}}
 */
async function anchorProof({ proof, publicSignals }) {
  if (!configured()) {
    // Say so plainly. Never dress a local result up as an on-chain fact.
    return {
      mode: "local",
      status: "not_anchored",
      note: "KURIER_API_KEY not set — proof verified locally only, not anchored on-chain",
    };
  }

  try {
    const res = await fetch(`${API_URL}/submit-proof/${process.env.KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: {
          proof,
          publicSignals,
          vk: vkHash(),
        },
      }),
    });

    if (!res.ok) {
      return {
        mode: "kurier",
        status: "submit_failed",
        error: `HTTP ${res.status} ${(await res.text()).slice(0, 200)}`,
      };
    }

    const job = await res.json();
    const jobId = job?.jobId || job?.id;

    // Poll to Finalized. "Included in a block" is not the same as final.
    const deadline = Date.now() + 90_000;
    while (jobId && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 3000));
      const s = await fetch(`${API_URL}/job-status/${jobId}`, {
        headers: { "x-api-key": process.env.KURIER_API_KEY },
      });
      if (!s.ok) continue;
      const status = await s.json();
      const state = status?.status || status?.jobStatus;
      if (state === "Finalized") {
        return { mode: "kurier", status: "finalized", jobId, txHash: status.txHash || status?.txHash };
      }
      if (state === "Failed" || state === "Rejected") {
        return { mode: "kurier", status: "failed", jobId, error: JSON.stringify(status).slice(0, 200) };
      }
    }

    return { mode: "kurier", status: "pending", jobId, note: "submitted, not yet finalized" };
  } catch (err) {
    return { mode: "kurier", status: "error", error: String(err.message || err).slice(0, 200) };
  }
}

module.exports = { anchorProof, configured, vkHash };
