/**
 * ATTEST · policy engine
 *
 * The published policy. Deterministic, ordered, and identical to what
 * circuits/policy.circom enforces. If these two ever disagree, the agent
 * cannot produce a proof — which is the safety property, not a bug.
 *
 * Rule order matters: a failing score is reported as a score failure even when
 * DTI would also fail. Collapsing the two would let an operator hide which rule
 * actually did the rejecting.
 */

const REASON = {
  APPROVED: 0,
  SCORE_BELOW_THRESHOLD: 1,
  DTI_EXCEEDED: 2,
};

const DECISION = { REJECT: 0, APPROVE: 1 };

// The published policy parameters. Public by design — an auditor must be able
// to see the rule to judge whether a decision followed it.
const POLICY = {
  id: "attest.consumer-credit.v1",
  threshold: 620, // minimum acceptable score
  maxDti: 4200,   // maximum debt-to-income, in basis points (42.00%)
};

/**
 * Apply the policy. Mirrors policy.circom exactly.
 * @returns {{decision:number, reasonCode:number, decisionLabel:string, reasonLabel:string}}
 */
function evaluate({ score, dti }, policy = POLICY) {
  if (score < policy.threshold) {
    return {
      decision: DECISION.REJECT,
      reasonCode: REASON.SCORE_BELOW_THRESHOLD,
      decisionLabel: "REJECT",
      reasonLabel: "SCORE_BELOW_THRESHOLD",
    };
  }
  if (dti > policy.maxDti) {
    return {
      decision: DECISION.REJECT,
      reasonCode: REASON.DTI_EXCEEDED,
      decisionLabel: "REJECT",
      reasonLabel: "DTI_EXCEEDED",
    };
  }
  return {
    decision: DECISION.APPROVE,
    reasonCode: REASON.APPROVED,
    decisionLabel: "APPROVE",
    reasonLabel: "APPROVED",
  };
}

module.exports = { evaluate, POLICY, REASON, DECISION };
