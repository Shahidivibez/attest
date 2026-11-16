pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";

/*
  ATTEST · policy.circom

  WHAT THIS CIRCUIT PROVES
  ------------------------
  For a given log entry, the decision recorded in that entry is the correct
  output of the published policy applied to the private inputs committed in
  that same entry.

  Why it matters: an auditor can check that we were not arbitrary, WITHOUT us
  handing over the applicant's score or income. The policy is public, the
  verdict is public, the reasoning is checkable, and the personal data stays
  private. That is the whole point — GDPR data minimisation and AI Act
  record-keeping, satisfied at the same time.

  STATEMENT (public signals)
  --------------------------
    [0] threshold    policy: minimum acceptable score
    [1] maxDti       policy: maximum acceptable debt-to-income (basis points)
    [2] decision     1 = APPROVE, 0 = REJECT
    [3] reasonCode   0 = APPROVED, 1 = SCORE_BELOW_THRESHOLD, 2 = DTI_EXCEEDED
    [4] inputCommit  Poseidon(score, dti, salt) — binds to the stored entry
    [5] entryHash    binds this proof to one specific link in the hash chain

  PRIVATE INPUTS
  --------------
    score, dti  the applicant's data — never revealed
    salt        32-byte blinding value, so the commitment can't be brute-forced

  The circuit does not ask the agent to be honest. It makes an incorrect
  decision unrepresentable: if the recorded decision disagrees with the policy,
  witness generation fails and no proof exists.
*/

template PolicyDecision() {
    // ---- private inputs -------------------------------------------------
    signal input score;      // 0..1000
    signal input dti;        // basis points, 0..10000
    signal input salt;       // field element blinding factor

    // ---- public inputs --------------------------------------------------
    signal input threshold;   // policy parameter
    signal input maxDti;      // policy parameter
    signal input decision;    // claimed outcome
    signal input reasonCode;  // claimed reason
    signal input inputCommit; // claimed commitment to (score, dti, salt)
    signal input entryHash;   // claimed chain entry this proof belongs to

    // ---- 1. the commitment must match the private inputs ----------------
    // Without this, a prover could feed the circuit convenient numbers while
    // the log stores a different commitment, and the two would silently diverge.
    component commit = Poseidon(3);
    commit.inputs[0] <== score;
    commit.inputs[1] <== dti;
    commit.inputs[2] <== salt;
    commit.out === inputCommit;

    // ---- 2. evaluate the published policy -------------------------------
    component scoreBelow = LessThan(16);   // 1 if score <  threshold
    scoreBelow.in[0] <== score;
    scoreBelow.in[1] <== threshold;

    component dtiOver = GreaterThan(16);   // 1 if dti   >  maxDti
    dtiOver.in[0] <== dti;
    dtiOver.in[1] <== maxDti;

    // ---- 3. derive the one correct verdict ------------------------------
    signal scorePass;
    scorePass <== 1 - scoreBelow.out;

    signal passAll;
    passAll <== scorePass * (1 - dtiOver.out);   // 1 only if both checks pass

    // The recorded decision must equal the derived one. This is an ===, not a
    // constraint on a free variable: a wrong decision cannot be witnessed.
    decision === passAll;

    // ---- 4. and the reason must match the ordered rule ------------------
    // Rule order is part of the policy: a failing score is reported as a score
    // failure even if DTI would also fail. Collapsing these two into one code
    // would let an operator hide which rule actually did the rejecting.
    reasonCode === scoreBelow.out * 1 + scorePass * dtiOver.out * 2;

    // entryHash is carried through unconstrained by design: it is a binding
    // tag, not a computed quantity. The verifier checks it against the chain
    // out-of-band, and requires it to equal the entry being audited.
}

/*
  Declaration order below sets the order of the public signals array, which
  snarkjs returns as:
    [threshold, maxDti, decision, reasonCode, inputCommit, entryHash]

  Everything not listed stays private forever: score, dti, salt.
*/
component main {public [threshold, maxDti, decision, reasonCode, inputCommit, entryHash]} = PolicyDecision();
