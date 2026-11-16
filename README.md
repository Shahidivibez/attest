# ATTEST

**The audit log you cannot backdate.**

Every automated decision is sealed into a hash chain and carries a Groth16 zero-knowledge
proof that it followed the published policy — **without revealing the applicant's data**.

Built for the [zkVerify Agent Games](https://agentgames.zkverify.io) · Wildcard Track · Season 01.

---

## The problem

The EU AI Act now requires organisations deploying AI systems to keep automatically generated
records of their operation and produce them on demand (Art. 12, Art. 19). Every compliance team
is currently writing `.log` files to disk and calling it governance.

But **a log file is just a file.** After an incident — a bad loan denial, a discriminatory filter,
a wrong triage — the first question anyone asks is *"was this edited afterwards?"* and nobody can
answer it. The audit trail has exactly the same trust problem as the system it's auditing.

Two things follow, and most "AI governance" tooling solves neither:

1. **The record must be tamper-evident.** An operator with write access must not be able to
   rewrite history, even if they understand the scheme and recompute every hash.
2. **Proving compliance must not require exposing personal data.** "We applied the rule
   correctly" and "here is every applicant's income" should not be the same request. GDPR data
   minimisation and AI Act record-keeping are usually treated as a trade-off. They don't have
   to be.

---

## What this does

```
                       ┌──────────────────────────────┐
  applicant data ──────►│  policy engine (public rule) │
  (never stored)       └──────────────┬───────────────┘
                                      │ verdict
                                      ▼
                    ┌─────────────────────────────────────┐
                    │  hash chain (append-only, sealed)   │
                    │  entryₙ ──► entryₙ categorically    │
                    │      each entry commits to prev     │
                    └──────────────┬──────────────────────┘
                                   │ entryHash
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  policy.circom — 297 constraints    │
                    │  proves: decision == policy(inputs) │
                    │  reveals: verdict, not the inputs   │
                    └──────────────┬──────────────────────┘
                                   │ Groth16 proof
                                   ▼
                    ┌─────────────────────────────────────┐
                    │  zkVerify (Kurier) — anchored       │
                    │  claim leaves our infrastructure    │
                    └─────────────────────────────────────┘
```

### Three guarantees, layered

| Layer | Mechanism | Establishes | Cost |
|---|---|---|---|
| **Integrity** | SHA-256 hash chain | No entry was edited or removed | ~0 per decision |
| **Correctness** | Groth16 over `policy.circom` | The verdict followed the published rule — proven, not asserted | ~0.4 s |
| **Existence** | zkVerify anchor | The root existed in this state, outside our control | per-batch |

Each layer catches something the others don't. The chain catches a careless edit. The proof
catches an arbitrary decision. The anchor catches an operator who is careful.

---

## The demo

```
1. Baseline        chain INTACT · 6 decisions · all PROVEN
2. Edit history    flip entry #1 from REJECT to APPROVE
                   → CHAIN BROKEN · CONTENT_ALTERED · "entry 1 content does not
                     match its recorded hash — it was edited after being written"
3. Cover tracks    recompute every hash so the chain is internally consistent again
                   → STILL BROKEN · ROOT_MISMATCH · "chain root is 0x1765… but
                     0xf9ae… was anchored"
```

Step 3 is the point. A hash chain alone is defeated by an attacker who understands it. The
anchor is what makes the record something we can no longer change.

### Verify it yourself — `/verify.html`

The audit page asks you to trust our server. `/verify` doesn't.

It downloads the proof, public signals and verification key, then:

1. **Runs Groth16 verification in your browser** via `snarkjs`, locally — no round trip to us
2. **Re-derives the entry hash** with your browser's own Web Crypto SHA-256 and compares it to the
   recorded hash
3. **Checks the proof binds to this entry** — public signal `[5]` must equal this entry's hash
4. **Compares the chain root** against the root we published

If our server were lying about any of it, these checks fail in front of you. That's the difference
between a demo and a demonstration.

`test/verify-page.js` replays the page's exact logic (17 checks) so the in-browser path can't
silently rot. **36 checks total.**

### Public-demo safety

`POST /api/tamper` is exposed on a public URL, which is a footgun: a visitor flips an entry, walks
away, and the next visitor sees a broken record. So the demo:

- **self-heals** from a pristine snapshot after `DEMO_HEAL_MS` (default 90s)
- is **rate-limited** per IP (12 destructive ops/minute)
- can be **fully locked** with `TAMPER_LOCKED=1` + `x-demo-token`

The demo stays impressive and cannot be left vandalised.

---

## The circuit

`circuits/policy.circom` — 297 non-linear constraints, Groth16 / BN254, 6 public signals.

**Proves:** for a given entry, the decision recorded in it is the correct output of the published
policy applied to the private inputs committed in that same entry.

**Public:** `threshold`, `maxDti`, `decision`, `reasonCode`, `inputCommit`, `entryHash`
**Private:** `score`, `dti`, `salt`

Three enforcement points worth reading in the source:

- `commit.out === inputCommit` — stops a prover feeding the circuit convenient numbers while the
  log stores a different commitment.
- `decision === passAll` — an incorrect verdict cannot be *witnessed*. Forging an approval doesn't
  require detection; it fails mathematically.
- `reasonCode === scoreBelow * 1 + scorePass * dtiOver * 2` — the rule **order** is part of the
  policy. A failing score is reported as a score failure even when DTI would also fail. Collapsing
  the two would let an operator hide which rule actually did the rejecting.

The circuit doesn't ask the agent to be honest. It makes a wrong decision unrepresentable:

```
$ node test/smoke.js
  ok   forging an approval is impossible, not just discouraged
       witness generation refused: Error: Assert Failed. In template PolicyDecision line: 81
  ok   a fake commitment breaks the proof
=== RESULT: 19 passed, 0 failed ===
```

---

## Run it

```bash
npm install
npm start            # http://localhost:3000
npm test             # 16 end-to-end checks
```

Rebuild the circuit from scratch (needs [`circom`](https://docs.circom.io) 2.1.x on PATH):

```bash
npm run circuit:build     # compile → ceremony → groth16 setup → export vk
```

---

## Deploy

```bash
docker build -t attest .
docker run -p 3000:3000 attest
```

The circuit is **pre-built and committed** (`policy_final.zkey`, `policy.wasm`,
`verification_key.json`), so the image needs no `circom`, no Rust, and no ptau ceremony at build
time. `render.yaml` and `railway.json` are included.

| Env | Purpose |
|---|---|
| `PORT` | server port |
| `KURIER_API_KEY` | enables real on-chain anchoring; without it the app runs `mode: "local"` and says so |
| `ATTEST_VK_HASH` | our circuit's VK, registered on Kurier |
| `DEMO_HEAL_MS` | tamper self-heal window (default `90000`) |
| `TAMPER_LOCKED`, `DEMO_TOKEN` | lock the demo endpoints behind a token |
| `ATTEST_DATA_DIR` | where records are written (mount a volume to persist) |

**Cold starts matter here.** Free tiers sleep after inactivity, and a sleeping URL reads as a broken
submission. Keep an uptime ping on `/health` during the judging window.

## What is honestly *not* production-ready

I'd rather write this down than have a reviewer find it.

**1. The trusted setup is self-generated.** `npm run circuit:build` runs a power-12 ceremony
locally, which means **we hold the toxic waste.** A Groth16 setup where one party knows the trapdoor
can produce proofs of false statements. That is fine for a demo and unacceptable in production.
The path forward is a public multi-party ceremony (or a zkVerify-supported setup) with the
contribution hashes published. This is a single function swap, not a redesign.

**2. Anchoring is local by default.** Without `KURIER_API_KEY` the app runs in `mode: "local"`:
proofs are verified locally and **nothing is anchored on-chain**. The UI says so explicitly rather
than implying an on-chain guarantee it doesn't have. In that state the chain is tamper-*evident*
(it catches edits) but not tamper-*proof* against the operator (they control both the data and the
verifier). Those are different claims and it matters which one is true.

**3. The policy is a toy.** Two thresholds over two numbers. The mechanism generalises to real
policies — multiple weighted factors, regulatory thresholds, any deterministic rule — but this
specific circuit is a demonstration, not a credit engine.

**4. The demo tamper endpoint is an affordance, not a feature.** On a public URL it is guarded by
self-heal, rate limiting and an optional token, but it exists so reviewers can watch the system catch
an edit. In production there is no such endpoint — tampering happens outside the application, in the
database, which is exactly the threat model.

**5. The agent does not use an LLM, deliberately.** The decision is a deterministic rule, because
the thing being proven is rule-following and an LLM in the decision path would make the proof
meaningless. Where an LLM belongs in this product is drafting the *explanation* attached to a
decision — and that explanation should be proven to be derived from the same committed inputs.
That's the natural next version.

---

## Why zkVerify specifically

The chain and the proof are both things we could, in principle, run on our own server. That's
exactly the problem: a verifier we control is not a verifier.

Anchoring through zkVerify means the verification of our proof against our registered verification
key happens on public infrastructure, and finalizes there. The claim stops being "our system says
it's fine" and becomes "here is a finalized record that our system's proof verified" — checkable by
someone with no reason to trust us.

The AI Act asks organisations to *demonstrate* conformity. A record you can produce but also
retroactively edit is not a demonstration. That's the whole argument.

---

## Layout

```
circuits/policy.circom    the rule circuit — read this first
src/policy.js             the published policy, mirrors the circuit
src/chain.js              hash chain, canonical serialisation, verification
src/prover.js             witness building, proving, local verify, field mapping
src/zkverify.js           Kurier anchoring (degrades honestly when unconfigured)
src/store.js              decision store + separately-held anchor record
src/server.js             agent core, API, tamper endpoints
public/index.html         the audit UI
test/smoke.js             19 circuit/chain checks including the forgery attempts
test/verify-page.js       17 checks replaying the in-browser verification path
public/verify.html        independent verification, runs in the visitor's browser
```

---

## Licence

MIT.
