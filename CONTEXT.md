# CONTEXT.md - sim-doctor

Project decisions, open questions, and the milestone plan. This is the **why** behind the
repo. AGENTS.md is the **what**. Research citations are in [docs/research-report.md](docs/research-report.md).

---

## 1. Where this came from

The project started as an open-ended request: build a Rust SIM security testing tool that
covers the feature set of SIMTester, pySim, GlobalPlatform, SIMurai, YggdraSIM, and jCardSim,
plus the eUICC SGP.22 tools (virtual-rsp, euicc-rsp), with the CLI UX modelled on React
Doctor's agentic terminal pattern.

A research phase ran first. Three parallel subagents scanned the SIM tooling landscape,
reverse-engineered the React Doctor CLI, and resolved the Rust dependency set. Two of those
subagents failed - see section 2 - and the whole output was re-verified by a second round of
three focused agents. The consolidated result is docs/research-report.md.

That second round mattered. First-pass research had **4 of 7 repo names wrong** and one
fabricated claim. Every fact in AGENTS.md section 5 is from the verified second round.

---

## 2. Process notes - what went wrong, so it does not repeat

Worth recording because the failures were instructive and cost real time.

**GitHub API rate limits (403) starved one agent.** It ran out of unauthenticated API budget
partway through and crashed with no output. The fix: `git clone` / `git ls-remote` / raw file
fetch never touch the API rate limiter. **Use git transport for repo access, not the API.**
This closed three gaps that the API-limited pass had left open.

**One agent completed its research but never emitted output.** It announced "here is the
deliverable" three times and produced nothing on interruption. A replacement agent redoing the
same query from scratch got a complete answer in one turn. The pattern that fixed it:

- instruct the agent that its **reply is the deliverable** - no handoff message
- require the reply to **begin with data**, no preamble
- bound retries on failed fetches ("on 403/404, note it and move on, max twice")

**Inflated confidence tags.** A first-pass agent tagged nearly everything `[VERIFIED]` while
its own blockers section admitted the research was truncated. `Verified` had to be redefined as
*read in a primary source in this session*, not *recalled*. See AGENTS.md section 1.

**Harness quirk:** the `run_code` harness rejects template literals containing certain
punctuation (em dash among them). Use the write tool for file content rather than shell
heredocs inside template literals.

---

## 3. Decisions made

| Decision | Rationale |
|---|---|
| Name: **sim-doctor** | "doctor" mirrors React Doctor's diagnostic framing |
| Agent-first CLI, TUI secondary | The stated goal was agentic UX; TUI is a view over the same data |
| Rust | Requested; also the right fit for a static binary with strong crypto ecosystem |
| MIT | Chosen by owner - maximum reuse, including closed-source and commercial |
| `iso7816-tlv` over `der` for BER-TLV | `der` is strict DER and rejects real SIM BER lengths |
| Development loop uses swSIM + swicc-pcsc | No hardware prerequisite for the test suite |
| JSON envelope modelled on `lpac` | Best existing agent-friendly contract found |
| **TS.48 in scope as a RUNNER, not transcribed profiles** | Owner decision. The profile definitions sit behind the same GSMA member login as SGP.22, so we build the executor that consumes operator-supplied profile files and stop there. Progress without pretending to spec access |
| **No GSMA member access** | Owner decision. Every SGP.22 / TS.48 section number is provenance-backed from `euicc-rsp` source comments, never primary. Label accordingly, permanently |
| **swSIM only, no physical reader for now** | Owner decision. Real-reader testing stays available later as a second fixture, not a redesign |
| **Autonomous PR merging** | Owner decision. A subagent may implement, test, self-review and open a PR; it may **not** merge. An orchestrator verifies then merges |
| **Serial, dependency-ordered delivery** | Owner decision. M1 is a strict chain, so parallel agents would collide on the contract and drift from it. Fan-out is deliberately rejected |

---

## 4. Milestone plan

### M1 - one end-to-end path that proves the whole stack

**Goal:** `PC/SC connect -> SELECT MF -> walk DF tree -> dump EF list -> JSON on stdout ->
correct exit code`

That single command touches transport, APDU types, TLV parsing, the clap surface, and the
output contract at once. When it works, every later feature is "another thing that emits
findings through a contract that already exists."

Steps:

1. `cargo build` to settle the `rand_core` question (AGENTS.md 4.4). Do this first - it is
   a 30-second check that determines whether ECC deps need adjusting.
2. Stand up swSIM + swicc-pcsc + pcscd as the test fixture.
3. Implement reader discovery, connect, SELECT MF, DF walk, EF enumeration.
4. Emit the JSON envelope. Exit 0 on success.

Do **not** start with a feature module. This slice has to come first.

### M2 - the agentic UX layer

Comes after M1 so there is real output to format. Rule IDs in `plugin/rule` form, severity
levels, `--json` / `--score`, exit codes 0/1/130/129, baseline + diff. See AGENTS.md section 3.

### M3 - feature modules

By value-per-effort:

1. Filesystem scanner (SIMTester's `-sf`, cheap and immediately useful)
2. TAR / MSL=0 audit
3. SCP02/03/11 mutual authentication
4. GlobalPlatform shell (API now mapped - AGENTS.md 5.5)
5. eUICC / LPA remote provisioning
6. Fuzzer - most expensive, most valuable, do last

---

## 5. Open questions

**Does TS.48 belong in scope?** ANSWERED - yes, as a runner. See section 3.

**Is GSMA member access available?** ANSWERED - no. See section 3.

**Hardware in the loop or not?** ANSWERED - swSIM only for now. See section 3.

These were the three questions this section used to carry. They are now decisions, and
the answers are recorded above. The one question that remains genuinely open is a scope
question for the end of M3: whether the TS.48 runner should also attempt to self-derive a
small set of smoke profiles from SIMTester behaviour, or stay strictly operator-supplied.
The current answer is strictly operator-supplied, because self-derived profiles would be
tagged `[U]` and would create a false impression of conformance coverage.

---

## 6. First actions

```
cd sim-doctor
cargo build                       # DONE - settled rand_core, see section 7
# stand up swSIM + swicc-pcsc, then:
sim-doctor scan --json             # M1 acceptance test
```

---

## 7. Delivery loop

Work is tracked as GitHub issues and delivered one at a time, in dependency order.

| Stage | What | Gate |
|---|---|---|
| Phase 0 | CI, crate skeleton, resolved-fact docs, swSIM fixture | CI green on `main` |
| Phase 1 | transport, APDU, TLV, walker, contract, CLI | M1 acceptance passes |
| Phase 2 | rule model, severity/score, baseline/diff, TUI | contract stable |
| Phase 3 | the six feature modules, fuzzer last | each module emits findings through the contract |
| Phase 4 | TS.48 runner | runner executes an operator-supplied profile |

Per issue, one subagent: branch, implement, verify locally, self-review the diff, open a PR,
watch CI. Then the orchestrator verifies independently and merges. A subagent never merges.

Process rules the loop depends on:

- CI runs `--locked`, so any dependency change must commit `Cargo.lock` in the same commit.
- Do not trust `gh pr view --json files` mid-run; its merge base can be stale. Use `git diff`.
- A subagent that runs long gets re-dispatched in the background. Foreground dispatch has a
  hard 600s ceiling and will truncate work that was nearly finished.
- Blocked items stay open with their unblock path written down. They are never silently dropped.
