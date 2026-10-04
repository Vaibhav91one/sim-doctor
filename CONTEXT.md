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

**Does TS.48 belong in scope?** It was in the original brief and has zero coverage. It is
conformance test profiles rather than a tool feature, so it likely wants its own workstream
and would reorder M3. This needs a decision before M3 planning.

**Is GSMA member access available?** Blocks primary verification of SGP.22 section numbers.
Without it, build against euicc-rsp source comments and treat 5.6 / 5.7 in AGENTS.md as
provenance-backed but not primary.

**Hardware in the loop or not?** M1 is designed for software-only. If real-reader testing
matters, it is a second fixture, not a redesign.

---

## 6. First actions

```
cd sim-doctor
cargo build                       # settles rand_core alignment
# stand up swSIM + swicc-pcsc, then:
sim-doctor scan --json             # M1 acceptance test
```
