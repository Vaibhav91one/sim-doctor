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
| ~~`iso7816-tlv` over `der` for BER-TLV~~ **SUPERSEDED by issue #11** | The premise was right - `der` is strict DER and rejects real SIM BER lengths - and the conclusion was wrong. See the three rows below |
| Development loop uses swSIM + swicc-pcsc | No hardware prerequisite for the test suite |
| JSON envelope modelled on `lpac` | Best existing agent-friendly contract found |
| **TS.48 in scope as a RUNNER, not transcribed profiles** | Owner decision. The profile definitions sit behind the same GSMA member login as SGP.22, so we build the executor that consumes operator-supplied profile files and stop there. Progress without pretending to spec access |
| **No GSMA member access** | Owner decision. Every SGP.22 / TS.48 section number is provenance-backed from `euicc-rsp` source comments, never primary. Label accordingly, permanently |
| **swSIM only, no physical reader for now** | Owner decision. Real-reader testing stays available later as a second fixture, not a redesign |
| **Autonomous PR merging** | Owner decision. A subagent may implement, test, self-review and open a PR; it may **not** merge. An orchestrator verifies then merges |
| **Serial, dependency-ordered delivery** | Owner decision. M1 is a strict chain, so parallel agents would collide on the contract and drift from it. Fan-out is deliberately rejected |
| Hand-roll APDU types rather than wrap `iso7816` 0.x | `iso7816 0.2.1` is 0.x with an unstable API, and wrapping it would put an upstream breaking change inside our own contract surface. `src/apdu.rs` now defines `Header`, `StatusWord`, `Le`, `Command` and `Response` directly |
| `iso7816` left declared but UNUSED in Cargo.toml | Deliberate, and a known loose end rather than an oversight. Issue #5's agent hand-rolled instead of wrapping, and removing an unused dependency mid-phase would force a Cargo.lock change for no functional gain. It must be wrapped or removed before this is called done - tracked, not forgotten |
| **Hand-roll BER-TLV; `iso7816-tlv` 0.4.4 and `flexiber` 0.2.0 both removed** | Issue #11 read both at these versions. `iso7816-tlv` reads an indefinite length as zero instead of rejecting it, copies every value into nested `Vec`s, rejects a single-octet tag ending `1F`, and encodes 127 non-minimally. `flexiber`'s length rules match ours exactly, but it discards the length *form* that `tlv::Length` exists to keep, and it is BER-only so it could not have been the strict half either. Decisive: the acceptance criterion is that the non-minimal tolerance be tested in *this* repository, and delegating the decoder delegates the property. Full reasoning in AGENTS.md 4.2.1 |
| **The FCP tag table is a caller-supplied value, not a default** | swSIM and ISO/IEC 7816-4 table 42 disagree on which tag means what, and reading one card with the other table's numbers reported a 10-octet EF as 2337 octets. `fcp::TagSet` has no `Default` and no constructor that invents tags, so `Template::parse` cannot be reached until somebody names the dialect; every `TagSet` carries its name so a scan reports the assumption it ran under. An enum with two built-in variants would have re-encoded the bug as a type |
| **The walk bounds rather than detects cycles** | Issue #7. The obvious cycle check - "this child's identifier already appears on the path to itself" - is **unsound**: a file identifier is unique inside a directory and not across a card, so a directory holding a child with the same two octets as an ancestor is describing a legal file. A walker that stopped there would hide files. The traversal is an explicit stack, candidates are de-duplicated per directory, a path can therefore be reached at most once, and a card describing an infinite tree is stopped by `Limits::max_depth` / `max_nodes` / `max_directories`, each reported as a `walk::Note::Limit` rather than applied silently. The repeat is still recorded as `Note::RepeatedAncestor`, because a card that puts a directory inside itself is worth a finding |
| **A status word is only read as "absent" if a caller says so** | Issue #7, and the direct consequence of the GSMA blocker. `6A 82` is verified; nothing else is, because 3GPP TS 102 221 assigns meanings in the `94 xx` range that this repository has not read and 3GPP's own FTP answers 403. `walk::StatusMeaning` is therefore a caller-supplied table whose default carries that one entry, and every other refusal reaches the caller as `NodeState::Refused { status }` with the status word intact. A walker that guessed "access denied" would turn every protected file on a real card into a finding this project cannot justify |
| **Enumeration is by probing, not by EF.DIR** | Issue #7. Reading a directory listing is the efficient enumeration and is unavailable on the fixture: swSIM's GET RESPONSE rejects any P1 other than `00` \\[V], swicc `src/apduh.c:apduh_res_get` at `421c8cdd`, and the 3GPP directory read is GET RESPONSE with P1 `81`. A walker that used it would find nothing on the one card this project can test against and would look broken rather than unsupported |
| **SIGINT is a flag plus a checkpoint, never work in the handler** | Issue #8. The handler is an `extern "C"` function that does two atomic operations and returns; the run notices at a checkpoint and exits normally, so destructors run, stdout is flushed and the exit code is chosen by ordinary code. Anything else - formatting a message, taking a lock, writing to a stream, calling `process::exit` - is a deadlock or an allocator call on the signal stack, and POSIX calls both undefined. The payoff is observable and tested: a handled SIGINT gives `code() == Some(130)`, an unhandled one gives `signal() == Some(SIGINT)` and `code() == None`. `tests/process_contract.rs` asserts the first and would fail on the second |
| **The handler is installed with `SA_RESTART`, and a checkpoint comes before output, never after** | Same issue. `SA_RESTART` because the handler does nothing except set a flag, so there is no interruption for the kernel to hand a blocked syscall and restarting keeps EINTR out of the card code entirely; on a SIM that matters twice over, because an APDU exchange abandoned half-way can leave the reader and the card disagreeing about which command is in flight. Checkpoints before output because a run that has already written its envelope has *finished*: retroactively converting a complete, correct answer into "interrupted" would need a second envelope on stdout, or would break the promise that `payload.code` is the value the process exits with. Both are worse than a Ctrl-C that arrives microseconds too late |
| **An interrupted run emits one envelope carrying code 130 and an empty `data`, never a partial result** | Issue #8, and the question the issue asked to be answered rather than deferred. `contract::INTERRUPTED_MESSAGE` and `contract::interrupted_data()` are the constants; `an_interrupted_envelope_is_byte_for_byte_the_documented_shape` pins the bytes. Three reasons: stdout stays pure in *every* mode (one complete envelope, whether the run finished or not), `payload.code` keeps meaning what `Payload::code` documents - the same value the process exits with - and a half-finished scan is never readable as a result. In the human modes the same event writes a line to stderr and nothing to stdout, because stdout there is a report and there is no report to give |
| **A second Ctrl-C restores `SIG_DFL` and re-raises** | Issue #8. Installing a handler replaces the default disposition, so without this an operator mashing Ctrl-C at a wedged card exchange would get nothing back. `sigaction` and `raise` are both on POSIX's async-signal-safe list, so the escape hatch costs nothing in safety terms. The counter saturates at one rather than counting, because `AtomicU8` wraps in a release build and a signal flood must not be able to wrap the count back to zero and make the first interrupt look like a later one |
| **Exit code 1 is reachable today only as "the run could not deliver its result"** | Issue #8. No rule produces findings yet (#13), so the four codes are proved by making the output unwritable rather than by inventing a fake command: the test hands the binary a pipe whose read end is already closed, which is also the real shape of `sim-doctor modules --json | head -5`. The finding this replaced is a `println!` panic - exit 101, a number AGENTS.md section 3 does not promise. Two other candidates were tried and are wrong on macOS: pointing stdout at a read-only file or directory makes the writes *succeed*, because Rust's runtime polls fds 0-2 at startup and replaces anything reporting POLLNVAL with `/dev/null` |
| **Failure to install the SIGINT handler is a diagnostic, not a failed run** | Issue #8. A tool that cannot be interrupted cleanly still produces correct output; exiting non-zero would turn one unhappy platform into a total outage. The cost is that a silently broken install would make 130 unreachable on that platform, which is why the process-level test exists |
| **`tracing` is wired to stderr at WARN, and `RUST_LOG` is deliberately not honoured yet** | Issue #8. `tracing-subscriber` was a declared dependency installed nowhere, which is the same thing as saying no library module had a safe place to log from; and its default writer is stdout, the one stream `--json` reserves. Honouring `RUST_LOG` needs the `env-filter` feature, and taking a dependency feature for a log level nothing in the repo sets is the speculative change AGENTS.md section 4 warns about. The issue that first needs per-module levels records that decision instead |
| **The SIGINT test drives the binary through a documented environment variable, not a sleep** | Issue #8. `SIM_DOCTOR_TEST_SIGNAL_HOLD_MS` parks the process at its first interrupt checkpoint and announces `parked at the interrupt checkpoint` on stderr; the test waits for that sentence before calling `kill(2)`. Sleeping a fixed interval instead was tried first and is flaky: these tests run on parallel threads, several children are exec'd at once, and a cold exec on a loaded CI runner outlived any fixed delay, so the signal arrived before `install()` returned and the kernel killed the process through the default disposition. Unset in every normal invocation, where it costs one failed environment lookup |
| **The CLI surface is the deliverable, so `scan` lives in the library as a report, not in main.rs as a printer** | Issue #6. Everything `scan` does that can be wrong without a card - carrying the truncation, carrying the dialect, keeping absent and forbidden apart, saying which candidate set ran - is in [`src/scan.rs`], testable with a software card double. `src/main.rs` keeps what only a binary can do: pick a reader, open a real PC/SC session, take the interrupt checkpoints, write stdout. The next scan command inherits all of it |
| **Truncation is reported in three places, and `truncated_by` is never reported without `limits_hit` beside it** | Issue #6, and the single most important thing in it. `walk::WalkReport.truncated_by` is the FIRST bound only; a walk that hit the depth bound and then ran out of node budget reports depth alone and understates what it missed. So the JSON carries `"complete"`, `"truncated"`, `"truncated_by"` and the full `"limits_hit"` list; the human report opens with a `TRUNCATED` banner before the reader name; and `scan` writes one warning line to stderr in BOTH modes, because under `--json` stdout is the envelope and a human watching a CI log should not have to pipe it through a formatter first. A truncated walk still exits 0: no rule produces findings yet (#13), so 1 would conflate "the card is dirty" with "the walk could not see the card", and `"truncated"` is the honest channel |
| **`--dialect` has a stated default, and the chosen TagSet is named in both output modes** | Issue #6. `walk` takes a `TagSet` and there is deliberately no `Default`, so `scan` picking one silently would make the assumption vanish. The flag defaults to `swicc` because that is what the one card this project can test against writes, and `--help` says a real UICC is more likely to follow the ISO table. What makes a default acceptable rather than a silent one is that the name is reported: `data.dialect.id`, `data.dialect.name` and the actual tags in the JSON, and "FCP dialect swicc (...) file size 80, descriptor 82, file id 83" in the human report |
| **The default candidate set is flagged as able to MISS a file, in `--help` and in every report** | Issue #6. `walk::Candidates::SimFamilies` probes 2Fxx/4Fxx/5Fxx/6Fxx/7Fxx and nothing else; a file outside those families is invisible to the walk rather than reported missing, because no probe ever happened. `scan::CANDIDATE_WARNING` is one constant used by the flag help, the human report and `data.candidates.warning`, and `data.candidates.exhaustive` is false for anything but a whole-space `Candidates::Range`. The flag help says it in capitals. The obvious gap is that `scan` cannot yet ASK for an exhaustive range, which is recorded on the flag rather than left to be discovered |
| **Absent, forbidden and unclassified refusals are three arrays and a four-value `state`, never one "failed" list** | Issue #6. `walk::NodeState` keeps them apart in the type; flattening them at the output boundary would throw that away at exactly the place an agent reads it. `scan::to_json` emits `data.absent` (paths), `data.forbidden` ({path, status}), `data.refused` ({path, status}) and a per-file `"state"`, and a test asserts a forbidden path never appears in `absent`. Forcing the forbidden state in that test needed `StatusMeaning::with_forbidden(9804)`, which is the point: the classification is the caller's table, never this crate's guess |
| **`--score`, `--severity`, `--baseline` and `--diff` exist from day one and refuse with exit 1 before a reader is opened** | Issue #6, and the issue's own constraint. Agents script against the contract, so a flag that exists and answers "not yet" is found at design time while a missing flag is found at runtime, in production, by whoever wrote the script. Each refusal is one envelope carrying `"implemented": false`, `"scanned": false`, `"card_touched": false` and a `tracking_issue`, with the sentence on stderr in either mode. Exit 1 rather than 0 because 0 means "no findings above threshold", and a `--score` returning 0 because the scorer is unwritten would be indistinguishable from a card that passed; exit 129 is wrong because the command line WAS understood. `--severity` still parses its value, so a typo is still 129 |
| **`scan` takes exactly two interrupt checkpoints, both before any output** | Issue #6. One before the reader is opened, so an operator who hits Ctrl-C while the tool is still finding hardware is not made to wait for a card; one after the walk and before the report is rendered, so a finished walk is either reported in full or reported as interrupted. There is no third, because a run that has written its envelope has finished. The first checkpoint is also what lets `tests/process_contract.rs` prove SIGINT for `scan` on a machine with no card at all, which is most of the value |
| **`SIM_DOCTOR_TEST_SIGNAL_HOLD_MS` parks once per process, not once per checkpoint** | Issue #6, forced by `scan`'s two checkpoints. Parking at each would make a test whose signal did not land sit out the full hold twice - two checkpoints times thirty seconds, on a run that was always going to be interrupted at the first. `main.rs` holds the park behind one `AtomicBool` |
| **Completions are generated at run time from `Cli::command`, and they name the unimplemented flags** | Issue #6, which is where the declared-but-unused `clap_complete` dependency stopped being one. A checked-in script would go stale the moment a flag is added, and one generated from a filtered command would reintroduce the missing-flag problem in a place nobody looks: an agent that types "sim-doctor scan --" and hits tab has to see `--score`. The process test greps the script for every AGENTS.md section 3 flag and parses the bash one with `bash -n` |
| **Strict DER is a separate module and a separate type, not a mode** | AGENTS.md 4.2. `der::Der` and `tlv::Tlv` share no code, no `From`, and no module; `der` is layer 0 with no dependencies in `MODULES`. Three `compile_fail` doctests in `src/der.rs` assert that the separation, so `cargo test` fails if a conversion is ever added. A `strict: bool` would have made the choice a runtime flag, which is how a BER parser ends up being pointed at a certificate |

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
2. Stand up swSIM + swicc-pcsc + pcscd as the test fixture. **DONE in issue #4** -
   pinned SHAs, separate CI workflow, card-backed test behind the `card-fixture`
   feature. See [docs/swsim-fixture.md](docs/swsim-fixture.md).
3. Implement reader discovery, connect, SELECT MF, DF walk, EF enumeration. Reader
   discovery, connect and SELECT MF are **proved against a live card** by that
   fixture; the DF walk and EF enumeration are the remaining part.
   **DONE in issue #7** - [`src/walk.rs`](src/walk.rs), card-verified by
   `walks_the_file_system_of_a_real_card` in the card-fixture workflow. What it
   does **not** prove on a card is the forbidden case: swICC evaluates no access
   condition on SELECT \\[V], `src/fs/va.c:va_select_file`, so no fixture run
   can produce that status and the absent/forbidden distinction rests on the
   unit tests.
4. Emit the JSON envelope. Exit 0 on success.
   **DONE in issue #6** - [sim-doctor scan](../src/main.rs) opens a real
   PC/SC session, picks a reader, walks the card and emits one envelope,
   card-verified by `scans_a_real_card_end_to_end` in the card-fixture
   workflow. The report side is [src/scan.rs](../src/scan.rs), because the
   parts that can be wrong without a card - truncation, the dialect, the
   candidate set's coverage, absent against forbidden - are all testable
   against a software card double and none of them belong in a printer.
   What issue #6 deliberately did **not** do: pick an exit code from findings
   (#13), score anything (#13), or compare runs (#9).

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
cargo test                        # DONE - 63 tests, no reader and no daemon needed
# the swSIM fixture exists but is opt-in and Linux-only; see
# docs/swsim-fixture.md for how to bring it up locally.
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
