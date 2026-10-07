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
| **TS.48 in scope as a profile comparison (re-scoped 2026-10-07)** | TS.48 is public (Apache-2.0, `https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public`). It defines a test profile, not test cases, so #25 parses the public profile package and compares a card's file system against it, read-only. Supersedes the earlier "runner for operator-supplied profiles" decision, which assumed the profiles were behind a member login |
| **SGP.22 and TS.48 are public (corrected 2026-10-07)** | SGP.22 v2.5 PDF: `https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/05/SGP.22-v2.5.pdf`. Section numbers taken from `euicc-rsp` stay `[U]` until checked against it; eUICC issues upgrade them to `[V]` as they go |
| **swSIM only, no physical reader for now** | Owner decision. Real-reader testing stays available later as a second fixture, not a redesign |
| **Autonomous PR merging** | Owner decision. A subagent may implement, test, self-review and open a PR; it may **not** merge. An orchestrator verifies then merges |
| **Serial, dependency-ordered delivery** | Owner decision. M1 is a strict chain, so parallel agents would collide on the contract and drift from it. Fan-out is deliberately rejected |
| Hand-roll APDU types rather than wrap `iso7816` 0.x | `iso7816 0.2.1` is 0.x with an unstable API, and wrapping it would put an upstream breaking change inside our own contract surface. `src/apdu.rs` now defines `Header`, `StatusWord`, `Le`, `Command` and `Response` directly |
| `iso7816` left declared but UNUSED in Cargo.toml | Deliberate, and a known loose end rather than an oversight. Issue #5's agent hand-rolled instead of wrapping, and removing an unused dependency mid-phase would force a Cargo.lock change for no functional gain. It must be wrapped or removed before this is called done - tracked, not forgotten |
| **Hand-roll BER-TLV; `iso7816-tlv` 0.4.4 and `flexiber` 0.2.0 both removed** | Issue #11 read both at these versions. `iso7816-tlv` reads an indefinite length as zero instead of rejecting it, copies every value into nested `Vec`s, rejects a single-octet tag ending `1F`, and encodes 127 non-minimally. `flexiber`'s length rules match ours exactly, but it discards the length *form* that `tlv::Length` exists to keep, and it is BER-only so it could not have been the strict half either. Decisive: the acceptance criterion is that the non-minimal tolerance be tested in *this* repository, and delegating the decoder delegates the property. Full reasoning in AGENTS.md 4.2.1 |
| **The FCP tag table is a caller-supplied value, not a default** | Reading a card with the wrong table's numbers reported a 10-octet EF as 2337 octets (issue #11). The table once called "ISO/IEC 7816-4 table 42" was itself wrong for real cards (issue #69); the standard one is ETSI TS 102 221 clause 11.1.1.3, which swSIM also writes. `fcp::TagSet` has no `Default` and no constructor that invents tags, so `Template::parse` cannot be reached until somebody names the dialect; every `TagSet` carries its name so a scan reports the assumption it ran under. An enum with built-in variants would have re-encoded the bug as a type |
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
| **`emit_stdout` flushes explicitly, because `write_all` returning Ok does not mean the bytes left the process** | Issue #6's first CI run, and it is the most surprising finding in this issue. `stdout()` is line-buffered, so a `write_all` that fits the buffer returns Ok without the stream ever being touched; the tail is flushed by the standard library's exit-time cleanup, which runs **after** `main` has chosen the exit code and throws the error away. The result is a run that exits **0 having written nothing**: for an agent that is worse than the `println!` panic this function was written to replace, because the caller gets silence and a success status. The Ubuntu runner returned 0 where the same binary on macOS returned 1, for the same 1.6 KB payload - so whether the buffer is flushed inside `write_all` is a property of the payload size and the standard library's line-flush behaviour, not of this crate, and it moves between releases. Flushing explicitly makes the property hold on every toolchain. The assertion was NOT relaxed: `a_run_that_cannot_write_its_report_exits_1_and_explains_itself_on_stderr` is unchanged in substance, now carries the child's own stderr and raw status in its failure message, and a second test proves the same property on the human renderer's payload |
| **`scan --json` cannot prove the write-error path on a machine with no card, and must not be used to** | Issue #6. With stdout unwritable and no reader attached, `scan` exits 1 from `report_failure` - "no PC/SC reader is attached" - before it ever reaches `emit_stdout`, so the test would be measuring the wrong thing while still seeing exit 1. `modules` is the only command that reaches a write on any machine, which is why the write-error test is still written against it |
| **The closed-stdout handshake marks both pipe ends close-on-exec, and this file serializes every spawn** | Issue #6's first CI run. `libc::pipe()` creates two descriptors that survive every later fork+exec in the process, so a child another test spawns inside the two-instruction window between `pipe()` and `close(read_end)` inherits the read end, the run under test writes SUCCESSFULLY, and `a_run_that_cannot_write...` fails with a bare `left: 0`. Three things fix it, all in `tests/process_contract.rs` and none in the assertion: both ends get `FD_CLOEXEC` before anything else (`pipe2` is Linux-only, `fcntl` is portable), `the_closed_stdout_handshake_marks_both_pipe_ends_close_on_exec` reads the flag back off the handshake's own descriptors so deleting the fix fails that test, and `SPAWN_LOCK` serializes every spawn in the file because descriptor NUMBERS are process-global state this file mutates. Measured: 400 consecutive runs of the 17-test binary at `--test-threads=16`, 0 failures, against 3/300 before the lock |
| **`scan` cannot prove the write-error path on a machine with no card, and must not be used to** | Issue #6. With stdout unwritable and no reader attached, `scan` exits 1 from `report_failure` - "no PC/SC reader is attached" - before it reaches `emit_stdout`, so a test written against it would be measuring the wrong thing while still seeing exit 1. `modules` is the only command that reaches a write on any machine, which is why the write-error test stays written against it. Verified rather than assumed: `scan --json` against a closed pipe on a cardless machine exits 1 with empty stdout and a no-reader diagnostic |
| **Whether the binary or the harness was at fault was settled by running the binary directly, not by reading the code** | Issue #6. `emit_stdout`, `emit_modules` and `run_modules` were diffed against `main` and are byte-identical, which rules out a behaviour change; 100 direct runs of `modules` and `modules --json` against a closed pipe returned 1 every single time. What was left was harness-only, and serializing spawns made it disappear. A red test is worth one experiment that isolates it rather than an argument about which file should have changed |
| **A finding carries its own `coverage`, and "partial" means the list may be short, not that anything in it is wrong** | Issue #13, and the question the issue asked to be answered rather than deferred. A finding raised from a walk that hit `max_depth` may be entirely true; the card really did hold that file. What cannot be claimed is that it holds no others. So incompleteness travels **on the finding** (`{"status":"partial","reason":"..."}`) and not only on the report, because an agent that greps one rule ID reads one object and never sees the report header, and that is the exact path by which a truncated scan becomes a claim about the whole card. `Findings::partial` marks every finding and the set, because a consumer may read either; it does **not** overwrite a reason a rule set for itself, since a rule that knows why it could not answer knows more than the scan headline bound does |
| **Absent, forbidden and refused survive into the rule model as `Location::File`'s `access`, carrying `walk`'s four spellings unchanged** | Issue #13. `walk::NodeState` already keeps them as separate variants with separate iterators, and issue #6 pushed them all the way to `data.absent`/`data.forbidden`/`data.refused`. Flattening them inside the rule layer would throw that away at the one place a consumer still had to choose. The four JSON words are the four `walk` words (`selected`, `absent`, `forbidden`, `refused`) so one vocabulary describes a walk and a finding, and a test asserts the serde tag and the `Display` spelling cannot drift. Four named constructors - `selected_file`, `absent_file`, `forbidden_file`, `refused_file` - mean the distinction cannot be got wrong at a call site by omission |
| **Evidence is bounded at construction, by types with private fields, and the omission is counted** | Issue #13. `EvidenceBytes`/`EvidenceText` have private fields precisely so that `Evidence::Bytes(..)` cannot be reached with an unbounded payload: a public field on a public enum variant would let a rule attach a 65 535-octet EF body and make one line of scan output longer than the card. `MAX_EVIDENCE_BYTES` (64) and `MAX_EVIDENCE_CHARS` (64) are named, enforced in the constructor, and the dropped count is carried into the JSON as `omitted` rather than discarded - silently handing back a prefix is how a scan comes to report a card saying something it did not. A test asserts `Display` stays under 512 bytes with a 64 KB evidence attached, because the other two homes for a finding are a terminal and an agent's stdout |
| **A rule ID is re-validated on deserialization, and a status word or an evidence hex string with it** | Issue #13, in preparation for issue #9's baselines. `RuleId` has a hand-written `Deserialize` that runs `RuleId::new`; the derived one would have let a baseline naming `Filesystem/Unreadable_EF` parse into an ID no registry could ever have produced, and the comparison it feeds would be against a rule that does not exist. Same for `Status` (four hex digits) and evidence octets (even-length hex). Unknown *fields* are still ignored, because a baseline written by a later version has to stay readable by this one - the strictness goes on the forward path, not the backward one |
| **A registry refuses a duplicate ID at registration AND a misattributed finding at evaluation** | Issue #13. Agents address rules by ID, so two rules under one ID make every answer about that ID ambiguous from then on, a baseline cannot say which one it compared, and nothing in the output would show it happening. `register` checks before it inserts, so a refused registration cannot half-happen. The second refusal closes the back door: a producer that emits an ID it was not registered under is the same ambiguity arriving at output time, and `Registry::evaluate` is the last point before it reaches a file an agent will diff. `Rule::run` exists and does not check, because a bare run has nothing to check against |
| **`rules::Registry` is generic over what its rules are handed, so the binding can live in a leaf module** | Issue #13. A registry has to map an ID to a function, and the function needs an argument: a DF tree, an APDU exchange log, a TAR table. Naming any of those in `rules` would give the layer-0 module a dependency and pull a card type into the surface of every command. `Registry<S>` over `fn(&S) -> Vec<Finding>` keeps the whole contract - lookup, ordering, duplicate refusal, misattribution - inside `rules` while naming no card type. `rules` stays a leaf: its `MODULES` entry is unchanged, `contract` still cannot see it, and a new test reads both modules' source and fails if either grows a `use crate::` |
| **`rules` now derives `Serialize`, and owns the finding's JSON body but not the envelope** | Issue #13, which retired the old note that "nothing here derives Serialize". That was true while `rules` owned two vocabularies and no structure. A finding's keys are `rules`' to choose and have to be pinned by a test somewhere; `contract` owns the wrapper and must not learn what goes inside it. `Finding::to_json` builds a `serde_json::Value` the caller already had a slot for, and `tests/finding_contract.rs` asserts from outside the crate that the bytes outside `payload.data` are identical with and without findings. `Serialize` for `Finding` is hand-written for one reason: the object carries `severity_rank` beside `severity`, and a derived impl can only emit fields the struct has |
| **Strict DER is a separate module and a separate type, not a mode** | AGENTS.md 4.2. `der::Der` and `tlv::Tlv` share no code, no `From`, and no module; `der` is layer 0 with no dependencies in `MODULES`. Three `compile_fail` doctests in `src/der.rs` assert that the separation, so `cargo test` fails if a conversion is ever added. A `strict: bool` would have made the choice a runtime flag, which is how a BER parser ends up being pointed at a certificate |
| **A scan that PRODUCES findings still exits 0, RE-TOOK in issue #24 with a rule in place, and the answer did not change** | Issue #14 first, issue #24 second. Issue #14 decided it while no rule ran, and gave three reasons; the first ("no rule runs yet") was **withdrawn** by issue #24 because it stopped being true, and is struck through in AGENTS.md rather than deleted - a reason that is no longer true must stop being quoted as if it were. The two that survived are independent of it. `payload.code` still means "the walk finished" (0 for a truncated walk) and `scan --help` has said `GATE ON data.complete, NOT ON payload.code` since issue #6. **The decisive reason is one issue #24 found that was not written down before**: exit 1 is already reachable from six conditions, and every one of them emits a *refusal* document carrying `data.error` and **no `data.findings` key**, while a scan that found something emits `data.findings` and **no `data.error` key**. Flipping does not add a meaning to an exit code; it gives one code two mutually exclusive document schemas, and an agent branching on the status would have to read the body to pick one. That is the wrong trade in the same release that first produces a finding. A CI gate reads `data.complete` and `data.score.value` instead, which are per-field and cannot be mistaken for each other. **Revisit when #9 lands `--baseline`/`--diff`**: a gate then has a threshold to fail against rather than a bare "something is wrong" |
| **A TAR is reported accepted by DIFFERENTIAL, not by a status word, and no "TAR refused" status is hard-coded anywhere** | Issue #24, and the most important decision in it. This project has read no 3GPP TS 31.111 text (AGENTS.md blocker 2) and cannot cite a status word meaning "this TAR is not allowed"; the one card it has talked to contradicts the obvious guess, answering `94 04` for a missing file rather than for a refused TAR. So `src/tar.rs` measures: twenty calibration TARs establish the modal response, and a TAR is accepted when its answer **differs** from that. This is SIMTester's own `-stbs` algorithm (`TARScanner.tryBeingSmart`), not an invention. It is also the only criterion that cannot manufacture findings: swSIM has no TAR check at all, so it answers `90 00` to every TAR including TAR zero, and a rule reading that literally would raise a critical MSL=0 finding for all 656 probes. The differential absorbs it and reports nothing, which on that card is the correct answer rather than a miss. When even the baseline cannot be established - a tie, or no status word at all - `data.tar.blind_spot` says so in words and nothing is raised |
| **A TAR probe is TWO exchanges, and the card is never left mid-command** | Issue #24, from swSIM `src/apduh.c`, `apduh_etsi_cat_envelope`: with `procedure_count == 0` and `*cmd->p3 > 0` the handler returns `SWICC_APDU_SW1_PROC_ACK_ALL` and copies **nothing** out of `cmd->data`. A scanner that sends the envelope inline and moves on leaves the card holding half a command, the next APDU is swallowed as its continuation, and every later probe answers about the wrong TAR. So the probe is the opening `CLA INS P1 P2 Lc` and then exactly `Lc` octets, and a card that asks for a different amount **ends the scan** rather than being sent a mismatched exchange. A `91xx` after the data is drained with FETCH through `crate::session` rather than left for the next probe, because draining changes the NEXT answer. The card-fixture test asserts the card still answers SELECT MF after the whole sweep, which is the property that makes "do no harm" checkable rather than asserted |
| **The TAR sweep is capped at 4096 probes whatever `--tar` asks for, and the focused default is 656** | Issue #24. The TAR space is 16 777 216 values; SIMTester's `-st full` sweeps all of them and says "go get a (few) coffee(s)". An unbounded probe loop behind a flag is what AGENTS.md section 2 argues against - the swSIM card is cooperative and a real card is not - so `tar::MAX_PROBES` is a constant, a selection past it stops there, `data.tar.stopped` says so, and every finding raised from that scan is marked `partial`. The focused default takes SIMTester's own `prepareTARlist` bands and narrows them to the ones that carry TAR zero, the low bands, and the all-`B` wildcard; the printable-ASCII permutations are dropped because they are over 400 000 values, and `--tar range:200000-7FFFFF` reaches them. A regex is matched against the six-hex-digit spelling, which is also where this crate DIVERGES from SIMTester: its `-stre` filters on the card's *response*, this selects *TARs*, and the response side is reported per probe instead |
| **A TAR accepted that is not TAR zero is reported in the `tar` block and NOT raised as a finding** | Issue #24. An over-broad TAR allow-list is a real problem and a different one from MSL 0, and no rule ID has been agreed for it. Raising it under `gsma/msl-zero-allowed` would be a rule ID lying about itself, which is the same category of mistake as flipping the exit code without moving the table that describes it. Every accepted TAR is in `data.tar.accepted` with its status word, so nothing is hidden by not raising it; the decision to add a second rule is a separate one with a separate ID to agree |
| **A score of 100 with `rules_run` 1 is a VERDICT, and with `rules_run` 0 it is an absence - and the fixture now proves both** | Issue #14 wrote the warning; issue #24 made it mean something. On a live swSIM card the scan now reports `rules_run` 1, `scored_findings` 0, `value` 100, `warning` **null** - the one rule ran, looked, and found nothing. Before issue #24 the same 100 carried a warning string saying nothing had been checked. Those are the same number with opposite meanings and the difference between them is exactly one integer, which is the whole reason `rules_run` is in the block. The card-fixture assertions were rewritten from "the warning is present" to "the warning is null AND `rules_run` is 1", asserted together, because either half alone is a much weaker claim |
| **`--severity` filters rather than masks, and the filter runs BEFORE the score** | Issue #14. A finding below the threshold leaves no entry, no contribution to `count` and no rule ID anywhere in the rendered document - not a zeroed entry, not a placeholder, not a `suppressed` flag. A mask would be counted correctly by one consumer and still be greppable by another, and those two would then disagree about how dirty the card is. Ordering is the other half: the score is a function of the `findings` array printed beside it, so `--severity high --score` scores the high and critical findings and reports `scored_findings` to match, and a number an agent cannot reproduce from the document it is holding is a number it should not gate a build on. The filter does not touch the walk: `complete`, `truncated`, `truncated_by` and `limits_hit` are identical filtered and unfiltered, so raising the level can never make a truncated scan look whole |
| **The penalty ladder is chosen, not measured, and moving one is a decision to record** | Issue #14. There is no published CVSS-equivalent for a SIM and this project has not derived one, so `SCORE_PENALTY = [1, 3, 10, 25, 50]` is a choice, published for that reason. The shape of the choice - each rung costs several times the one below, a `critical` costs half the scale alone - is a judgement about what a card being dirty should look like on a 0-100 scale, and a CI threshold written against these numbers stops meaning the same thing if they move. The sum is a `u64` clamped at 0 rather than truncated, because a truncating cast turns a penalty of 256 into 0 and reports a dirty card as 100 |
| **The formula is published in three places and a test reads AGENTS.md to prove it** | Issue #14, whose constraint was "a score nobody can reproduce is worse than no score". A formula that lives only in the source is exactly that, so it is in `rules::SCORE_FORMULA`, in the `score` block of every JSON report (`formula` plus the whole `penalties` table plus the `penalty` total), and in AGENTS.md section 3. `the_three_copies_of_the_formula_say_the_same_thing` reads AGENTS.md at compile time and asserts the constant and the penalty rows still appear verbatim, so the document is a checked copy rather than one somebody has to remember to update |
| **A score of 100 from an empty set is not a clean card, and the report says so in words** | Issue #14. No rule runs yet, so `--score` on any card today returns 100 from nothing having been examined - indistinguishable, read alone, from a card that passed. Three fields have to agree before the question is answerable: `rules_run` 0, `scored_findings` 0, and a non-null `warning` string saying the 100 is because there is nothing to subtract, NOT because the card is clean. The human report prints the same warning. The warning goes null once rules do run, or it stops meaning anything. This is documented rather than defended against: a contract that cannot be broken cannot be relied on, and a CI gate that reads `value` without reading `warning` is making a mistake this output exists to prevent |
| **`--score` and `--severity` are no longer deferred; `--baseline` and `--diff` are** | Issue #14, completing issue #6's rule that all four flags exist from day one. The two that needed a card now take one; the two that need a saved run still refuse with one envelope carrying `"implemented": false`. The refusal is still worth having, and the process test asserting it was narrowed rather than deleted so that a flag quietly going back to refusing is a test failure. `implemented_flags_are_no_longer_deferred` asserts the difference in KIND rather than the exit code, because a refusal and a failed walk both exit 1 on a cardless machine and only the payload tells them apart |
| **Stdout purity is asserted across the flag MATRIX, not per flag** | Issue #14's fourth acceptance criterion. Purity is a property of the combination: a score printed to stderr only when `--severity` is also present, or a severity echoed to stdout by a path that only runs under `--json --score`, passes every single-flag test. Fifteen combinations are run against the real binary, each asserted for one line, one envelope that re-serialises to the bytes on stdout, kind `scan`, and `payload.code` equal to the process exit status. The exit code itself is deliberately not asserted per combination, because it legitimately differs between a machine with a card, a deferred flag and a failed walk - the property that does not differ is the purity |
| **A crash-salvage commit is a branch state, not a starting point** | Process, issue #14. Two agents died on this issue. The second left a commit that did not compile - an unterminated string literal and 19 call sites behind a signature change - and the recovery cost was a full read of three files before anything could be verified. What helped was that the good work was its own commit (`a325256`, `src/rules.rs` alone, +509) and the broken work was a second one clearly labelled DO NOT MERGE AS-IS with a good/broken inventory in the message. Both conventions are now load-bearing rather than incidental: a WIP checkpoint states what is good, what is broken, and what command proves it, and the branch is pushed at every stage so a third death inherits a pushed commit rather than an uncommitted plan

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

**DONE in issue #13** - [src/rules.rs](../src/rules.rs) now holds what a finding
is: the ID, the severity, the message, the location (which keeps a forbidden file
apart from an absent one), evidence (bounded at construction), and a `coverage`
field saying whether the scan that raised it finished. `rules::Registry` binds an
ID to the code that produces it and refuses a duplicate, at registration and
again at evaluation. What is **still** missing, and is the rest of M2: no rule
exists yet, so nothing raises a finding, `scan` still exits 0 whatever it saw,
`--score`/`--severity` still refuse honestly, and `--baseline`/`--diff` are
still placeholders (#9).

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

**Does TS.48 belong in scope?** ANSWERED - yes, as a comparison against the public profile package (re-scoped 2026-10-07). See section 3.

**Is GSMA member access needed?** ANSWERED - no: SGP.22 and TS.48 are public. See section 3.

**Hardware in the loop or not?** ANSWERED - swSIM in CI, plus a live operator SIM used read-only on the owner's machine (from 2026-10-07: SELECT, GET RESPONSE, READ of metadata files, STATUS, GET DATA only; no PIN, auth, write, ENVELOPE or fuzzing). See section 3.

These were the three questions this section used to carry. They are now decisions, and
the answers are recorded above. The former open question (whether the TS.48 runner should
self-derive smoke profiles) is moot: the real TS.48 profile is public, so #25 uses it directly.

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
| Phase 4 | TS.48 profile comparison | a card's file system is compared against the public TS.48 profile |

Per issue, one subagent: branch, implement, verify locally, self-review the diff, open a PR,
watch CI. Then the orchestrator verifies independently and merges. A subagent never merges.

Process rules the loop depends on:

- CI runs `--locked`, so any dependency change must commit `Cargo.lock` in the same commit.
- Do not trust `gh pr view --json files` mid-run; its merge base can be stale. Use `git diff`.
- A subagent that runs long gets re-dispatched in the background. Foreground dispatch has a
  hard 600s ceiling and will truncate work that was nearly finished.
- Blocked items stay open with their unblock path written down. They are never silently dropped.
