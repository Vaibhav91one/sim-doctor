# AGENTS.md - sim-doctor

Canonical instructions for any agent or contributor working in this repo.
Read this before writing code. It encodes decisions that are expensive to rediscover.

**Confidence tags are load-bearing.** Facts below carry:

- `[V]` - verified against a primary source (repo at a pinned SHA, live API, spec text)
- `[U]` - unverified, inferred, or recalled. Do not build on these without checking first.

Full source citations live in [docs/research-report.md](docs/research-report.md).
Project history and open questions live in [CONTEXT.md](CONTEXT.md).

---

## 1. What this project is

A CLI-first SIM security testing tool in Rust. It examines SIM/UICC/eUICC cards over PC/SC
and reports security findings through both a human terminal UI and a stable machine-readable
contract, so the same binary serves an interactive operator and an automated agent.

Feature coverage target, in rough priority order:

1. Filesystem scanner (EF/MF/DF enumeration, TLV decode)
2. TAR / MSL=0 audit
3. SCP02/03/11 mutual authentication
4. GlobalPlatform shell (install, key mgmt, DAP tokens)
5. eUICC / LPA remote provisioning (SGP.22 ES9+/ES10x, SCP03t, BPP)
6. Fuzzer (OTA/SMS/APDU)

---

## 2. Non-negotiable principles

### Agent-first, not agent-optional

Every command must work headless with a stable contract. The TUI is a view over the same
data, never the only way to get it. If a finding can only be seen by a human in a terminal,
the feature is not done.

### Verified facts only

When writing code against a protocol fact, cite it. If a fact is tagged `[U]`, either verify
it first or leave a comment saying it is unverified. Silent assumptions are how protocol
implementations go wrong.

### Testable without hardware

The primary dev loop is a software SIM behind a software PC/SC reader:

- `tomasz-lisowski/swsim` - software SIM card [V, 567 stars, BSD-3, C]
- `tomasz-lisowski/swicc-pcsc` - PC/SC IFD handler exposing swICC cards via pcscd [V, 48 stars]

Never make hardware a prerequisite for running the test suite.

**This is standing up, in issue #4.** Both projects are pinned by SHA, built and
installed in a separate CI workflow, and the card-backed tests run against
[src/transport/pcsc.rs](src/transport/pcsc.rs), the real `pcsc` implementation of
[ReaderProvider](src/transport.rs) and [CardSession](src/transport.rs). Five
tests live behind the gate:

| Test | Proves |
|---|---|
| `drives_a_real_card_through_the_pcsc_transport` | the transport round trip: SELECT MF, GET RESPONSE, READ BINARY (issue #4) |
| `walks_the_file_system_of_a_real_card` | the DF-tree walk against real capabilities templates (issue #7) |
| `scans_a_real_card_end_to_end` | `sim-doctor scan --json` as the **built binary**: one envelope, exit 0 (issue #6) |
| `the_score_and_severity_flags_reach_the_envelope_against_a_real_card` | `sim-doctor scan --score --severity` as the **built binary**: the score block, its formula, and the difference between an earned 100 and an unearned one on real stdout (issue #14, rewritten by #24) |
| `a_baseline_saves_and_a_diff_against_a_truncated_one_is_refused` | `--baseline` writes a file a later run reads back, that file records what the run did, and `--diff` against a baseline whose walk stopped at a bound is refused with `baseline-truncated` and exits 1, because this fixture's walk is always truncated (issue #12) |

The third is the M1 acceptance criterion, and it is the only one that runs the
executable. The argument parsing, the reader choice, the envelope, the stdout
purity and the exit status all live in the binary, so no library-level test can
reach them. The fourth exists for the same reason and for one more:
`--score` and `--severity` need a card before they produce anything at all, so
on a cardless machine the process tests can only prove they are no longer
**deferred**. Whether the score block reaches stdout, carrying its formula and
its penalty table, is card-only. It is also the one that made the difference between an earned
score and an absent check meaningful: with a rule registered, `rules_run` is 1 and the warning
is null, so the 100 on a real card means a rule looked and found nothing rather than that nothing
looked. The fifth is the baseline round trip: a file written by one run and read by the next, on
a real card, with the record of what the run did checked field by field against the report beside
it - and **not** the regression, because this fixture is deterministic and a card that does not
change cannot regress. The new/fixed classification is proved in
[src/baseline.rs](src/baseline.rs) against synthesised finding sets instead.

**The TAR scanner has NO card test, and that is a cost recorded rather than worked around.**
There was one. It was deleted because a TAR probe is an ENVELOPE, and an ENVELOPE leaves
swicc-pcsc unable to start a transaction for any later process - it poisoned every card test that
ran after it, which is the same hazard `tar::Selection::default` being `Off` is about. The facts
it established were kept and the wire capture was not: swSIM recognises one envelope root tag,
`D3` [V], has no notion of `D1`, no notion of a TAR and no notion of an MSL, so it answers every
SMS-PP-DOWNLOAD with `90 00`. The differential absorbs that, the modal response is `90 00`, and
nothing is raised - the correct answer on a card with no TAR check rather than a miss. See
[TAR scanning and MSL 0](#tar-scanning-and-msl0) for the argument and `src/tar.rs` for the
algorithm.

The gate keeping the default suite hardware-free is the **`card-fixture` cargo
feature**, which is off by default; the test additionally carries `#[ignore]`.
Three commands to check the gate holds:

```
cargo test --locked                                   # no reader, no daemon, no card
cargo test --locked --all-features                     # still green; the card tests are ignored
cargo test --locked --features card-fixture -- --ignored --nocapture   # needs the fixture
```

Local reproduction steps, the pinned commits, the BSD-3 notice and a
troubleshooting table are in [docs/swsim-fixture.md](docs/swsim-fixture.md).
The fixture cannot be run on macOS: there is no pcscd, and swicc-pcsc is a
pcsc-lite IFD handler with no macOS port. Only the crate builds and tests
there, which is exactly why the default suite has to stay hardware-free.

### Status words the fixture proved [V]

Two facts about real cards that the swSIM fixture established by exchanging
APDUs, not by reading a spec. Both will bite every later issue that parses a
status word, so they are recorded here rather than only in the fixture doc.
Source citations and the full transcript are in
[docs/swsim-fixture.md](docs/swsim-fixture.md).

- **SW1 `91`..`9F` is NOT failure.** `9F` is ISO/IEC 7816-4 "normal
  processing, proactive command available"; `91`, `92` and `93` are the 3GPP
  variants and carry the pending command's length in SW2. swSIM rewrites a
  successful command's `90 00` into `91 <length>` whenever a proactive command is
  pending (`src/apduh.c:sim_apduh_demux`, at the end of every command). A scanner
  that treats `91 xx` as an error reports every healthy card as broken.
- **A 9x SW2 is not always a length.** `61 xx` is a response-data length, 9x may
  be a proactive-command length, and `6C xx` is a corrected length. Three
  different numbers sharing a byte.

Consequence for the rule model: **`StatusWord::is_success` returning false for
`91 xx` is correct and must not be "fixed".** Deciding that a 9x status is
acceptable is issue #5's job, one layer up, because it needs to know what
command was sent.

Two more, found the same way. Both are simulator behaviour, not card
behaviour, and are flagged as such so nobody generalises them.

- **Draining a proactive command changes the NEXT command's answer.** On
  swSIM, the first SELECT MF answers `91 80`, FETCH (`80 12 00 00 <length>`)
  returns the 128-byte proactive command and clears it, and the next SELECT MF
  answers a plain `90 00`. An issue that issues commands without draining
  proactive commands will see `91 xx` where it expected `90 00` and must not
  read that as failure.
- **FCP tag numbering is ETSI TS 102 221 clause 11.1.1.3, and swSIM and real
  cards agree on it.** Inside an FCP template `80` is the file size, `82` the
  file descriptor, `83` the file ID, `84` the DF name, `88` the SFI, `8A` the
  life cycle status, `8B`/`8C`/`AB` security attributes, `A5` proprietary
  information and `C6` the PIN status template. A live operator USIM answers
  SELECT MF with `82 02 78 21 | 83 02 3F 00 | ...`, and swICC's builder
  (`swICC/src/3gpp.c`) writes the same tags. An earlier version of this section
  (and `TagSet::iec_7816_4_table_42`) claimed ISO put the size in `82` and the
  FID in `84`; that was wrong (issue #69) and the mapping is removed. The
  `--dialect` value `iec-7816-4-table-42` is still accepted as a deprecated
  alias for `ts-102-221` (it prints a note on stderr), because the CLI value
  and the JSON `dialect.id` are part of the contract. A mapping must still not
  be hard-coded anywhere: a card may deviate.

  **RESOLVED by issue #11.** `fcp::TagSet` is the mapping, it is a value the
  caller supplies, and it has no `Default` and no constructor that invents tags.
  `fcp::Template::parse` takes one, so a decoder cannot be reached until somebody
  has recorded which dialect is being read. `TagSet::ts_102_221()` and
  `TagSet::swicc()` are the two known ones (same tags, different names);
  `TagSet::named(..)` plus the
  `with_*` builders are for a card nobody has characterised. Every `TagSet`
  carries the name it was given so a scan can report the assumption it ran
  under. The CLI default is `ts-102-221`.

### Never commit card secrets

`.gitignore` blocks `*.key`, `*.der`, `*.crt`, `*.pem`, `*.pvk`, `profile.json`,
`secrets.toml`. Keys, profiles, and PKI material stay out of git, always.

---

## 3. The output contract

This is the most important design surface. It mirrors React Doctor's CLI model, which is
the reference implementation for agent-friendly terminal UX.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, no findings above threshold |
| 1 | Findings present (or checks failed) |
| 130 | Interrupted by user (SIGINT or SIGTERM; SIGTERM exits 130 too, not 143) |
| 129 | Invalid usage / bad arguments |

Every one of the four is proved by a test that spawns the built binary and reads its
real exit status, not by asserting the enum: [tests/process_contract.rs](tests/process_contract.rs).

#### A scan that PRODUCES findings exits 0, and that is a decision [V]

**The table above permits exit 1 for findings. `scan` does not use it, and says so
in the output instead.** The second half - "or checks failed" - is what a scan
currently returns 1 for: no reader, no card, a walk that could not run, a
deferred flag. A scan that ran to the end and found something to report exits
**0** whatever it found.

Three reasons were recorded when this was first decided, in the order they
carried weight. **Issue #24 withdrew the first one, because issue #24 shipped a
rule; the other two are unchanged and were re-checked against a scan that can
actually produce a finding.**

1. ~~**No rule runs yet.**~~ **WITHDRAWN by issue #24.** Issue #13 shipped
   the vocabulary a rule needs - the ID, the severity, the registry - and no
   rule, because a rule that guessed would manufacture findings this
   repository cannot justify. Issue #24 registers the first one,
   `gsma/msl-zero-allowed`, so the question is observable for the first time. A
   reason that has stopped being true must stop being written down, or the
   next reader inherits it as a live argument.
2. **`payload.code` already means something else.** Still true, and
   independent of the first: it is 0 whenever the walk *finished*, including a
   walk that was cut short, and `scan --help` has said
   `GATE ON data.complete, NOT ON payload.code` since issue #6. Spending code
   1 on "the card is dirty" without rewording that sentence would make the help
   wrong.
3. **The two meanings have two different documents.** **This is the decisive
   one, and it was not written down before.** Exit 1 is reachable from six
   conditions today - no reader, unknown reader, reader unavailable, walk
   failed, rule misattribution, a deferred flag - plus an unwritable stdout.
   Every one of them emits a *refusal* document: `data.error` and
   `data.card_touched`, and **no `data.findings` key at all**. A scan that found
   something emits the opposite shape: `data.findings` and `data.score`, and
   **no `data.error` key at all**. Flipping the switch therefore does not add a
   meaning to an exit code; it gives one code two mutually exclusive document
   schemas, and an agent branching on the status has to read the body to pick
   one. For a tool whose whole promise is that an agent can branch on the
   status, that is the wrong trade to make in the same release that first
   produces a finding.

**What to gate on instead, and it is already in the document.** A CI gate reads
`data.complete` (was the whole card read?) and `data.score.value` (is it under
the threshold?). Both are per-field, neither collides with the exit code, and
neither can be mistaken for the other.

**The revisit condition has been met, and issue #12 answered it. The answer is yes for a
DIFF and no for a PLAIN SCAN, and those are two different decisions.**

The condition this section set was: "when #9 lands `--baseline` and `--diff`, both of which are
already designed to exit 1, a gate has a *threshold* to fail against rather than a bare
'something is wrong'." That is exactly what `--diff` plus `--severity` is - a number the operator
chose, evaluated against a baseline these two runs have already been checked as entitled to be
compared on. **So `--diff` regressing exits 1**, and `FINDINGS_FAIL_A_SCAN` stays `false`.

#### Is a regressed diff a SEVENTH meaning smearing across the exit code? No, and here is the test

Reason 3 above was never "code 1 is shared" - the table says so in so many words, deliberately,
because a gate cares whether the card passed and not why it did not. Reason 3 was that sharing it
would give one code two **mutually exclusive document schemas**, so an agent branching on the
status would have to read the body to pick one. **A regressed diff is not a second schema.** The
three documents are mutually exclusive:

- a **refusal** carries `data.error` and **no** `data.diff`,
- a **regressed diff** carries `data.diff` and **no** `data.error`,
- a **clean scan** carries neither and exits 0.

So `data.error` remains the refusal marker - the field AGENTS.md tells an agent to read - and
code 1 keeps meaning **the thing you asked for was not delivered**, which is what it already
meant for "a check failed". A diff that reports a regression did not deliver what was asked for.
Every refusal this issue adds - an unreadable baseline, an incomparable pair - lands on the
refusal side of that line, so the rule reason 3 was defending survives intact.

**The honest cost, stated rather than hidden.** An agent that reads `data.error.message` on
code 1 without checking the key first now has to check. That is one extra key read against a
contract that was going to need one the moment a gate existed at all, and it is the price of a
gate that is a gate. An agent branching on the status *alone* still fails the build, which is
the correct answer in both cases.

**What a diff does NOT exit 1 for, and the reasons.** A **fix** never fails a build: a card that
improved is not a regression and a gate that punishes improvement is a gate nobody turns on.
**Saving a baseline without `--diff` never fails a build either** - a baseline has to be
takeable from a dirty card, which is the entire point of having taken one.

**Reasons 2 and 3 still hold for a plain scan**, and nothing here gives code 1 a meaning to an
operator who did not ask for a comparison. `--score` remains the per-field threshold a CI gate
reads. The primitive for the other decision is still written and tested:
[
`Findings::reaches`](src/rules.rs) over the rendered set, at the `Ok(())` arm of
`run_scan`. The switch is the single constant `FINDINGS_FAIL_A_SCAN` in
[src/main.rs](src/main.rs). **Flipping IT is still a contract change and is still not a one-line
edit**: the table above, the `GATE ON data.complete` sentence in `scan --help`, and the
`scans_a_real_card_end_to_end` assertion in [tests/card_fixture.rs](tests/card_fixture.rs) which
currently expects exit 0 against a live swSIM card all have to move in the same commit. Full
reasoning in [CONTEXT.md](CONTEXT.md) section 3.

**SIGINT and SIGTERM are handled, not inherited.** The handler sets one atomic flag and returns;
ordinary code notices at a checkpoint and exits 130 itself, so a handled interrupt
reports `code() == Some(130)` and never `signal() == Some(SIGINT)`. An interrupted run
still emits **one** envelope carrying code 130 and an empty `data` - never a partial
result - so `payload.code` keeps meaning the value the process exits with. Checkpoints
go before output and never after: a run that has already written its envelope has
finished. Full reasoning in [CONTEXT.md](CONTEXT.md) section 3.

### Flags

| Flag | State | |
|---|---|---|
| `--json` | implemented | structured output on stdout, nothing else on stdout |
| `--score` | implemented | single numeric quality score for CI gating, with its formula beside it |
| `--severity <level>` | implemented | remove findings below a minimum severity |
| `--tar <selection>` | implemented | which TARs to probe for MSL 0: `off`, `focused`, `full`, `range:FIRST-LAST`, `regex:PATTERN`; capped at 4096 probes |
| `--baseline <file>` | implemented | save this run, so a later scan can be compared against it |
| `--diff` | implemented | compare this run against `--baseline`; **exits 1 when the diff regresses** |

No flag on the surface is deferred any more. The rule that a flag must exist from day one and
refuse honestly until it is built is unchanged and is kept here because the pattern was right
for `--score`, `--severity`, `--baseline` and `--diff`, but the refusal shape it produced -
one envelope carrying `"implemented": false`, `"scanned": false` and `"card_touched": false` -
is now reached from nothing on the command surface, and what replaced it is described below.
The scoring and severity contract is [Severity and score](#severity-and-score).

### Baseline and diff

`--baseline <file>` writes the findings the report carries, after `--severity`, plus **a record
of what the run did**. `--diff` reads that file back before a reader is opened and compares.

#### What a baseline records, and why refusing is the whole design

A diff is only as good as its baseline. If the baseline was written by a **truncated** scan, or
by one that ran **fewer rules**, then almost everything reads as NEW and nothing reads as
FIXED, and neither word means anything - a gate wired to that does not fail, it fails
*randomly*, which is worse. So a baseline records six things, and a diff **refuses** against a
baseline it cannot honestly compare with:

| Recorded | The lie it prevents |
|---|---|
| `complete`, `truncated_by`, `limits_hit` | a truncated walk did not see the whole card, so a finding absent from it may simply be below where it stopped |
| `rules`, each with an **evidence** flag | a rule that ran with **nothing to look at** cannot have found nothing. `--tar off` is the default, so the usual baseline never checked MSL 0 |
| `severity_threshold` | the two runs filtered different sets, so a finding one never held is not new and one the other dropped is not fixed |
| `dialect` | two tag tables read the same bytes differently, so the findings are not about the same things |
| `candidates`, with how many identifiers it actually yielded | a file one run never probed is neither new nor fixed |
| `tar_selection`, band and class byte both | the MSL 0 rule answers about the TARs it probed |

**A truncated CURRENT run refuses too**, and that direction is the dangerous one: everything the
baseline found and this run does not have would otherwise read as fixed, which tells an operator
a card got better when the walk never got there.

Every one of these is a **refusal**, not a warning: `data.error` with its own `error.kind`, exit 1,
and no `data.findings` and no `data.diff`. Same shape as "no reader attached", for the same
reason - a comparison this tool cannot make honestly is a check that could not run.

#### A rule ID is the address, and a rename reads as a rename

Findings are matched across runs by rule ID **plus location**, because a rule may fire once per
TAR or once per file and the ID alone is not a finding. An ID in exactly one of the two runs is
**counted as neither new nor fixed**: it appears under `data.diff.rules` with the findings it
carried and a `warning` saying an ID that leaves and one that arrives together is what a **rename**
looks like - and also what a withdrawn rule plus an unrelated new one looks like, which two files
cannot tell apart. That is where AGENTS.md's "an ID must never be renamed casually" gets
enforced, because a baseline outlives the release that wrote it.

#### Evidence is bounded on the way IN as well as out

A baseline file is **untrusted input**. A finding's `message` is an unbounded `String` in the wire
type, so a hand-edited file could otherwise put a megabyte of prose into a CI log. `parse` walks
the whole parsed document and refuses any string over **1024 characters** or any array over
**4096 items**, before the typed parse; the file is read through a `take` with a **1 MiB** ceiling
rather than `fs::read`, so the ceiling holds while reading. `RuleId` re-validates itself on the way
in, which is issue #13's deliberate choice and the reason reading one back is safe at all.

A finding too long to record is **refused on the way out** rather than truncated: a baseline that
cannot be reloaded is not a baseline, and a shortened message would be compared against text the
file does not contain. Saves go through a temporary file and a rename, so a machine that dies
mid-write cannot leave a half-written baseline the next `--diff` reads as though somebody chose it.

#### What a baseline does not contain

Findings and comparability facts. **Not the ATR, not the file tree, not the notes, not the APDU
log** - a baseline is a local artifact that lands in a CI workspace, and the narrower it is the
less of the card it carries around. A test asserts the key set. `*.baseline.json`, `baseline.json`,
`baseline-*.json`, `*-baseline.json` and `.baselines/` are all in `.gitignore`.

### Rule IDs

Use the `plugin/rule` namespaced form, e.g. `filesystem/unreadable-ef`,
`auth/scp03-missing-mac`, `gsma/msl-zero-allowed`. Stable and greppable. Rules are
addressable by agents, so an ID must never be renamed casually.

### Findings

One thing a rule found. The body below is fixed by [src/rules.rs](src/rules.rs) and
pinned byte for byte by a test; **the envelope around it does not change to accommodate
it**, because a finding is serialized *into* `payload.data`, not wrapped by it.

```json
{
  "rule": "filesystem/unreadable-ef",
  "severity": "high",
  "severity_rank": 3,
  "message": "EF.ICCID could not be selected: 9804",
  "location": { "kind": "file", "path": "3F00/2F00/6F07", "access": "forbidden", "status": "9804" },
  "evidence": { "kind": "bytes", "octets": "a4000a4f", "omitted": 0 },
  "coverage": { "status": "complete" }
}
```

Key order is not contract. `serde_json` orders an object's keys itself; only the names
are.

Four things about that object are contract rather than implementation detail, and each
exists because getting it wrong breaks somebody downstream:

- **`rule` is the address.** It is validated at construction *and re-validated on the
  way back in from a baseline file*, so a hand-edited baseline cannot inject an ID
  that could never have been registered. Two rules may never share one ID, and a rule
  may only emit its own; `rules::Registry` refuses both, at registration and at
  evaluation.
- **`location.access` keeps absent, forbidden and refused apart**, using the four
  spellings `walk` already reports: `selected`, `absent`, `forbidden`,
  `refused`. A finding produced from a forbidden file and one produced from an
  absent file are different findings - an access control versus an empty card - and a
  consumer must be able to tell them apart without reading `message`.
- **`coverage` says whether the scan that raised it finished.** A finding from a
  truncated scan may still be entirely true; what cannot be claimed is that the card
  holds no others. `{"status": "partial", "reason": "..."}` means **the list may be
  short**, not that anything in it is wrong. Read it before treating findings as
  exhaustive, and note it travels on each finding rather than only on the report,
  because an agent that greps one rule ID reads one object.
- **Evidence is bounded.** `MAX_EVIDENCE_BYTES` (64 octets of card data) and
  `MAX_EVIDENCE_CHARS` (64 characters of rule text), enforced at construction by types
  with private fields so naming a variant cannot bypass them, and `omitted` reports
  whatever was dropped. A rule must not be able to fill a terminal or an agent's
  stdout with a 64 KB elementary file.

```
sim-doctor scan --json | jq '.data.findings[] | select(.rule == "gsma/msl-zero-allowed")'
```

### TAR scanning and MSL=0

A TAR is a three-octet value a network uses to route an SMS payload to one
application on a card. **A card running at MSL 0 accepts ANY command under ANY
TAR with no cryptographic verification**, so the security question is not "can
this card be attacked" but "which TARs will it act on". `gsma/msl-zero-allowed`
answers the sharpest form of it: does this card act on TAR `000000`?

Three things about this feature are contract, and each of them exists because
the naive version of it is wrong.

#### A TAR reaches a card inside an ENVELOPE, and the ENVELOPE is two exchanges

There is no TAR in a bare command header. The chain is: a 3GPP TS 03.48
Command Packet holding the TAR, inside a TS 23.040 SMS-DELIVER TPDU, inside an
ISO/IEC 7816-4 SMS-PP-DOWNLOAD envelope (BER-TLV tag `D1`), inside an ENVELOPE
command. [src/tar.rs](src/tar.rs) reproduces it octet for octet from SIMTester
at `d197fef`; the tests pin the bytes against those constants.

**The ENVELOPE cannot be sent in one APDU.** swSIM answers the opening with a
`61 Lc` procedure byte *before reading a single octet of the data field* [V]
(swSIM `src/apduh.c`, `apduh_etsi_cat_envelope`: with `procedure_count == 0`
and `*cmd->p3 > 0` it sets `SWICC_APDU_SW1_PROC_ACK_ALL`, copies nothing out of
`cmd->data`, and returns). A scanner that transmits the whole envelope inline
and moves on **leaves the card holding half a command**: the next APDU is
swallowed as this one's continuation and every later probe is answering about
the wrong TAR. So the probe is the opening `CLA INS P1 P2 Lc`, then exactly
`Lc` octets, and the scanner abandons the scan rather than continue if the card
asks for anything else.

#### "Accepted" is a measurement, not a status word

A TAR is reported **accepted** when the card's answer to it **differs from the
answer it gives to TARs it has no opinion about**. That is a differential and it
is SIMTester's own algorithm: `-stbs` runs `TARScanner.tryBeingSmart`, which
probes twenty TARs, counts the responses, and declares **the most common one to
be the false response**.

**No status word is hard-coded as "refused", because this project cannot cite
one.** AGENTS.md blocker 2 records that no 3GPP TS 31.111 text has been read
here, and the only card this project has talked to contradicts the obvious
guess: swSIM answers GSM SELECT of a missing file with `94 04` [V] (swSIM
`src/apduh.c`, `apduh_gsm_select`, `/* "File ID not found" */`). On that card
`94 04` demonstrably does **not** mean "the TAR was refused". The baseline is
therefore measured on every scan and published in `data.tar.baseline`.

**This is what stops the rule manufacturing findings, and the fixture proves it.**
swSIM's proactive application recognises exactly one envelope root tag, `D3`
(Menu Selection) [V] (swSIM `src/proactive.c`, `proactive_app_default__envelope`,
`root_tag = {0xD3}`). It has no notion of `D1`, no notion of a TAR and **no
notion of an MSL at all**. Every SMS-PP-DOWNLOAD envelope on that card, TAR zero
included, is swallowed and answered `90 00`. A scanner that read `90 00` as
"accepted" would raise a critical MSL=0 finding for all 656 probes, on a card
with no TAR check to find. The differential absorbs it: the modal response is
`90 00`, so nothing is reported. **A card that answers every TAR identically
reports nothing, and on a card with no TAR check that is the correct answer
rather than a miss.** When even a baseline cannot be established - the responses
tied, or carried no status word - `data.tar.blind_spot` says so in words and
nothing is raised.

#### The probe count is bounded, and the range is justified

The TAR space is 16 777 216 values. **Nothing here will send them all to a
card.** `tar::MAX_PROBES` caps one scan at **4096** whatever `--tar` asks for; a
selection that runs past it stops there, reports `data.tar.stopped`, and every
finding it carries is marked `partial` rather than read as an exhaustive audit of
the card's TAR allow-list.

`--tar` takes `off`, `focused` (the default), `full`, `range:FIRST-LAST` or
`regex:PATTERN`, mirroring SIMTester's `-st full` / `-str` / `-stre`. **The
focused default is 656 TARs**, taken from SIMTester's own band list
(`TARScanner.prepareTARlist`) and narrowed: `000000`-`0000FF` (which contains TAR
zero), the five `00NN0F` bands, `3F0000`-`3F003F`, and `BFFF00`-`BFFFFF`. SIMTester's
list also contains every three-character permutation of printable ASCII - which
is where real OTA service TARs come from, since a TAR is chosen to look like an
SMS originator address - but that is over 400 000 values, which does not fit the
bound and is why `-str` there takes coffee. An operator who wants them says
`--tar range:200000-7FFFFF`.

A regex is matched against the **six-hex-digit** spelling, so it is six
characters or it can never match. **This is not what SIMTester's `-stre` does**:
`TARScanner.analyseResponse` applies its pattern to `currentResponse`, the
card's *response*, and skips the TAR whose response matched [V]. That is a
response filter rather than a TAR selector. Both halves exist here and are
named apart - `--tar regex:` chooses which TARs to probe, and every response is
recorded per probe under `data.tar.probes`.

### Severity and score

`--severity <level>` and `--score <flag>` are implemented (issue #14) and both land in
`payload.data`. The order they are applied in is part of the contract: **the filter runs
first, and the score is taken from what is reported.** `scan --severity high --score`
scores the high and critical findings and nothing else, and says so in
`data.score.scored_findings`. That ordering is the whole of "a score must not hide a
finding" - the number in the report is a function of the `findings` array beside it, so the
two can never disagree about what was found.

#### The filter is a filter, not a mask

A finding below the level is **removed**, not marked: no entry, no contribution to
`data.findings.count`, and **no rule ID anywhere in the document**. Not a zeroed entry, not
an empty placeholder, not a `"suppressed": true` flag carrying the ID. A consumer that counts
and a consumer that greps for `gsma/msl-zero-allowed` both see the same set, and a set that
one of them can still see in the document is a set the other is counting wrong.

The level in force is reported as `data.findings.severity_threshold`, because a short list
is otherwise indistinguishable from a quiet card. `null` means nothing was filtered, which is
different from `"info"` - the first is every finding, the second is every finding the ladder
can spell. Coverage is **recomputed from the survivors** rather than carried over, because
the filtered value describes a different, smaller set than the one it came from.

It does not filter the **walk**. `data.complete`, `data.truncated`, `data.truncated_by` and
`data.limits_hit` are untouched, so raising the level can never make a truncated scan look
like a whole one.

#### The formula

This is the sentence a reader of a scan report needs, and it is published as
`rules::SCORE_FORMULA` so the formula is *shipped* rather than merely implemented:

```text
max(0, 100 - sum(penalty[severity] for every finding in this report))
```

with the penalty table, indexed by `severity_rank` and published as `rules::SCORE_PENALTY`:

| Severity | `severity_rank` | Penalty |
|---|---|---|
| `info` | 0 | 1 |
| `low` | 1 | 3 |
| `medium` | 2 | 10 |
| `high` | 3 | 25 |
| `critical` | 4 | 50 |

The score is an **integer**. Nothing reads a clock, a hash iteration order, a locale or an
environment variable, so the same findings always produce the same number and a CI threshold
is an integer comparison. The sum is a `u64` and is **clamped, not truncated**: a penalty at or
past 100 saturates to exactly 0. A truncating cast would turn a penalty of 256 into 0 and
report a dirty card as 100, which is the one number this must never be able to say.

**These penalties are a chosen ladder, not measurements.** There is no published
CVSS-equivalent for a SIM and this project has not derived one. The shape of the choice is
that each rung costs several times the one below it, so a handful of `info` findings cannot
bury a `high` one and a `critical` costs half the scale on its own. They are contract: a CI
threshold written against them stops meaning the same thing if they move, so changing one is
a decision to record in CONTEXT.md, not a tune.

#### The number a reader can rebuild from the document alone

`--score` does not print a bare number. `payload.data.score` carries:

| Field | |
|---|---|
| `value` | the score, 0 to 100 |
| `max` | the top of the scale, 100, so a reader of `value` alone still knows the ceiling |
| `penalty` | the total subtracted, so `max - penalty` can be checked without re-deriving it |
| `scored_findings` | how many findings the score was computed from |
| `rules_run` | how many rules the scan evaluated |
| `formula` | the sentence above, verbatim |
| `penalties` | the whole table, keyed by severity spelling |
| `warning` | non-null when there was nothing to score - see below |

**`scored_findings: 0` is not automatically a clean card, and `rules_run` is
what tells the two apart.** A score of 100 from an empty finding set is
otherwise indistinguishable from a card that passed. **The card fixture proved
why in issue #24**: on a live swSIM card the scan reports `rules_run` 1,
`scored_findings` 0, `value` 100, `warning` null - which is a rule that looked
and found nothing, a verdict - and before any rule existed the same 100 carried
a warning string saying nothing had been checked at all. Those are the same
number with opposite meanings, and the difference between them is exactly one
integer.

So the contract is: while `rules_run` is 0 the block carries a warning string
saying in words that nothing on this card was checked, and the human report
prints the same warning. A scan that runs a rule and finds nothing has *earned*
its 100 and the warning is null. A CI gate that reads `value` without reading
`rules_run` is still making a mistake, and this is documented rather than
defended against, because a contract that cannot be broken cannot be relied on.

**This is also why a TAR scan that cannot decide anything is loud.** The swSIM
card has no TAR check at all, so a scanner that read its answer literally would
report TAR zero accepted. It does not, because the TAR verdict is a
*measurement* against a baseline rather than a status word this tool guessed at,
and `data.tar.blind_spot` says so in words when even that could not be
established.


#### Proving the three copies still agree

The formula lives in three places: `rules::SCORE_FORMULA`, the `score` block of every
JSON report, and this section. A test reads this file and asserts the other two still say the
same thing, so a reworded constant cannot leave a reader holding a formula that computes
something else.

### JSON envelope

The best existing model is `lpac`, which returns a single envelope for everything:

```json
{ "type": "lpa", "payload": { "code": 0, "message": "ok", "data": {} } }
```

Adopt this shape. `type` identifies the response, `payload.code` a machine-checkable
status, `payload.data` the body.

---

## 4. Dependency gotchas

Full manifest with rationale in [Cargo.toml](Cargo.toml). These four will cost real time:

### 4.1 Do NOT pin the obvious crypto versions

`milenage 0.3.1` requires `aes ^0.9`, `sha2 ^0.11`, `hmac ^0.13` [V]. Those ARE the latest
stable lines. Pinning `aes 0.8` / `sha2 0.10` / `hmac 0.12` - the versions most tutorials
show - selects the previous major line and will not satisfy milenage at all.

### 4.2 `der` does not parse BER-TLV

`der 0.8.2` is strict DER [V]. It rejects the non-minimal BER lengths common in real SIM and
SGP.22 BPP payloads. It is NOT a drop-in BPP parser.

Keep `der` for actual DER, i.e. certificates.

#### 4.2.1 Which BER-TLV library: none. RESOLVED by issue #11 [V]

This section used to nominate `iso7816-tlv 0.4.4` or `flexiber 0.2.0`. Issue #11 read
both at those versions and **removed both from `Cargo.toml`**. BER-TLV is
[src/tlv.rs](src/tlv.rs), hand-rolled, and the strict DER counterpart is
[src/der.rs](src/der.rs), a separate module with separate types.

Why, in the order the arguments actually carried weight:

- **`iso7816-tlv` 0.4.4 reads an indefinite length (`80`) as length zero** instead of
  rejecting it (`ber/tlv.rs`, `Tlv::read_len`: `n_bytes == 0` means the loop runs zero
  times). A decoder that answers a question instead of saying it cannot is the worst
  failure mode available, and `tlv::Error::IndefiniteLength` exists to prevent it.
- It **owns and copies** every value into nested `Vec`s (`Value::Primitive(Vec<u8>)`,
  `Value::Constructed(Vec<Tlv>)`). A card file body is up to 65535 octets and a scan walks
  dozens of them; `Tlv<'a>` borrows out of the response buffer instead.
- It **rejects a single-octet tag whose low five bits are all set** (`Tag::try_from` returns
  `InvalidInput` for `7F`) because it decodes the identifier octet as a multi-octet BER
  tag. That is the class-bit question `Tag` deliberately leaves open.
- Its **encoder is not canonical**: `Tlv::inner_len_to_vec` tests `l < 0x7f` rather than
  `l <= 0x7f`, so a re-encode writes a 127-octet value as `81 7F`.
- **`flexiber` 0.2.0's length rules are behaviourally identical to ours** - short form
  below `0x80`, `80` rejected, `81`/`82` accepted non-minimally, `83`+ rejected
  (`length.rs`, `impl Decodable for Length`). That is real validation of the design. But it
  keeps only the parsed length and **discards the form it arrived in**, which is exactly
  what `tlv::Length` exists to preserve, and it is BER-only so it could not have supplied
  the strict half either.
- Decisive: **the acceptance criterion is that the non-minimal tolerance be tested here.**
  Delegating the decoder delegates the property, and a property this repository cannot
  assert is not a property this project has.

Adding a BER crate later would mean rewriting `tlv.rs`, not wrapping it. Do not re-add
these without reopening that decision in CONTEXT.md.

### 4.3 Yanked versions to avoid

`aes 0.9.0`, `der 0.8.0`, `crossterm 0.28.0` [V]. Pin 0.9.3 / 0.8.2 / 0.29.0.

### 4.4 `rand_core` alignment - RESOLVED, do not downgrade

`rand 0.10.3` alongside `p256 0.14` / `ecdsa 0.17` **works as pinned** [V]. The alignment
question is closed, and it was closed by compiling, not by reading:

```
cargo generate-lockfile && cargo tree -d
cargo build          # full stack compiles in ~26s
```

Observed results:

- `rand_core` resolves to a **single** version, `0.10.1`. No drop needed.
- The only duplicated crates are `hashbrown` 0.16/0.17 and `syn` 2.0/3.0. Both benign.
- The lockfile pins 284 packages.

The old instruction to "drop to whichever `p256` accepts" is withdrawn. There is nothing to
drop. Do not downgrade `rand` to make a trait error go away; if you ever see one, it is a
real incompatibility introduced by a later dependency change, not this original problem.

### 4.5 `der` / `oid` pairing with p256 / ecdsa - RESOLVED

`der` resolves to a **single** version, `0.8.2`, and it is the *same instance* that `p256`
`0.14`, `ecdsa` `0.17`, `spki` `0.8` and `sec1` `0.8` all consume [V]:

Run `cargo tree -i der` to see it. The command reports one `der` node at `0.8.2`, with
`sim-doctor` as a direct dependent and these as the other dependents, all at the same version:
`ecdsa 0.17.0` (which reaches `p256 0.14.0`), `pkcs8 0.11.0`, `sec1 0.8.1` and `spki 0.8.0`.
(Summarised from the real output rather than pasted, so the point is the single version, not
the exact tree shape - re-run the command for that.)

So the direct `der = "0.8.2"` dependency and the one reached through the ECC stack are the
same crate. Signature DER encoding interoperates with `ecdsa` without an adapter, and the
`oid` version pairs with it cleanly.

This does **not** weaken section 4.2. `der` is still strict DER and still will not parse
BER-TLV from real SIM files or SGP.22 BPP payloads. Resolving the version pairing fixed a
dependency-compatibility question, not a format question.

---

## 5. Domain reference - verified facts

Distilled from [docs/research-report.md](docs/research-report.md). All `[V]` unless noted.

### 5.1 Reference implementations and where they live

| Tool | Repo | SHA | Language |
|---|---|---|---|
| SIMTester | `srlabs/SIMTester` | `d197fef` | Java, GPL |
| pySim | `osmocom/pysim` | `3c437d4` | Python (branch `master`) |
| SIMurai | `tomasz-lisowski/simurai` | `2027a78` | C, BSD-3 |
| swSIM | `tomasz-lisowski/swsim` | - | C, BSD-3 |
| swICC | `tomasz-lisowski/swicc` | - | C, BSD-3 |
| swICC-pcsc | `tomasz-lisowski/swicc-pcsc` | - | C, BSD-3 |
| jCardSim | `licel/jcardsim` | `41511ec` | Java (branch `master`) |
| LPA tool | `estkme-group/lpac` | `82ada9e` | C, 730 stars |
| eUICC-RSP | `waigel/euicc-rsp` | `df87411` | C |
| eUICC-LPA | `waigel/euicc-lpa` | - | C |
| virtual-rsp | `Lavelliane/virtual-rsp` | `1eab1cc` | C + Python |
| GlobalPlatform | `kaoh/globalplatform` | `877bbe1` | C, LGPL |
| YggdraSIM | `1oT/YggdraSIM` | `31cdf7d` | Python |

**Correction worth remembering:** these owner/name pairs were wrong in first-pass research.
`fgsect/SIMTester`, `perso/pySim`, `PostPigeon/lpac`, and `ThalesGroup/euicc-rsp` do NOT exist.
`ThalesGroup/euicc-lpa` does NOT exist. YggdraSIM is Python by 1oT, not Rust by tomasz-lisowski.

### 5.2 SIMTester capabilities to replicate

- MSL=0 detection via TAR scanning [V]
- OTA fuzzer (`-of` / `--ota-fuzz`) [V]
- FileScanner: `-sf` from MF 3F00, `-sfb`, `-sffs`, `-sfrv` [V]
- TAR scanner: `-st full 0x000000-0xFFFFFF`, `-str` ranged, `-stbs` smart, `-stre` regex [V]
- Base fuzzer: ~130 TARs x 15 keysets x 16 mechanisms; `-qf` quick, `-poke`,
  `-kic` / `-kid` / `-spi1` / `-spi2` [V]

Note: `FuzzerFactory.java` is a fuzzer factory, NOT an APDU fuzzer factory. APDU discovery is
a separate `APDUScanner.java` (`-sa LEVEL 1` CLA via OTA, `-sal2` LEVEL 2 CLA+INS) [V].

### What issue #24 read in SIMTester's TAR scanner [V]

Everything above about the reference is read out of `srlabs/SIMTester` at the
pinned SHA `d197fef`, not recalled. The four facts worth not rediscovering:

- **The TAR is three octets and there is no header encoding for it.**
  `TARScanner.HIGHEST_TAR = 16777215` ("this is 0xFFFFFF"), and a TAR reaches a
  card only inside an SMS-PP-DOWNLOAD envelope.
- **The envelope is `80 C2 00 00 <data>`** (`Envelope.getAPDU`, 3G branch), built
  from a TS 03.48 Command Packet (`CommandPacket._formatMessage`), a TS 23.040
  SMS-DELIVER TPDU (`SMSDeliverTPDU.getBytes`) and a `D1` BER-TLV
  (`EnvelopeSMSPPDownload`). ISO/IEC 7816-4 numbers ENVELOPE `CA`; the two
  implementations agree on `C2` and this crate follows them.
- **`-stbs` is a differential, and that is the algorithm.**
  `TARScanner.tryBeingSmart` probes twenty TARs, counts the responses and declares
  **the most common one to be the false response**, skipping anything equal to it.
  `analyseResponse` calls that "GOT VALID TAR!!" for anything else. A TAR is
  reported when the response carries a TS 03.48 Response Packet whose status code
  is not 9, or when the response is not an error at all.
- **`-stre` filters on the RESPONSE, not on the TAR.**
  `analyseResponse` matches `_regexp_to_match_response_pattern` against
  `currentResponse`, so it skips a TAR *whose answer* matched. This crate's
  `--tar regex:` is a TAR selector instead, and the response side of the
  comparison is reported per probe.

`prepareTARlist` is also where the focused range came from: `-str` builds its
list from every three-character permutation of printable ASCII plus the hex
bands listed in [TAR scanning and MSL=0](#tar-scanning-and-msl0). The
permutations are over 400 000 values, which is why `-str` there says "go get a
(few) coffee(s)" and why this crate caps its own sweep.

### 5.3 pySim-shell command surface

~120 commands [V]. Namespaced by vertical, which is a good structural precedent:

- Files: `desc`, `dir`, `tree`, `fsdump`, `export`, `verify_adm`, `reset`
- Binary/record: `read_binary`, `update_binary`, `edit_binary`, `read_record`, `update_record`
  (each with a `_decoded` variant)
- Data/TLV: `retrieve_data`, `set_data`, `del_data`, `retrieve_tags`, `get_data`, `store_data`
- Keys/security: `put_key`, `delete_key`, `authenticate`, `change_chv`, `unblock_chv`,
  `verify_chv`, `establish_scp02`, `establish_scp03`, `release_scp`
- CAP: `load`, `install_cap`, `install_for_personalization`, `install_for_install`,
  `install_for_load`, `delete_card_content`
- eUICC/LPA: `get_euicc_info1`, `get_euicc_info2`, `get_euicc_challenge`, `get_eid`,
  `list_notification`, `get_profiles_info`, `enable_profile`, `disable_profile`,
  `delete_profile`, `euicc_memory_reset`, `es10x_store_data`, `get_certs`
- Services: `est_service_*`, `ist_service_*`, `ust_service_*`, `sst_service_*`, `aram_*`
- Utility: `apdu`, `apdu_trace`, `numeric_path`, `json_pretty_print`, `bulk_script`,
  `conserve_write`

### 5.4 lpac CLI - best existing agent-friendly contract

Four verb groups [V]: `chip` (info / defaultsmdp / purge), `profile` (list / nickname / enable /
disable / delete / download / discovery), `notification` (list / process / remove), `driver`
(apdu / http / list). Backend selection via env: `LPAC_APDU` = pcsc|at|at_csim|stdio,
`LPAC_HTTP` = curl|stdio.

### 5.5 GlobalPlatform C library

`kaoh/globalplatform`. **Prefix is `OPGP_`, not `GP_`** [V]. Grepping `GP_*` returns only
export/visibility macros - a trap.

43 public functions. Main API: `OPGP_establish_context`, `OPGP_card_connect`,
`OPGP_release_context`, `OPGP_select_application`, `OPGP_select_channel`, `OPGP_manage_channel`,
`OPGP_read_executable_load_file_parameters`, `OPGP_extract_cap_file`, `OPGP_cap_to_ijc`,
`OPGP_calculate_key_check_value`, `OPGP_encrypt_sensitive_data`, `OPGP_get_cplc`.
Connection: `OPGP_list_readers`, `OPGP_send_APDU`, `OPGP_send_chained_APDU`,
`OPGP_send_chained_APDU_extended`, `OPGP_enable_trace_mode`.

Key derivation methods: `GP_DERIVATION_METHOD_EMV_CPS`, `GP_DERIVATION_METHOD_VISA` [V].

GPShell3 DAP token family: `sign-load-token`, `sign-install-token`, `sign-delete-token`,
`sign-extradition-token`, `sign-update-registry-token`, `sign-dap`, `put-dap-key` [V].

### 5.6 SGP.22 ES9+ / ES10x

ES9+ section mapping [V]:

| Section | Function |
|---|---|
| 5.6.1 | InitiateAuthentication |
| 5.6.2 | GetBoundProfilePackage |
| 5.6.3 | AuthenticateClient |

euicc-rsp implements 3 of 5 ES9+ functions; **HandleNotification and CancelSession are NOT
implemented** [V]. Their section numbers remain `[U]`.

ES10a/b/c all share one generic STORE DATA APDU (SGP.22 5.7.2) [V]:
CLA `80-83`/`C0-CF`, INS `E2`, P1 `11` more blocks / `91` last block, P2 = block number,
<=255 data bytes.

- **ES10b** (eUICC ISD-R write/derive): PrepareDownload 5.7.5, LoadBoundProfilePackage 5.7.6,
  GetEUICCChallenge 5.7.7, GetEUICCInfo 5.7.8, AuthenticateServer 5.7.13, CancelSession
- **ES10c** (profile management): GetProfilesInfo 5.7.15, EnableProfile 5.7.16, DeleteProfile 5.7.18
- **ES10a** role: `[U]` - GSMA spec unavailable. Best available source is virtual-rsp's README
  ("Local Profile Assistant to Local Discovery Service"), uncorroborated.

### 5.7 SCP03t crypto

- MAC: `CMAC(S-MAC, chain || tag || Lcc || data)`, 128-bit key. **Wire MAC is the 8 MSB of
  the 16-byte CMAC output** [V]
- Cipher: AES-128-CBC. IV = ICV from S-ENC + 16-byte encryption counter [V]
- KDF: ECDH P-256 (SECP256R1) + X9.63 with SHA-256, `SHA-256(Z || counter_be32(i) || info)` [V]
- Key split (Annex G), L=16: 1..L = initial MAC chaining value, L+1..2L = S-ENC, 2L+1..3L = S-MAC [V]
- SharedInfo: `keyType(1) || keyLen(1) || HostID-LV || EID-LV`. **HostID is NOT the EID** [V]

### 5.8 BPP tag semantics

Group order per SGP.22 2.5.4 [V]:

1. `initialiseSecureChannelRequest` - in clear
2. `firstSequenceOf87` = ConfigureISDP - tag `'87'`, encrypted + MAC'd
3. `sequenceOf88` = StoreMetadata - tag `'88'`, **MAC-only, never encrypted**
4. `secondSequenceOf87` = Profile Protection Keys - NOT implemented upstream
5. `sequenceOf86` = Protected Profile Package - tag `'86'` segments

**All three tags advance ONE shared MAC chaining value**, not three independent counters [V].
Segmentation: 1020-byte max segment, 1008 usable, 1007 bytes PPP payload after padding [V].
Padding always 1-16 bytes, never all-zero [V].

### 5.9 Signing and test PKI

- **RFC 6979 deterministic ECDSA** [V]. Signature format is **plain `r||s`, 64 bytes, NOT DER**
  (SGP.22 2.6.7.2 -> GPCS v2.2 Amendment E 3.1.3, SHA-256).
- SGP.26 test certs live in `waigel/euicc-rsp/testdata/sgp26/` [V]. Both DP certs **expire
  30 March 2030** [V].
- `euicc.der` is a **re-issuance**: asn1c's `CertificateSerialNumber_t` is a native `long` and
  the real cert's 9-octet serial overflows it [V]. Production-relevant, not a test artifact.
- This is SGP.26 **test PKI material**, not a conformance harness [U].

### 5.10 virtual-rsp - what it is NOT

Do not model it as a conformant RSP server [V]:

- InitiateAuthentication / AuthenticateClient are **client-side demos that POST to an external
  SM-DP+**. The agent is the caller, not the server.
- No BPP builder. No SCP03t. No AES-CMAC, AES-CBC, ECDH, or X9.63 anywhere in the repo.
- Does NOT use RFC 6979 - its Python path uses random-nonce ECDSA.
- What it does implement: ES10x eUICC-side commands over a custom `VEUC` binary protocol.
  ES10a functions are explicit stubs (`v_euicc_core.c:541`).
- Its README self-scores "95.0% EXCELLENT" with no test evidence. Treat as demo harness.

---

## 6. Open blockers and unverified facts

Do not treat any of these as settled.

| # | Item | Status |
|---|---|---|
| 1 | ~~`rand_core` alignment~~ | **RESOLVED** [V] single `rand_core 0.10.1`, no drop needed. See 4.4 |
| 2 | GSMA SGP.22 spec text | **RESOLVED** [V] public: SGP.22 v2.5 PDF at `https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/05/SGP.22-v2.5.pdf` returns HTTP 200 (checked 2026-10-07). The earlier 404s were wrong URLs, not a member gate |
| 3 | ES10a's actual responsibility | `[U]` until checked against SGP.22 v2.5 (now readable, see blocker 2) |
| 4 | HandleNotification / CancelSession section numbers | `[U]` until checked against SGP.22 v2.5 (now readable, see blocker 2) |
| 5 | GSMA TS.48 test profiles | **RESOLVED** [V] public under Apache-2.0 in GSMA's own repo `https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public` (v7.1 spec, profile structure, SAIP 2.3 package). #25 re-scoped, #26 closed |
| 6 | ~~`der` / `oid` pairing~~ | **RESOLVED** [V] single `der 0.8.2`, shared with p256/ecdsa/spki. See 4.5 |

### On blocker 2 (resolved 2026-10-07)

SGP.22 is published by GSMA without a login: v2.5 at `https://www.gsma.com/solutions-and-impact/technologies/esim/wp-content/uploads/2023/05/SGP.22-v2.5.pdf`
(HTTP 200, PDF). The 404s recorded earlier came from guessed `wp-content/uploads` paths.

Consequence: the section numbers in 5.6 and 5.7 still come from euicc-rsp's source comments
and stay `[U]` until someone checks each one against SGP.22 v2.5. Any issue touching the eUICC
half (#17, #18, #20, #23) checks the numbers it uses against the PDF and upgrades them to `[V]`.

### On blocker 5 - TS.48 (resolved 2026-10-07)

GSMA publishes TS.48 itself under Apache-2.0: `https://github.com/GSMATerminals/Generic-eUICC-Test-Profile-for-Device-Testing-Public` holds the v7.1 document, the profile
structure spreadsheet and the SAIP 2.3 profile package.

What TS.48 actually is: a *test profile*, the eSIM contents (file system, applications, test
keys) that a test eUICC carries for device testing. It is not a list of APDU test cases with
expected outcomes. So issue #25 is re-scoped from a generic test-case runner to: parse the
public TS.48 profile package and compare a card's file system against it (read-only).
Issue #26 is closed: there is no access blocker.

---

## 7. Where to look

| Question | File |
|---|---|
| How do I build / test this? | [CONTEXT.md](CONTEXT.md) section 4 |
| What is the full research with citations? | [docs/research-report.md](docs/research-report.md) |
| What is the dependency set and why? | [Cargo.toml](Cargo.toml) + section 4 above |
| What is the output contract? | Section 3 above |
| What protocol facts can I trust? | Section 5 above, `[V]` tags only |


