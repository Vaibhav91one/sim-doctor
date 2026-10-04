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
| 130 | Interrupted by user (SIGINT) |
| 129 | Invalid usage / bad arguments |

### Flags

- `--json` - structured output on stdout, nothing else on stdout
- `--score` - single numeric quality score for CI gating
- `--severity <level>` - filter to a minimum severity
- `--baseline <file>` / `--diff` - regression gating against a saved run

### Rule IDs

Use the `plugin/rule` namespaced form, e.g. `filesystem/unreadable-ef`,
`auth/scp03-missing-mac`, `gsma/msl-zero-allowed`. Stable and greppable. Rules are
addressable by agents, so an ID must never be renamed casually.

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

Use `iso7816-tlv 0.4.4` (preferred, scoped to ISO/IEC 7816-4) or `flexiber 0.2.0` for BER-TLV.
Keep `der` for actual DER, i.e. certificates.

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

```
cargo tree -i der
# der v0.8.2
# |- ecdsa v0.17.0 -> p256 v0.14.0
# |- pkcs8 v0.11.0 -> elliptic-curve v0.14.1
# |- sec1 v0.8.1, spki v0.8.0
# '- sim-doctor v0.1.0
```

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
| 2 | GSMA SGP.22 spec text | **GATED, CONFIRMED UNAVAILABLE** - owner has no member access. Both public PDF paths 404 under a browser UA. Do not retry with curl |
| 3 | ES10a's actual responsibility | `[U]` traces to blocker 2 |
| 4 | HandleNotification / CancelSession section numbers | `[U]` traces to blocker 2 |
| 5 | GSMA TS.48 conformance test profiles | **KNOWN-BLOCKED** - profile CONTENT is behind the same GSMA login as blocker 2. The RUNNER is in scope (#25); authoring profiles is not, until access exists |
| 6 | ~~`der` / `oid` pairing~~ | **RESOLVED** [V] single `der 0.8.2`, shared with p256/ecdsa/spki. See 4.5 |

### On blocker 2

This is **not** a tooling problem and **cannot be fixed with curl**. Both plausible
`gsma.com/wp-content/uploads` PDF paths return HTTP 404 under a browser UA. The spec is behind
a GSMA member login.

Consequence: every SGP.22 section number in section 5.6 comes from euicc-rsp's own source
comments, not from the spec. That is decent provenance - the repo cites section numbers
consistently and matches at pinned SHA - but it is not primary. If member access becomes
available, verify 5.6 and 5.7 before shipping the eUICC half.

### On blocker 5 - TS.48 scope decision

**Decided by the owner: TS.48 is in scope as a RUNNER, not as transcribed profiles.**

TS.48 *is* the conformance test profile definitions, so it sits behind the same GSMA member
login as blocker 2. Transcribing profiles we cannot read was never available. What is
available, and what we are building, is the **executor**: a runner that consumes profile files
supplied by an operator who does have access, runs them against a card, and reports per-test
verdicts through the standard JSON contract. That is issue #25.

Two consequences to keep straight:

- The runner's own conformance to TS.48 is **unverifiable** without the spec. Document it as
  such. Do not let "TS.48 support" in the README imply a conformance claim we cannot back.
- Self-authoring a few smoke profiles from SIMTester behaviour is **rejected**, not deferred.
  They would be tagged `[U]` and would manufacture a false impression of conformance coverage.

Profile authoring stays tracked as issue #26, open and blocked, with its unblock condition
written down. It is not dropped.

---

## 7. Where to look

| Question | File |
|---|---|
| How do I build / test this? | [CONTEXT.md](CONTEXT.md) section 4 |
| What is the full research with citations? | [docs/research-report.md](docs/research-report.md) |
| What is the dependency set and why? | [Cargo.toml](Cargo.toml) + section 4 above |
| What is the output contract? | Section 3 above |
| What protocol facts can I trust? | Section 5 above, `[V]` tags only |


