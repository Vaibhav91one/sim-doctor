# SIM Security CLI - Consolidated Research Report

All content below was produced by verification subagents reading primary sources in-session.
Confidence tags: **[V]** verified from primary source this session / **[U]** unverified or inferred.

---

## 0. Subagent outcomes (what happened, for the record)

| Agent | Task | Outcome |
|---|---|---|
| B `9865cef3` | React Doctor CLI UX audit | Complete. Findings already incorporated. |
| A `cbb7199f` | SIM tool feature scan | **Crashed** (GitHub 403 rate limits + raw 404s). Recovered partial report, but **4 of 7 repo names wrong** and 1 claim fabricated. Superseded by V1. |
| C `fa55fe21` | Rust crate list | **Behavioral failure.** Completed research, announced deliverable 3x, emitted zero output on 3 interruptions. Superseded by V3. |
| V1 `0a383967` | Verify SIM tool features | Complete. Major corrections to A. |
| V2 `2d08cd5e` | Verify SGP.22 protocol | Complete. One A claim largely false. |
| V3 `699a60c7` | Verify Rust crate versions | Complete. 32 crates, live crates.io API. |

**Diagnosis: A and C were not looped.** A starved on HTTP 403/404 and died. C completed its research
and failed purely at output emission (announced "here is the deliverable" without ever producing it).
The anti-loop rules added to V1/V2/V3 (data-first reply, no preamble, no send_message handoff,
log-and-move-on on fetch failure) resolved it - V1/V2/V3 all returned clean first-turn reports.

---

## 1. Rust dependencies (V3 - 32 crates, all fetched live from crates.io API)

### Copy-ready Cargo.toml

```toml
[dependencies]
# --- Smartcard transport ---
pcsc    = "2.9.0"   # PC/SC reader bindings (SCard* API). STALE: last publish 2024-12-14
iso7816 = "0.2.1"   # APDU types (CLA/INS/P1/P2/LC/RApdu/statuswords). 0.x - unstable API

# --- SIM crypto ---
milenage = "0.3.1"  # MIL-ENAGE KDF, f1-f5/f5*, auth responses

# --- Symmetric / hash primitives ---
aes  = "0.9.3"      # AES block cipher. 0.9.0 is YANKED
des  = "0.9.0"      # DES/3DES for legacy GSM
cbc  = "0.2.1"      # CBC mode
cmac = "0.8.0"      # AES-CMAC / DES-CMAC (SCP03, GSM auth)
sha2 = "0.11.0"
hmac = "0.13.0"
sha3 = "0.12.0"

# --- ECC (SGP.22 SCP03t) ---
p256  = "0.14.0"    # NIST P-256, otPK/otSK .ECKA keys
ecdsa = "0.17.0"    # RFC 6979 deterministic signing

# --- ASN.1 ---
der = "0.8.2"       # STRICT DER only. 0.8.0 is YANKED. See WARNING 3
oid = "0.3.0"

# --- CLI / TUI ---
clap = { version = "4.6.7", features = ["derive"] }
clap_complete = "4.6.11"
ratatui = "0.30.2"  # 0.28.0 is YANKED; use 0.29.0 for crossterm
crossterm = "0.29.0"
owo-colors = "4.4.0"  # zero-alloc, best fit with ratatui

# --- Serialization / errors ---
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.151"
anyhow = "1.0.104"
thiserror = "2.0.21"

# --- Logging / util ---
tracing = "0.1.44"
tracing-subscriber = "0.3.23"
hex = "0.4.3"        # frozen since 2021, stable
bytes = "1.12.1"
rand = "0.10.3"      # MAJOR LINE JUMP 0.8->0.9->0.10, API changed. See WARNING 2
chrono = "0.4.45"
tokio = { version = "1.53.2", optional = true }  # only for remote-SIM/ATC-UICCS; pure PC/SC is sync

# Alternatives: colored 3.1.1 (no TUI) | termcolor 1.4.1 (Windows color stream)
```

### Three warnings that will cost real debug time

**WARNING 1 - do not pin the "obvious" crypto versions.** [V]
`milenage 0.3.1` requires `aes ^0.9`, `sha2 ^0.11`, `hmac ^0.13` - which are exactly the
latest stable lines. Pinning `aes 0.8` / `sha2 0.10` / `hmac 0.12` (the versions most
tutorials show) selects the *previous major line* and will not satisfy milenage at all.

**WARNING 2 - rand / ECC trait-stack alignment is UNCONFIRMED.** [U]
The crates.io `/dependencies` endpoint returned HTTP 400 on every form tried, so dependency
alignment for `p256 0.14` / `ecdsa 0.17` vs `rand 0.10.3` is unknown. A `rand_core` trait
mismatch (0.9 vs 0.10 era) is plausible. **Resolve at build time with `cargo add` +`cargo tree -d`,
not from a table.** Same unconfirmed status for `der 0.8.2` vs p256/ecdsa DER pairing.

**WARNING 3 - `der` will NOT parse BPP payloads.** [V]
`der 0.8.2` is strict DER and rejects the non-minimal BER lengths common in real SIM/BER-TLV
data. It is **not** a drop-in BPP parser. Hand-roll the TLV walker or add a dedicated BER crate.
This bites early since euicc-rsp and virtual-rsp both lean on asn1c-generated BER-TLV.

### Yanked versions to avoid [V]
`aes 0.9.0` · `der 0.8.0` · `crossterm 0.28.0` -> pin 0.9.3 / 0.8.2 / 0.29.0

---

## 2. SIM tool landscape (V1 - corrects A)

### Corrections to the earlier scan - 4 repo names were WRONG

| Claimed (A) | Actual (V1) |
|---|---|
| `fgsect/SIMTester` | **`srlabs/SIMTester`** (Java, GPL). Forks: threatcode/, cdeletre/, scintill/ |
| `perso/pySim` | **`osmocom/pysim`** (594 stars). Canonical: `gitea.osmocom.org/sim-card/pysim` |
| YggdraSIM = Rust, tomasz-lisowski | **FALSE on every point.** Real: `1oT/YggdraSIM`, **Python**, by Hampus Hellsberg / 1oT OU |
| `PostPigeon/lpac` | **`estkme-group/lpac`** (C, 730 stars, GSMA SGP.22 v2.2.2, ESTKME TECH Hong Kong) |

A conflated YggdraSIM with SIMurai/swSIM (which *are* tomasz-lisowski, C).

### Also falsified: pysim Crypto.SIMalliance MILENAGE claim

[V] **Not supported - treat as stale.** pysim `requirements.txt` has no `Crypto.SIMalliance`
(only pyosmocom, pycryptodomex, cryptography). `pyosmocom 0.0.12` depends only on gsm0338 +
construct. Grep of pySim-shell.py / commands.py / gsm_r.py returns **zero** milenage hits.
PyPI `Crypto.SIMalliance` = 404. **MILENAGE is implemented in Rust via the `milenage` crate
instead, not inherited from pysim.**

### Verified capabilities

**SIMTester** [V] - MSL=0 TAR scanning; OTA fuzzer (`-of`/`--ota-fuzz`); FileScanner
(`-sf` from MF 3F00, `-sfb`, `-sffs`, `-sfrv`); TAR Scanner (`-st full 0x000000-0xFFFFFF`,
`-str`, `-stbs`, `-stre` regex); base fuzzer ~130 TARs x 15 keysets x 16 mechanisms;
`-qf` quick, `-poke`, `-kic`/`-kid`/`-spi1`/`-spi2`.
*Correction:* `FuzzerFactory.java` is a "fuzzer" factory, **not** an APDU fuzzer factory. APDU
discovery is a separate `APDUScanner.java` (`-sa LEVEL 1` CLA via OTA, `-sal2` LEVEL 2 CLA+INS).

**pysim** [V] - scripts: pySim-shell.py, pySim-read.py, pySim-prog.py, pySim-trace.py,
osmo-smdpp.py, pySim-smpp2sim.py. `read`/`prog` are explicitly LEGACY; `shell` is recommended.
pySim-shell command surface (~120 commands) grouped:
- Files: `desc`, `dir`, `tree`, `fsdump`, `export`, `verify_adm`, `reset`
- Binary/record: `read_binary`, `update_binary`, `edit_binary`, `read_record`, `update_record` (+ `_decoded` variants)
- Data/TLV: `retrieve_data`, `set_data`, `del_data`, `retrieve_tags`, `get_data`, `store_data`
- Keys/security: `put_key`, `delete_key`, `authenticate`, `change_chv`, `unblock_chv`, `establish_scp02`, `establish_scp03`, `release_scp`, `verify_chv`
- CAP: `load`, `install_cap`, `install_for_personalization`, `install_for_install`, `install_for_load`, `delete_card_content`
- eUICC/LPA: `get_euicc_info1`, `get_euicc_info2`, `get_euicc_challenge`, `get_eid`, `list_notification`, `get_profiles_info`, `enable_profile`, `disable_profile`, `delete_profile`, `euicc_memory_reset`, `es10x_store_data`, `get_eim_configuration_data`, `get_certs`
- Services: `est_service_*`, `ist_service_*`, `ust_service_*`, `sst_service_*`, `aram_*`
- Channels: `open_channel`, `close_channel`, `switch_channel`
- Utility: `apdu`, `apdu_trace`, `numeric_path`, `json_pretty_print`, `bulk_script`, `conserve_write`

**SIMurai** [V] - `tomasz-lisowski/simurai` (267 stars, BSD-3, C). USENIX Security '24 paper
"SIMurai: Slicing Through the Complexity of SIM Card Security Research" (Lisowski, Chlosta,
Wang, Muench - CISPA). Security-focused software SIM: 2G-5G, MILENAGE auth, proactive commands,
TPDU-layer control, **response rewriting**, JSON FS definitions (`./swsim/data/usim.json`).
Runs via SIMtrace2 cardem, FirmWire peripheral, or any PC/SC client.

**swSIM / swICC / swICC-pcsc** [V] (all tomasz-lisowski, C, BSD-3) -
`swsim` (567 stars, "A software SIM card."), `swicc` (142 stars, ICC-based smart card
framework), `swicc-pcsc` (48 stars, PC/SC IFD handler exposing swICC cards via pcscd).

**jcardsim** [V] - `licel/jcardsim` confirmed. Java Card v3.0.5 simulator
(`javacard.framework.*`, `javacard.framework.security.*`, `javacardx.crypto.*`).
APDU tooling: apdutool-compatible scripting, `apdu.script` in repo root with raw hex traces,
`javax.smartcardio` terminal emulation, CardSimulator/CommandAPDU/ResponseAPDU API.
Own `javacard.security` modeled on NXP JCOP 31/36k (ALG_EC_F2M, ALG_RSA_CRT).

**lpac** [V] - `estkme-group/lpac`, all output JSON `{type:"lpa",payload:{code,message,data}}`
- `chip` -> `info` / `defaultsmdp <addr>` / `purge`
- `profile` -> `list` / `nickname` / `enable` / `disable` / `delete` / `download` / `discovery`
- `notification` -> `list` / `process` / `remove`
- `driver` -> `apdu` / `http` / `list`
Backends via env: `LPAC_APDU` = pcsc|at|at_csim|stdio, `LPAC_HTTP` = curl|stdio.
**This is the cleanest CLI UX reference in the whole landscape** - see section 4.

**Adjacent finds** [V] - `estkme-group/openeuicc` (Kotlin, 1080 stars), `creamlike1024/EasyLPAC` (Go, 768).

---

## 3. SGP.22 / eUICC (V2)

### ES9+ section mapping [V]

| Section | Function | Location |
|---|---|---|
| 5.6.1 | **InitiateAuthentication** | `rsp.h:433`, `rsp_es9.c` |
| 5.6.2 | **GetBoundProfilePackage** | `rsp.h:550`, `rsp_es9.c:1069` |
| 5.6.3 | **AuthenticateClient** | `rsp.h:496`, `rsp_es9.c:605-702` |

euicc-rsp implements 3 of ES9+'s 5 functions; **HandleNotification and CancelSession not
implemented** [V]. Their section numbers remain unverified [U].

AuthenticateClient enforcement: transactionId check, serverChallenge check, CERT.EUM then
CERT.EUICC chain validation, euiccSignature1 verify.

### SCP03t crypto [V]

- **MAC:** `CMAC(S-MAC, chain || tag || Lcc || data)`; 128-bit key; **wire MAC is the 8 MSB of
  the 16-byte CMAC output**.
- **Cipher:** AES-128-CBC. IV = ICV from S-ENC + 16-byte encryption counter.
- **KDF:** ECDH P-256 (SECP256R1) + X9.63 with SHA-256, `SHA-256(Z || counter_be32(i) || info)`.
  **Checked against NIST vectors**, not just self-consistency.
- **Key split (SGP.22 Annex G):** L=16; KeyData 1..L = initial MAC chaining value,
  L+1..2L = S-ENC, 2L+1..3L = S-MAC.
- **SharedInfo:** `keyType(1) || keyLen(1) || HostID-LV || EID-LV`. **HostID is NOT the EID.**

### BPP tag usage [V] - group order per SGP.22 2.5.4

1. `initialiseSecureChannelRequest` - **in clear**
2. `firstSequenceOf87` = ConfigureISDP - tag `'87'`, **encrypted + MAC'd**
3. `sequenceOf88` = StoreMetadata - tag `'88'`, **MAC-only, never encrypted**
4. `secondSequenceOf87` = Profile Protection Keys - **not implemented**
5. `sequenceOf86` = Protected Profile Package - tag `'86'` segments

**All three tags advance ONE shared MAC chaining value**, not three independent counters.
Segmentation: 1020-byte max segment, 1008 usable, **1007 bytes PPP payload** after padding.
Padding always 1-16 bytes, never all-zero.

### Signing + test PKI [V]

- **RFC 6979 deterministic ECDSA** - nonce from HMAC-DRBG seeded from private key + message hash.
  Enforced by tests asserting thread-identical signatures.
- **Signature format: plain `r||s`, 64 bytes - NOT DER** (SGP.22 2.6.7.2 -> GPCS v2.2 Amd E 3.1.3,
  SHA-256 per Amd E Table 3-3).
- **SGP.26 test certs present**: ci.der, dpauth.der, dppb.der, ci-2017.der, eum.der, euicc.der.
  `rsp_pki_verify()` chains DPauth/DPpb to test CI + checks cert-key agreement.
  AuthenticateClient verifies CERT.EUM against **both** ci.der and ci-2017.der (same key, two issuances).
- **Caveats:** both DP certs **expire 30 March 2030**. `euicc.der` is a **re-issuance** - asn1c's
  `CertificateSerialNumber_t` is a native `long` and the real cert's 9-octet serial **overflows it**.
  This is a production-relevant limitation, not just a test artifact.
- [U] None of this constitutes SGP.26 *conformance* - it is test PKI material exercising the
  SGP.22 code path, not a conformance harness.

### ES10a / ES10b / ES10c [V]

All three share one generic STORE DATA APDU per SGP.22 5.7.2: CLA `80-83`/`C0-CF`,
INS `E2`, P1 `11` (more blocks) / `91` (last block), P2 = block number, <=255 data bytes.

- **ES10b** - eUICC ISD-R write/derive: PrepareDownload 5.7.5, **LoadBoundProfilePackage 5.7.6**,
  GetEUICCChallenge 5.7.7, GetEUICCInfo 5.7.8, **AuthenticateServer 5.7.13**, CancelSession.
- **ES10c** - profile management: GetProfilesInfo 5.7.15, EnableProfile 5.7.16, DeleteProfile 5.7.18.
- **ES10a role: [U]** GSMA spec PDF 404s. Only source is virtual-rsp's README -
  "Local Profile Assistant to Local Discovery Service". The ES10b/ES10c halves are corroborated by
  the section cites; **the ES10a half is not.**

### virtual-rsp is largely NOT an RSP implementation [V] - corrects A

- **InitiateAuthentication / AuthenticateClient: client-side demos only.** They POST *to* an
  external SM-DP+ at `testsmdpplus1.example.com` - the agent is the **caller**, not a server.
- **GetBoundProfilePackage: absent entirely.** Grep for `BoundProfile|bound_profile|BPP` across
  all `.c/.h/.py/.md` returns **zero hits**. No BPP, no SCP03t.
- **No AES-CMAC, no AES-CBC, no ECDH, no X9.63 anywhere.** Only crypto is OpenSSL ECDSA + SHA.
- **Does not use RFC 6979** - Python path uses random-nonce `ECDSA(hashes.SHA256())`.
- What it *does* implement: ES10x eUICC-side commands over a custom binary protocol
  (magic `VEUC`, CONNECT/OPEN_CHANNEL/TRANSMIT_APDU) - GetEUICCInfo1, GetEUICCChallenge,
  AuthenticateServer, GetEID, GetEUICCInfo2. **ES10a functions are explicit stubs.**
- Its README self-scores "95.0% EXCELLENT" with no test evidence. **Treat as demo harness.**

---

## 4. UX patterns worth stealing

**lpac** [V] - single JSON envelope for everything (`{type, payload:{code,message,data}}`),
global backend selection via `$LPAC_APDU` / `$LPAC_HTTP` env vars, four clean verb groups
(chip/profile/notification/driver). Closest existing analogue to an agent-friendly contract.

**pysim shell** [V] - ~120 commands namespaced by vertical (`est_service_*`, `ist_service_*`,
`aram_*`, `es10x_*`), legacy commands explicitly marked, `apdu` / `apdu_trace` /
`numeric_path` built-in debug verbs, `bulk_script` for headless replay.

**React Doctor** [V, from agent B] - the target UX. exit codes 0/1/130/129; `--json`/`--score`
headless modes; oclif-style `plugin/rule` IDs; severity levels; config files; baseline/diff for
regression gating. This is the model for the agentic CLI surface.

---

## 5. Second pass - git/curl recon (bypasses API rate limits)

Direct `git clone` / `git ls-remote` / raw fetch avoids the GitHub API rate limiter entirely.
Findings below are from local clones at pinned SHAs.

### Repo identity - independently confirmed

| Repo | SHA | Note |
|---|---|---|
| `waigel/euicc-rsp` | `df87411` | **Matches every SHA V2 cited** - line references are trustworthy |
| `waigel/euicc-lpa` | - | V2 used this for ES10 cites; owner is `waigel`, not `ThalesGroup` |
| `ThalesGroup/euicc-rsp` / `ThalesGroup/euicc-lpa` | - | **DO NOT EXIST** (4 owner variants probed, all MISS) |
| `kaoh/globalplatform` | `877bbe1` | GP C library + GPShell3 |
| `estkme-group/lpac` | `82ada9e` | |
| `osmocom/pysim` | `3c437d4` | default branch is `master` |
| `srlabs/SIMTester` | `d197fef` | |
| `licel/jcardsim` | `41511ec` | default branch `master` |
| `1oT/YggdraSIM` | `31cdf7d` | Python confirmed |
| `tomasz-lisowski/simurai` | `2027a78` | |

### RESOLVED: BER-TLV crate (was gap #2, hard blocker)

[V] - not a blocker after all. crates.io search returns purpose-built ISO 7816-4 BER-TLV parsers:

- `iso7816-tlv 0.4.4` - "tools and utilities for handling TLV data as defined in ISO/IEC 7816-4"
  <- **best fit**, since it targets exactly the standard our payloads follow
- `flexiber 0.2.0` - "Encoding and decoding of BER-TLV as described in ISO 7816-4"
- `tlv_parser 0.10.0` - generic BER-TLV parse/emit

General BER options if needed: `bsn1 3.0.0`, `der-parser 10.0.0`, `tc_asn1 0.1.1`.
**Use `iso7816-tlv` or `flexiber`; keep `der` for actual DER (certificates).**

### RESOLVED: GlobalPlatform C library API surface (was gap #7)

[V] `kaoh/globalplatform` @ `877bbe1`. **The prefix is `OPGP_`, not `GP_`** - a naive grep
for `GP_*` returns only export/visibility macros, which is a trap.

43 public `OPGP_*` functions. Header layout under `globalplatform/src/globalplatform/`:
`globalplatform.h`, `security.h`, `connection.h`, `library.h`, `types.h`, `unicode.h`, `error.h`.

Main API (`globalplatform.h`) [V]:
`OPGP_establish_context`, `OPGP_card_connect`, `OPGP_release_context`,
`OPGP_select_application`, `OPGP_select_channel`, `OPGP_manage_channel`,
`OPGP_read_executable_load_file_parameters`, `OPGP_read_executable_load_file_parameters_from_buffer`,
`OPGP_extract_cap_file`, `OPGP_cap_to_ijc`, `OPGP_calculate_key_check_value`,
`OPGP_encrypt_sensitive_data`, `OPGP_get_cplc`, `OPGP_parse_cplc`,
`OPGP_get_extended_card_resources_information`, `OPGP_parse_extended_card_resources_information`,
`OPGP_build_bcd_encoding`

Connection layer (`connection.h`) [V]:
`OPGP_list_readers`, `OPGP_card_connect`, `OPGP_card_disconnect`,
`OPGP_send_APDU`, `OPGP_send_chained_APDU`, `OPGP_send_chained_APDU_extended`,
`OPGP_enable_trace_mode`

Error taxonomy (`error.h`) [V] includes `GP_ERROR_NO_SUPPORTED_SCP_FOUND`,
`GP_ERROR_CARD_CRYPTOGRAM_VERIFICATION`, `GP_ERROR_KEY_CHECK_VALUE`,
`GP_ERROR_WRONG_KEY_VERSION`, `GP_ERROR_WRONG_KEY_INDEX`, `GP_ERROR_INVALID_PASSWORD`,
`GP_ERROR_WRONG_PIN_LENGTH`, `GP_ERROR_WRONG_TRY_LIMIT`, `GP_ERROR_CAP_UNZIP`,
`GP_ERROR_INVALID_LOAD_FILE`, `GP_ERROR_COMMAND_SECURE_MESSAGING_TOO_LARGE`,
`GP_ERROR_COMMAND_TOO_LARGE`, `GP_ERROR_INSUFFICIENT_BUFFER`, `GP_ERROR_INVALID_RESPONSE_DATA`,
`GP_ERROR_UNRECOGNIZED_APDU_COMMAND`, `GP_ERROR_VALIDATION_FAILED`, `GP_ERROR_WRONG_EXPONENT`,
`GP_ERROR_WRONG_HASH_SIZE`

**GPShell3 full command list is far richer than first reported** [V] - this is the real surface
and should drive our GlobalPlatform command design:
`apdu`, `card-cap`, `card-data`, `card-info`, `card-resources`, `cin`, `confirm-counter`,
`cplc`, `del-key`, `delete`, `div-data`, `hash`, `iin`, `install`, `install-sd`, `is`,
`list-apps`, `list-keys`, `man`, `move`, `put-auth`, `put-dap-key`, `put-dm-receipt`,
`put-dm-token`, `put-key`, `scp`, `seq-counter`, `sign-dap`, `sign-delete-token`,
`sign-extradition-token`, `sign-install-token`, `sign-load-token`,
`sign-update-registry-token`, `status`, `store`, `store-cin`, `store-iin`,
`update-registry`, `verify-delete-receipt`

Note the **DAP token family** (`sign-load-token`, `sign-install-token`, `sign-delete-token`,
`sign-extradition-token`, `sign-update-registry-token`) and **key derivation methods**
`GP_DERIVATION_METHOD_EMV_CPS` / `GP_DERIVATION_METHOD_VISA` - these are new, not in the
earlier summary.

### Nuance on virtual-rsp BPP claim

[V] V2 said grep for `BoundProfile` returns "zero hits". Locally there are **2 string references**,
both being HTTP endpoint URLs in Python demo clients (`comprehensive_sgp22_demo.py:695`), not
implementations. No BPP builder exists (the sole `0x86` hit is an unrelated status-word byte).
**V2's substance holds** - virtual-rsp builds no BPP and has no SCP03t. Also reconfirmed directly:
no `CMAC` symbol anywhere in the repo, and `v_euicc_core.c:541` still carries the
`// Stub implementations for ES10a operations` comment at exactly the cited line.

### GSMA SGP.22 spec - confirmed genuinely unavailable

[V] **Not a rate limit.** Both plausible `gsma.com/wp-content/uploads` PDF paths return HTTP 404
under a browser UA. Requires GSMA member credentials. Every section cite in this report therefore
remains source-comment provenance, not primary spec.

### TS.48 - still uncovered

[V] No TS.48 reference found in any of the cloned repos. Uninvestigated, as flagged.

---

## 6. Open gaps - do NOT treat these as settled

1. **[U] rand 0.10.3 vs p256 0.14 / ecdsa 0.17** - `rand_core` trait alignment unconfirmed.
   Build-time only: `cargo add` + `cargo tree -d`.
2. ~~BER-TLV for BPP~~ - **RESOLVED**: use `iso7816-tlv 0.4.4` or `flexiber 0.2.0`, not `der`.
3. **[U] HandleNotification / CancelSession section numbers** in SGP.22.
4. **[U] ES10a's actual responsibility** - primary spec unavailable (GSMA 404s, needs member login).
5. ~~euicc-lsp files 404~~ - **RESOLVED**: clone via git, not raw URLs. `waigel/euicc-rsp`
   @ `df87411` has full source; ES10 cites live in `waigel/euicc-lpa`.
6. **[U] GSMA SGP.22 spec text** - confirmed unavailable, NOT a rate limit. All section cites are
   source-comment provenance from euicc-rsp.
7. ~~GlobalPlatform C API~~ - **RESOLVED**: `kaoh/globalplatform` @ `877bbe1`, 43 `OPGP_*` functions.
8. **[U] GSMA TS.48 test profiles** - still uncovered, no coverage anywhere.
9. **[U] `der` / `oid` pairing with p256 / ecdsa DER versions** - unconfirmed (same cause as #1).

---

## 7. Recommended next step

The GSMA spec remains the biggest unblock - gaps 3, 4 and 6 all trace to it, and it is confirmed
that this is an access problem, not a tooling problem. Options: obtain SGP.22 v2.6 through a GSMA
member login, or build against the euicc-rsp source comments with `[V]` confidence only where a
section number is explicitly cited.

The immediate blocker is gone. BER-TLV has a purpose-built crate (`iso7816-tlv`), so SGP.22 work
can start immediately. Before writing any ECC code, run `cargo add` + `cargo tree -d` to settle
the `rand_core` alignment question empirically - it is the one thing in the dependency stack that
no amount of reading will answer.

Remaining to commission: TS.48 test profiles (gap 8).
