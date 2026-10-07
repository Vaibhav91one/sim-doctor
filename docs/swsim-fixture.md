# The swSIM software-card fixture

Issue #4. This document is the local reproduction of what CI does, so a
developer without CI can get the same thing running and can debug a red
fixture run without waiting for a push.

## What this is

Three pieces, all running at once:

| Piece | What it is | Where it comes from |
|---|---|---|
| **swSIM** | An all-software SIM card. Speaks ISO 7816-4 over TCP. | [tomasz-lisowski/swsim](https://github.com/tomasz-lisowski/swsim) |
| **swicc-pcsc** | A pcsc-lite IFD handler. It **listens** on 127.0.0.1:37324 and presents each connecting card as a PC/SC reader. | [tomasz-lisowski/swicc-pcsc](https://github.com/tomasz-lisowski/swicc-pcsc) |
| **pcscd** | The PC/SC daemon. Loads the swicc-pcsc driver module. | distro package |

This crate then talks to all three through [src/transport/pcsc.rs](../src/transport/pcsc.rs),
which is the real **pcsc**-backed implementation of
[ReaderProvider](../src/transport.rs) and [CardSession](../src/transport.rs).

### Pinned commits

Both are fetched by full SHA in
[.github/workflows/card-fixture.yml](../.github/workflows/card-fixture.yml) so a
moving upstream head cannot silently change the fixture:

| Project | Commit |
|---|---|
| swSIM | **281da8c63398ece9a5126cad969674f4f413ab63** |
| swicc-pcsc | **0496740fc96ffc777cbcf1dc758892e2ff487973** |

Submodules come from the gitlinks recorded inside those two commits, so they
are pinned too. **Do not** substitute branch names here.

## The opt-in gate

A plain **cargo test** never touches a reader, a daemon or a card. That is
the AGENTS.md section 2 requirement and it is enforced two ways:

1. The test lives behind the **card-fixture** cargo feature, which is off by
   default. With the feature off, [tests/card_fixture.rs](../tests/card_fixture.rs)
   compiles to nothing at all, so the file does not even appear in the test
   list.
2. The test is additionally marked **#[ignore]**, so even
   **cargo test --all-features** reports it as ignored instead of failing on a
   laptop with no reader.

Run it against a live card with:

~~~sh
cargo test --features card-fixture --test card_fixture -- \
  --ignored --exact drives_a_real_card_through_the_pcsc_transport --nocapture
~~~

There is deliberately **no** "skip if no reader" branch. A card-backed test
that quietly passes with no card is exactly the failure mode this fixture
exists to rule out, so a missing reader is a failure that prints the reader
list it did see.

## Linux: full local reproduction

Requires: gcc, make, cmake, pkg-config, libpcsclite-dev, pcscd, pcsc-tools,
and sudo. Tested on Debian/Ubuntu; the package names differ elsewhere.

### 1. Install the PC/SC stack

~~~sh
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  gcc make cmake pkg-config libpcsclite1 libpcsclite-dev pcscd pcsc-tools
~~~

libpcsclite-dev is not optional for building this crate: pcsc-sys runs
pkg-config in its build script and calls exit(1) when the library is missing.

### 2. Build swSIM

**--recurse-submodules is not optional.** swSIM has three submodules
(lib/make-pal, lib/swicc, lib/tau). After a plain clone every lib/ directory
is empty and make fails much later with a confusing missing-header error.

~~~sh
git clone --recurse-submodules https://github.com/tomasz-lisowski/swsim.git
cd swsim
git checkout --detach 281da8c63398ece9a5126cad969674f4f413ab63
git submodule update --init --recursive
make main-dbg -j"$(nproc)"

# The binary is build/swsim.elf. build/swsim is the OBJECT DIRECTORY, so
# "ls build/swsim" shows a directory and looks like a missing binary.
test -f build/swsim.elf
~~~

If you cloned without submodules, delete the directory and clone again.
Switching branches does not re-fetch an empty submodule tree reliably.

### 3. Build AND install the swicc-pcsc driver

**This project builds no executable.** It builds a pcscd driver module, and
installing it is a separate step from building it.

~~~sh
git clone --recurse-submodules https://github.com/tomasz-lisowski/swicc-pcsc.git
cd swicc-pcsc
git checkout --detach 0496740fc96ffc777cbcf1dc758892e2ff487973
git submodule update --init --recursive
make main-dbg -j"$(nproc)"

test -f build/libswicc-pcsc.so.1.2.0

sudo make install   # copies BOTH of these, and the daemon needs both:
                    #   build/reader.conf       -> /etc/reader.conf.d/libswicc-pcsc
                    #   build/libswicc-pcsc.so  -> /usr/lib/pcsc/drivers/serial/

test -f /etc/reader.conf.d/libswicc-pcsc
test -f /usr/lib/pcsc/drivers/serial/libswicc-pcsc.so.1.2.0
~~~

Skipping **sudo make install** is the most common way to lose an afternoon
here: the daemon starts cleanly, never loads the driver, and never registers a
reader. It does not look like a missing install.

### 4. Start pcscd first, then swSIM

**Order is fixed and backwards is silent.** The swicc-pcsc IFD handler is the
listener: its IFDHCreateChannel creates the server socket on port 37324. swSIM
is the client that connects to it. Start swSIM first and you get a card nobody
is listening for.

~~~sh
# Terminal 1 - the daemon, foreground with debug output.
sudo pcscd --foreground --debug

# Terminal 2 - the card. --fs-gen builds a fresh USIM filesystem from the
# checked-in JSON profile, which is where the card key material comes from.
# It is generated at run time; nothing about it is ever committed.
cd swsim
./build/swsim.elf \
  --ip 127.0.0.1 --port 37324 \
  --fs filesystem.swiccfs --fs-gen ./data/usim.json
~~~

### 5. Confirm the card is visible, independently of this crate

~~~sh
pcsc_scan
~~~

Expect a reader whose name contains **swICC**, with **Card present** and an
ATR. This step matters because it does not depend on this crate compiling:
if pcsc_scan sees a card and the Rust test does not, the fixture is fine and
the bug is ours.

### 6. Run the card-backed test

~~~sh
cd <this repo>
cargo test --features card-fixture --test card_fixture -- \
  --ignored --exact drives_a_real_card_through_the_pcsc_transport --nocapture
~~~

Every exchange is printed as **command bytes, then response bytes**, so a
failure shows what the card actually said rather than only what was expected.

## What the test asserts

Not "a reader was listed". In order:

1. A PC/SC context enumerates readers, and one of them is the swICC reader.
2. A session connects to it and returns a non-empty ATR.
3. **SELECT MF (3F00)**, sent as **00 A4 00 0C 02 3F 00**, returns a bare
   status word in the **normal processing class** (SW1 90..9F) with no
   response data. If the card has a proactive command pending it answers
   **91 <length>**, so the test fetches that command and repeats the SELECT
   until it gets a literal **90 00**, which it then asserts exactly.
4. **SELECT MF (3F00)** with FCP, sent as **00 A4 00 04 02 3F 00**, returns
   **61 xx**, and a **GET RESPONSE** (**A0 C0 00 00 xx**) then returns exactly
   the advertised number of bytes followed by a normal processing status word,
   with the MF file capabilities template in the body carrying the file ID
   3F00.
5. **SELECT DF GSM (7F20)** returns normal processing, so selection walks
   the file system rather than only answering the first command, then
   **SELECT MF** again because 2F00 and 2FE2 hang off the MF and not off
   DF GSM.
6. **SELECT EF.IMSI (2FE2)** with FCP returns **61 xx**; the **GET RESPONSE**
   body must carry the file identifier **2F E2** in tag **83**, proving which
   file was actually selected, and the file size in tag **80**, which is then
   used as the Le of the read rather than a guessed number. The test reads
   both through `fcp::TagSet::swicc()`, the swICC mapping, because that is what
   this card answers with. The earlier version of this test said "tag **83**
   file descriptor and tag **82** file size", which is the ISO table's reading
   of swICC's bytes; issue #11 made the mapping an explicit argument so the two
   cannot be confused again.
7. **READ BINARY** of exactly that many bytes returns exactly that many bytes
   of non-fill content followed by a normal processing status word.
8. **READ BINARY on EF.DIR (2F00)** must be **refused** with a 6X status.
   EF.DIR is linear-fixed, i.e. record-structured, and READ BINARY does not
   apply to it. Asserting that the card refuses is the point: a stub that
   answered everything would fail here.
9. Disconnect, then disconnect again, which the trait specifies as a no-op.

### Why the assertions say "normal processing class" and not "90 00"

This is the single most useful thing the fixture found, and it cost a CI run
to learn, so it is recorded rather than smoothed over.

swSIM's own success is **90 00**: lib/swicc/include/swicc/apdu.h:43 defines
`SWICC_APDU_SW1_NORM_NONE = 0x90` with the comment "Success, 9000". A
SELECT MF does return it.

What swSIM then does, at the end of **every** command in
**src/apduh.c:sim_apduh_demux**, is:

~~~c
proactive_step(&sim_state->proactive);
if (ret == SWICC_RET_SUCCESS)
{
    if (res->sw1 == SWICC_APDU_SW1_NORM_NONE && res->sw2 == 0)
    {
        if (sim_state->proactive.command_length > 0)
        {
            res->sw1 = 0x91;
            res->sw2 = (uint8_t)sim_state->proactive.command_length;
        }
    }
}
~~~

So **a successful command's 90 00 is rewritten to 91 <length>** whenever a
proactive command is waiting. On the USIM profile in data/usim.json the first
SELECT MF therefore comes back **91 80**: the select worked, and there is a
128-byte proactive SIM command for the terminal to fetch. [V], read in swSIM
source at the pinned commit.

Three consequences worth keeping:

- **SW1 0x91 is not failure.** ISO/IEC 7816-4 defines 0x9F as "normal
  processing, proactive command available"; 0x91, 0x92 and 0x93 are the 3GPP
  variants, which put the pending command's length in SW2. A scanner that
  treats 91 xx as an error would report every healthy card as broken.
- **A 9x SW2 is not always a length.** 61 xx is a response length, 9x may be a
  proactive command length, and 6C xx is a corrected length. They are three
  different numbers that happen to share a byte.
- **Chasing a 90 00 needs a FETCH first.** FETCH is **80 12 00 00 <length>**;
  src/apduh.c:apduh_etsi_cat_fetch requires Le to equal the pending length
  exactly and clears it. Only once nothing is pending does a command answer a
  plain 90 00.

This is why the test asserts the class, and separately asserts that the
response carries no trailing data, which is the property P2 = 0x0C actually
promises. Hard-coding "90 00" everywhere would make it a test of the
simulator's mood.

### The FCP tag numbering swICC uses is NOT the ISO/IEC 7816-4 table

This one cost a CI run too, and every later issue that reads a file
capabilities template will meet it.

The first version of this crate assumed a table with **0x82 = file size** and
**0x83 = file descriptor** (mislabelled "ISO/IEC 7816-4 table 42"). That table
is wrong, for swSIM and for real cards alike. swICC's own FCP builder, in
**src/3gpp.c**, uses the ETSI TS 102 221 clause 11.1.1.3 numbering:

~~~c
0x80, /* '62': File size,        'A5': UICC characteristics. */
0x81, /* '62': Total file size,  'A5': App power consumption. */
0x82, /* '62': File descriptor,  'A5': Min app clock frequency. */
0x83, /* '62': File ID,          'A5': Available memory. */
~~~

So inside an FCP template swSIM puts the **file size in 0x80**, the file
descriptor in **0x82**, and the **file ID in 0x83**. [V], read in swSIM source
at the pinned commit.

**Where the file actually is.** `src/3gpp.c` is in **swSIM**
(`tomasz-lisowski/swsim`), not in swICC, at commit
`281da8c63398ece9a5126cad969674f4f413ab63`; swICC is the library swSIM links
against, pinned as submodule `421c8cdd544d1fab508351d8cd81c5f61aae6363`. The
file-descriptor byte layout this crate reads comes from that swICC commit's
`src/fs.c` (`swicc_fs_file_descr_byte`), whose own comment cites
ISO/IEC 7816-4:2020 clause 7.4.5 table 12. swSIM's own comments attribute the
FCP tag table to ETSI TS 102 221 V16.4.0 clause 11.1.1.3, and a live operator
USIM's MF FCP uses the same tags (issue #69), so `TagSet::ts_102_221()` is the
default and `TagSet::swicc()` carries identical tags under the swSIM name.

**How the crate handles it.** `fcp::TagSet` is the mapping, supplied by the
caller. It has no `Default` and no constructor that invents tags, so
`fcp::Template::parse` cannot be reached until somebody has said which table
is being read; `TagSet::ts_102_221()` and `TagSet::swicc()` are the two
known ones, and `TagSet::named(..)` plus the `with_*` builders are there for a
card nobody has characterised. Every `TagSet` carries the name it was given, so
a scan can report the assumption it ran under instead of burying it.

Two FCPs as the card actually sent them:

~~~
SELECT MF     -> 62 31 82 02 38 21 83 02 3F 00 A5 09 80 01 70 83 04 FF FF FE 31 ...
SELECT EF.IMSI -> 62 1B 82 02 09 21 83 02 2F E2 A5 00 8A 01 05 8C 08 7F 00 00 00 00 00 00 00 80 02 00 0A 90 00
~~~

Reading the EF.IMSI one against the ISO table gives a "file size" of
`0x0921` = 2337, which is nonsense and was the first failure of the
last leg. Reading it as swICC says gives **0x80 = 0x000A = 10**, and 10 is
precisely the length of the EF.IMSI contents in data/usim.json
(`98 88 12 01 00 00 50 01 80 F4`). The MF's FCP carries no 0x80 at
all, which also fits: a master file has no size.

**A real card may follow the ISO table instead.** This mapping is the
simulator's, recorded here so nobody re-derives it, not a claim about cards.

### Why P2 = 0x0C on the SELECT

ISO/IEC 7816-4 clause 7.5.1 sets bit b4 of P2 to mean "return no response
data". swSIM implements both forms: P2 = 0x00 leaves the FCP in the GET
RESPONSE queue and answers 61 xx, while P2 = 0x0C answers immediately with no
body. Both are conformant. The "no data" form is what lets the test assert
that nothing came back at all, which is why step 3 uses it and step 4 uses the
other form deliberately, to prove a real body comes back.

### Why READ BINARY is asserted to FAIL on EF.DIR

An early version of the test read EF.DIR (2F00) and the card answered **69 81**.
That was the test's bug, not the card's, and the reason is worth recording
because it is the kind of thing a scanner will hit on a real card too.

In data/usim.json, EF.DIR is a **`file_ef_linear-fixed`**: record-structured,
with `rcrd_size` 43. ISO/IEC 7816-4 clause 11.3.2 defines READ BINARY for
transparent (binary) EFs only; a record-structured EF is read with READ RECORD.
swICC says so plainly, at **lib/swicc/src/apduh.c:740**:

~~~c
res->sw1 = SWICC_APDU_SW1_CHER_CMD;
res->sw2 = 0x81; /* "Command incompatible with file structure" */
~~~

So **69 81** is the right answer and ISO/IEC 7816-4 clause 9.1.2 gives its
meaning. The test now asserts the 6X class rather than the literal, so
it states the rule and not one simulator's choice of code, and it reads its
content from EF.IMSI (2FE2), which is transparent in the same profile.

Two habits this changed in the test, both worth keeping:

- **Prove which file was selected before reading it.** The FCP's tag **83**
  carries the file identifier, so the test asserts it equals **2F E2** before
  issuing the read. A SELECT that answers 9000 has told you it resolved
  something, not which.
- **Take the length from the FCP, not from a guess.** On this card the file
  size is tag **80**; asking for a hardcoded 15 because EF.DIR looked about
  that long is exactly the kind of assertion that rots silently.
- **Say which tag table you are reading.** The test passes
  `fcp::TagSet::swicc()` explicitly rather than relying on a default, because
  there is no default and there cannot be one. Before issue #11 the test
  scanned the FCP with a four-octet window and hard-coded `0x80` and `0x83`;
  that window would have matched a three-octet file identifier and passed on a
  template it should have rejected. It now walks the template with
  `tlv::Stream` and reads it through the mapping, which is what makes step 6's
  assertion a real check.

### Why GET RESPONSE uses CLA 0xA0

swSIM routes INS 0xC0 to a handler only in the proprietary GSM class:
src/apduh.c dispatches CLA 0xA0 INS 0xC0 to the same response queue the 3GPP
SELECT filled. CLA 0x00 INS 0xC0 is not dispatched at all. [V], read in
swSIM source at the pinned commit.

## What issue #7's walk added, and what it cost a CI run to learn

The walker lives in [../src/walk.rs](../src/walk.rs) and is verified on this
fixture by `walks_the_file_system_of_a_real_card` in
[../tests/card_fixture.rs](../tests/card_fixture.rs). Four facts came out of
reading swSIM and swICC at the pinned commits, and a later issue that walks a
card will meet all four.

### SELECT must ask for the capabilities template, or it gets 6A 86

`src/apduh.c:apduh_3gpp_select` decodes P2 into a data-request field and
rejects anything that is neither `04` (FCP) nor `0C` (no response data):

~~~c
switch (cmd->hdr->p2 & 0b10011100)
{
case 0b00000100: data_req = DATA_REQ_FCP;     break;
case 0b00001100: data_req = DATA_REQ_ABSENT; break;
default:        data_req = DATA_REQ_RFU;     break;
}
...
if (meth == METH_RFU || data_req == DATA_REQ_RFU ...)
{
    res->sw1 = SWICC_APDU_SW1_CHER_P1P2;  /* 6A */
    res->sw2 = 0;
}
~~~

So the GSM 11.11 spelling `00 A4 00 00 02 3F 00`, which asks for a file
control information template, is **refused**. A walk that wants a file's own
capabilities has to send P2 = `04`, which is why
`fs::select_capabilities_header()` now sits beside `fs::select_header()`. \\[V],
swSIM `281da8c6`.

### P1 = 08 is "select by path from the MF", and it works

`apduh_3gpp_select` maps P1 `08` to `METH_PATH_MF` and hands the data field
to `swicc_va_select_file_path`, which walks it one segment at a time from
`3F00` with `swicc_disk_file_foreach(..., recurse = false)`. A path the card
does not hold comes back `6A 82`. \\[V], swSIM `src/apduh.c` and swicc
`src/fs/va.c` at `421c8cdd`.

**The two-octet form does not do this.** `METH_FID` calls
`swicc_va_select_file_id`, which calls `swicc_disk_lutid_lookup` over *every*
tree in the disk. So on swSIM a SELECT by file identifier is a **global**
lookup: `00 A4 00 04 02 FF01` reaches ADF.USIM from anywhere, and a walk that
used it would produce a tree that is not the card's directory structure. That
is why `walk::Addressing::PathFromMasterFile` is the default and why
`Addressing::Identifier` carries a warning saying exactly this. \\[V].

### GET RESPONSE cannot read EF.DIR

`apduh_res_get` in swicc rejects any P1 or P2 other than `00`:

~~~c
if (cmd->hdr->p1 != 0U || cmd->hdr->p2 != 0U)
{
    res->sw1 = SWICC_APDU_SW1_CHER_P1P2_INFO;
    res->sw2 = 0x86;
}
~~~

The 3GPP way to read a directory's listing is GET RESPONSE with **P1 = `81`**.
So the efficient enumeration is unavailable on this fixture and the walk
enumerates by probing identifiers instead. \\[V], swicc `421c8cdd`.

### This card cannot say "forbidden"

`va_select_file` evaluates no access condition and returns only success or
not-found, and the status table in swicc `include/swicc/apdu.h` has no code for
"access denied". So the absent/forbidden distinction is proved by the unit tests
and **cannot** be proved on this card. The card test asserts the opposite
direction instead: `report.forbidden == 0`, because a non-zero count would mean
the walk invented a finding. \\[V], swicc `src/fs/va.c` and
`include/swicc/apdu.h` at `421c8cdd`.

### What the walk found when it ran

The USIM profile in `data/usim.json` holds exactly four files under `3F00`:
`2F00` (EF.DIR), `2F05` (EF.PL), `2FE2` (EF.ICCID) and `7F20` (DF.GSM), and
DF.GSM is **empty** in that profile. ADF.USIM (`FF01`) is a separate disk tree,
reachable only by AID or by the reserved FID `7FFF`, so a path-based walk
correctly reports it absent under `3F00` where an identifier-based walk would
report it present. That single difference is the clearest demonstration of why
the addressing form is a parameter and not a constant.

The MF's FCP carries **no file size** (it is not an elementary file) and every
folder's carries a `C6` PIN status template, which `TagSet::swicc()` has no tag
for. Both are things the walk reports rather than guesses at: the size as
`Reported::NotReported`, and the tag in `Capabilities::unknown_tags`.

### This card describes an infinite tree, and that cost issue #7 a CI run

`swicc_disk_file_foreach` runs its callback on the starting file **itself**
before its children; the function's own comment says "including the file
itself" \\[V], swicc `src/fs/disk.c` at `421c8cdd`. `va_select_file_path` uses
it to walk a SELECT-by-path one segment at a time. So asking for
`3F00/7F20/7F20` searches the children of `7F20` for `7F20`, matches `7F20`
itself on the very first callback, and **succeeds**. Every further identical
segment does the same, so the card will select `3F00/7F20/7F20/7F20/...` forever.

This is not a bug the walker can detect by looking at identifiers, because it
is not a bug in the card's *file system* - it is a bug in the card's *path
resolver*. A real SIM file identifier repeats legally across directories, so a
walker that refused to descend on a repeat would hide files. What stops this
card is a bound: `walk` hit `Limits::max_depth` at sixteen levels and reported
`Note::Limit { limit: Depth }` on the node it did not descend.

**The first run of `walks_the_file_system_of_a_real_card` failed on exactly
this**, and the assertion it failed was "the whole card should fit inside the
default bounds". That assertion was wrong: the card does not fit, and saying
so is the correct behaviour. It is replaced by assertions that the truncation is
**reported on a node** rather than silently applied, and that the repeated
identifiers are recorded as `Note::RepeatedAncestor`.

## Both card-backed tests must run serially

A card has one current directory and one response queue. swSIM clears the
queue on **every** command that is not GET RESPONSE \\[V], swicc
\`src/apduh.c:swicc_apdu_rc_reset\` at \`421c8cdd\`:

~~~c
case SWICC_APDU_CLA_TYPE_INTERINDUSTRY:
    if (cmd->hdr->ins != 0xC0) /* GET RESPONSE instruction */
    {
        /* Make GET RESPONSE deterministically not work if resumed. */
        swicc_apdu_rc_reset(&swicc_state->apdu_rc);
    }
~~~

So a GET RESPONSE only returns the template the **most recent** SELECT queued.
Run two card-backed tests in parallel and one of them sends
\`A0 C0 00 00 33\` after the other has already reset the queue,
and the card answers \`6F 00\`. That is exactly what happened the
first time issue #7's walk and issue #4's transport test ran together, and the
card-fixture workflow now passes \`--test-threads=1\`. **One card,
one test at a time.**

## macOS: this does not work, and here is why

**Plainly: the swSIM fixture cannot be run on macOS with this project's setup.**

- macOS ships the **PCSC framework** for client apps, so the **pcsc** crate
  compiles and the normal **cargo test** suite runs fine on a Mac. That is not
  in question.
- What it does not ship is **pcscd**, the daemon. That is a pcsc-lite thing,
  and the software card is only reachable through a pcsc-lite **IFD handler**.
- swicc-pcsc is a pcsc-lite IFD handler. Its install target writes
  **/etc/reader.conf.d/** and **/usr/lib/pcsc/drivers/serial/**, it implements
  the pcsc-lite IFD ABI, and it is not built or supported for macOS. There is
  no upstream macOS port of it.

So on a Mac, the card-backed test cannot be made to pass locally. That is why
CI is the place this runs. What a Mac developer can do:

- run **cargo fmt**, **cargo clippy** and **cargo test** normally, which are
  hardware-free by design;
- drive the fixture through the Linux path above in a VM, a container or a
  remote shell;
- if a real reader is plugged into the Mac, **tests/card_fixture.rs** will use
  it, because the Rust side talks to PC/SC and does not know or care that the
  reader behind it is software. The reader-name assertion looks for **swicc**,
  so on a Mac with physical hardware expect that one assertion to be what
  fails. Treat it as a sign the test needs a software-reader guard, not as a
  transport bug.

## Licence notice

This repository does not vendor swSIM or swicc-pcsc source. It fetches both at
the pinned commits above and builds them in CI, so the notice is recorded here
rather than in a vendored tree.

Both projects are **BSD 3-Clause licensed**, Copyright (c) their respective
authors. The full licence text ships with each project, at these pinned URLs:

- swSIM: https://github.com/tomasz-lisowski/swsim/blob/281da8c63398ece9a5126cad969674f4f413ab63/LICENSE
- swicc-pcsc: https://github.com/tomasz-lisowski/swicc-pcsc/blob/0496740fc96ffc777cbcf1dc758892e2ff487973/LICENSE

This project's own licence is MIT, see [LICENSE](../LICENSE). The two are
compatible: BSD-3 is permissive, and the fixture artifacts are built and
thrown away inside CI, never redistributed from this repository.

### Card secrets

The swSIM USIM profile carries key material and is **generated at run time**
into the runner or developer temp directory. No card key, PKI file or profile
is ever committed; .gitignore blocks the usual extensions as a second line of
defence. See AGENTS.md, "Never commit card secrets".

## Troubleshooting

| Symptom | Cause |
|---|---|
| make fails on a missing header under lib/ | Cloned without submodules. Delete and re-clone with --recurse-submodules. |
| "build/swsim" exists but is a directory | It is the object directory. The binary is build/swsim.elf. |
| pcscd runs, pcsc_scan shows no reader | swicc-pcsc was built but not installed. Run sudo make install. |
| pcsc_scan shows the reader, but "Card state: Card removed" | swSIM is not running, or was started before pcscd. Reverse them. |
| pcsc_scan shows the reader and a card, the Rust test still fails | The fixture is fine and the bug is in this crate. |
| The Rust test fails with "no matching PC/SC reader" | pcscd is not running, or is running without the driver module. |
| The Rust test fails listing a reader with no swICC in its name | A real reader is attached. Only one card is supported at a time. |
