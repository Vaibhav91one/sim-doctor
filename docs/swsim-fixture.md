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
3. **SELECT MF (3F00)**, sent as **00 A4 00 0C 02 3F 00**, returns exactly
   **90 00** with no response data.
4. **SELECT MF (3F00)** with FCP, sent as **00 A4 00 04 02 3F 00**, returns
   **61 xx**, and a **GET RESPONSE** (**A0 C0 00 00 xx**) then returns exactly
   the advertised number of bytes, ending 90 00, with the MF file capabilities
   template in the body carrying the file ID 3F00.
5. **SELECT DF GSM (7F20)** returns 90 00, so selection walks the file system
   rather than only answering the first command.
6. **SELECT EF.DIR (2F00)** then **READ BINARY** of 15 bytes returns the
   profile's real application template, tag **61**, ending 90 00.
7. Disconnect, then disconnect again, which the trait specifies as a no-op.

### Why P2 = 0x0C on the SELECT

ISO/IEC 7816-4 clause 7.5.1 sets bit b4 of P2 to mean "return no response
data". swSIM implements both forms: P2 = 0x00 leaves the FCP in the GET
RESPONSE queue and answers 61 xx, while P2 = 0x0C answers 90 00 directly.
Both are conformant. The "no data" form is what gives a clean 90 00 to assert,
which is why step 3 uses it and step 4 uses the other form deliberately, to
prove a real body comes back.

### Why GET RESPONSE uses CLA 0xA0

swSIM routes INS 0xC0 to a handler only in the proprietary GSM class:
src/apduh.c dispatches CLA 0xA0 INS 0xC0 to the same response queue the 3GPP
SELECT filled. CLA 0x00 INS 0xC0 is not dispatched at all. [V], read in
swSIM source at the pinned commit.

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
