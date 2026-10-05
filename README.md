# sim-doctor

[![CI](https://github.com/Vaibhav91one/sim-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/Vaibhav91one/sim-doctor/actions/workflows/ci.yml)

CLI-first SIM security testing tool in Rust.

Examines SIM/UICC/eUICC cards over PC/SC and reports findings through both a human
terminal UI and a stable machine-readable contract, so the same binary serves both an
interactive operator and an automated agent.

## Status

**M1, end to end.** The M1 path works: `sim-doctor scan` opens a real PC/SC
session, selects the card's master file, walks the file system, and reports what
it found as a table or, under `--json`, as one envelope on stdout with a
meaningful exit code. It is card-verified against the swSIM fixture in CI.

```
sim-doctor scan --json            # one JSON envelope on stdout, exit 0 / 1
sim-doctor scan --help            # what every flag does, and what it cannot do yet
sim-doctor completions zsh        # shell completions for the whole flag surface
```

What it is **not** yet: the rule model exists (#13 - findings, locations,
bounded evidence, and a registry that refuses a duplicate rule ID) but **no rule
runs yet**, so `scan` still exits 0 whatever it saw, `--score` and `--severity`
refuse honestly rather than guessing, and `--baseline` / `--diff` are
placeholders (#9). A truncated walk is always labelled as one, in both output
modes. See [CONTEXT.md](CONTEXT.md) for the plan.

## Documentation

| File | Purpose |
|---|---|
| [AGENTS.md](AGENTS.md) | Canonical agent instructions: architecture, contracts, domain facts, gotchas |
| [CLAUDE.md](CLAUDE.md) | Pointer to AGENTS.md |
| [CONTEXT.md](CONTEXT.md) | Project decisions, open questions, milestone plan |
| [docs/research-report.md](docs/research-report.md) | Full source-verified research findings |
| [docs/swsim-fixture.md](docs/swsim-fixture.md) | Software-card fixture: how to run swSIM behind pcscd locally |
| [Cargo.toml](Cargo.toml) | Dependency manifest, versions verified against crates.io |

## License

[MIT](LICENSE) - chosen by the project owner.

## Design principles

1. **Agent-first, not agent-optional.** Every command has a headless mode with a stable
   JSON contract and a meaningful exit code. The TUI is a view, not the product.
2. **Verified facts only.** Claims carry a [V] verified or [U] unverified tag so nobody
   builds on a guess. See AGENTS.md.
3. **Testable without hardware.** The primary dev loop runs against a software SIM behind
   a software PC/SC reader. `cargo test` needs no reader at all; the three
   card-backed tests are behind the `card-fixture` feature and run in a separate
   CI job that builds swSIM and swicc-pcsc at pinned commits. See
   [docs/swsim-fixture.md](docs/swsim-fixture.md).