# sim-doctor

CLI-first SIM security testing tool in Rust.

Examines SIM/UICC/eUICC cards over PC/SC and reports findings through both a human
terminal UI and a stable machine-readable contract, so the same binary serves both an
interactive operator and an automated agent.

## Status

**Pre-implementation.** This repo currently holds research, architecture, and the
dependency manifest. No working binary yet. See [CONTEXT.md](CONTEXT.md) for the plan.

## Documentation

| File | Purpose |
|---|---|
| [AGENTS.md](AGENTS.md) | Canonical agent instructions: architecture, contracts, domain facts, gotchas |
| [CLAUDE.md](CLAUDE.md) | Pointer to AGENTS.md |
| [CONTEXT.md](CONTEXT.md) | Project decisions, open questions, milestone plan |
| [docs/research-report.md](docs/research-report.md) | Full source-verified research findings |
| [Cargo.toml](Cargo.toml) | Dependency manifest, versions verified against crates.io |

## License

[MIT](LICENSE) - chosen by the project owner.

## Design principles

1. **Agent-first, not agent-optional.** Every command has a headless mode with a stable
   JSON contract and a meaningful exit code. The TUI is a view, not the product.
2. **Verified facts only.** Claims carry a [V] verified or [U] unverified tag so nobody
   builds on a guess. See AGENTS.md.
3. **Testable without hardware.** The primary dev loop runs against a software SIM behind
   a software PC/SC reader.