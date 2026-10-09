# Corpus gate

`tests/corpus.rs` builds cards in code (never real dumps), runs each through the scan
pipeline over an in-process `CardSession`, and compares the findings to the case's expected
list. Per rule it computes TP/FP/FN and fails `cargo test` if precision or recall drops below
`THRESHOLDS` (default 1.0). It needs no reader and no swSIM, so it runs in the normal CI job.

A rule is gated once at least one case expects it. A registered rule with no case is a
warning on stderr, not a failure.

## Adding a rule's cases

1. In `corpus()`, add a `Case` where the rule must fire: list `(rule id, Location display)`
   in `expected`. Add one where it must stay silent (an existing clean case may be enough).
2. If the card needs a behaviour `Card` cannot express, extend `Card::transmit`; only reach
   for a swSIM image (card-fixture workflow) if it truly cannot be scripted.
3. Run `cargo test --test corpus -- --nocapture` to see the table.
4. `docs/rule_docs/` is generated from the rule declarations; a new rule needs
   `UPDATE_RULE_DOCS=1 cargo test --test rule_docs`.
5. Lowering a threshold: add the rule to `THRESHOLDS` with a reason in the PR. Do not lower
   it to make a regression pass.
