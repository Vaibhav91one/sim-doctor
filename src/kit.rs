//! sim-doctor on doctor-kit: the CLI skeleton comes from `doctor_kit::run_with`, the commands are ours.
//!
//! Every top-level command of the derive-built [`Cli`] is mounted as an `ExtCommand` of its own
//! name, so its flags, its `--help` text and its handler are exactly what they were; a command
//! named like one of the kit's (`scan`, `fix`, `install`, `ci`, `mcp`) replaces the kit's.
//! The doctor itself is a card, not a directory (`TargetKind::Detached`).
//!
//! `scan` runs through the kit's report pipeline ([`doctor_kit::preflight`] / [`doctor_kit::finish`]:
//! the baseline gate, the exit code, the one write of the report) with the card read in
//! [`SimDoctor::try_scan`]. Everything the kit would do differently from sim-doctor's contract is
//! kept as it was through the `Doctor` hooks (`load_baseline`, `baseline_hook`, `render_json`,
//! `render_human`, `preflight_error`) and is pinned by `tests/golden_scan.rs`.

use std::collections::HashSet;
use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};

use clap::{ArgMatches, CommandFactory, FromArgMatches};
use doctor_kit::baseline::Saved;
use doctor_kit::doctor_core::{BaselineCounts, BaselineState, Envelope, Score, Severity};
use doctor_kit::face::{Note, NoteLevel};
use doctor_kit::install::{plan, rendered, write, Agent, AgentFile, FileMode, Overwrite};
use doctor_kit::output::Color;
use doctor_kit::{
    failure_envelope, finish, preflight, Check, Config, Ctx, Doctor, ExtCommand, Extensions, Face,
    McpTexts, McpTool, Meta, Node, OutputArgs, PreflightKind, ScanFailure, TargetKind,
};
use serde_json::{json, Value};
use sim_doctor::baseline::{Baseline, Diff};
use sim_doctor::transport::CardSession;
use sim_doctor::walk::{Candidates, Limits, Tree};
use sim_doctor::{access, ef, rules, sarif, scan, session, tar, walk};

use super::{
    checkpoint, contract, dispatch, emit_stdout, limits_from, open_scan_session, Cli, InstallArgs,
    ScanArgs, INTERRUPT_REPORTED,
};
#[cfg(feature = "shell")]
use super::{CardArgs, ExploreArgs, ShellArgs};

/// The skill body shared by every agent file.
const SKILL_BODY: &str = include_str!("skill_body.md");

/// The card scan a `scan` command left behind, for the hooks that run after it.
struct Outcome {
    tree: Tree,
    verdict: scan::Verdict,
    reader: String,
    atr: Option<Vec<u8>>,
    dialect: scan::Dialect,
    candidates: Candidates,
    limits: Limits,
    /// `baseline_state` of each finding of the envelope, in order, as sim-doctor's own comparison
    /// set them (a multiset match; the kit's is a set match) and the `baseline` counts.
    states: Vec<Option<BaselineState>>,
    counts: Option<BaselineCounts>,
}

impl Outcome {
    fn context(&self) -> scan::Context<'_> {
        scan::Context::new(
            &self.reader,
            self.atr.as_deref(),
            self.dialect,
            self.candidates.clone(),
            self.limits,
        )
    }
}

/// What one card read is told: the `scan` flags, or the card part of `shell` and `explore`.
struct Run {
    reader: Option<String>,
    dialect: scan::Dialect,
    limits: Limits,
    tar: tar::Selection,
    terminal_profile: bool,
    severity: Option<rules::Severity>,
    score: bool,
    fail_on: rules::Severity,
    json: bool,
    tui: bool,
    baseline: Option<std::path::PathBuf>,
    sarif: Option<std::path::PathBuf>,
    /// `--face legacy`: the full report instead of the kit's face.
    legacy: bool,
}

impl Run {
    /// The card part of `shell` / `explore`: no TAR audit unless asked, nothing is compared or
    /// written.
    #[cfg(feature = "shell")]
    fn session(card: &CardArgs) -> Run {
        Run {
            reader: card.reader.clone(),
            dialect: card.dialect,
            limits: limits_from(&card.walk_limits),
            tar: card.tar.clone(),
            terminal_profile: false,
            severity: None,
            score: false,
            fail_on: rules::Severity::Critical,
            json: false,
            tui: false,
            baseline: None,
            sarif: None,
            legacy: false,
        }
    }

    fn scan(args: &ScanArgs) -> Run {
        Run {
            reader: args.reader.clone(),
            dialect: args.dialect,
            limits: limits_from(&args.walk_limits),
            tar: args.tar.clone(),
            terminal_profile: args.terminal_profile,
            severity: args.severity,
            score: args.score,
            fail_on: args.fail_on,
            json: args.json,
            tui: args.tui,
            baseline: args.baseline.clone(),
            sarif: args.sarif.clone(),
            legacy: args.face.as_deref() == Some("legacy"),
        }
    }
}

/// The doctor the kit's pipeline runs. It holds the parsed command line (the kit hands each
/// mounted command only its own matches, and the handlers want the whole `Cli`) and what the
/// `scan` command passes between the kit's hooks.
pub struct SimDoctor {
    root: ArgMatches,
    /// What the card read is told, once `scan` / `shell` / `explore` runs.
    run: OnceLock<Run>,
    /// The session's first read, handed to the kit's own (so `shell` opens on the card it checked).
    first: Mutex<Option<Envelope>>,
    /// The baseline `--baseline` named, loaded by `load_baseline`.
    baseline: Mutex<Option<Baseline>>,
    outcome: Mutex<Option<Outcome>>,
}

impl SimDoctor {
    fn json(&self) -> bool {
        self.run.get().is_some_and(|r| r.json)
    }

    /// A `scan` that could not run: one sentence on stderr, and under `--json` the doctor/1
    /// failure envelope (no findings, score 0, `data.error`) on stdout.
    fn refuse(&self, failure: &scan::Failure) -> ScanFailure {
        let mut refusal = ScanFailure::plain(format!("sim-doctor: {}", failure.message));
        if self.json() {
            let env = failure_envelope(
                self,
                failure.kind,
                &failure.message,
                json!({"scanned": false, "card_touched": false}),
            );
            refusal = refusal.with_envelope(env);
        }
        refusal
    }

    /// The run was interrupted at a checkpoint: exit 130, `interrupted` on stderr, and under
    /// `--json` the envelope of [`Doctor::interrupted_envelope`]. Reported once per process (the
    /// watchdog of `guard_exchange` may be reporting it already).
    fn interrupted(&self) -> ScanFailure {
        let mut failure = doctor_kit::interrupt::failure(self);
        failure.stderr = "sim-doctor: interrupted\n".into();
        if INTERRUPT_REPORTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            failure.stderr.clear();
            failure.envelope = None;
        } else if !self.json() {
            failure.envelope = None;
        }
        failure
    }

    /// The card read. Same steps, same checkpoints, same refusals as ever; the report is built
    /// here, the kit prints it.
    fn scan_card(&self, args: &Run) -> Result<Envelope, ScanFailure> {
        if checkpoint() {
            return Err(self.interrupted());
        }
        let refuse = |kind: &'static str, err: &dyn std::fmt::Display| {
            self.refuse(&scan::Failure::new(kind, err.to_string()))
        };
        let (mut session, reader, atr) =
            open_scan_session(args.reader.as_deref()).map_err(|f| self.refuse(&f))?;
        let session: &mut dyn CardSession = &mut *session;

        let options = walk::Options {
            addressing: walk::Addressing::PathFromMasterFile,
            // Spelled out rather than inherited: this is the set that can miss a
            // file, and the line that decides that belongs where the walk is built.
            candidates: walk::Candidates::SimFamilies,
            // Only 6A 82 is classified. Nothing else is, because this repository has
            // read no other table; see walk::StatusMeaning and CONTEXT.md section 3.
            meaning: walk::StatusMeaning::default(),
            limits: args.limits,
            ..walk::Options::default()
        };
        let mut tree = walk::walk(session, &args.dialect.tag_set(), &options)
            .map_err(|e| refuse("walk-failed", &e))?;
        // EF.ARR, read-only (SELECT and READ RECORD), so that the access rules the
        // FCPs only reference can be decoded by the rules.
        access::resolve(session, &mut tree, &session::Policy::default())
            .map_err(|e| refuse("access-rules-failed", &e))?;
        // The security-relevant EFs' contents, read-only (SELECT, READ BINARY, READ
        // RECORD), decoded later and shown in full (key files included).
        ef::read(session, &mut tree, &session::Policy::default())
            .map_err(|e| refuse("ef-read-failed", &e))?;

        // The second of three checkpoints. Everything the tree knows is still only
        // in memory here, so stopping now costs the whole run rather than emitting
        // something a caller could mistake for a result.
        if checkpoint() {
            return Err(self.interrupted());
        }

        // The TAR audit, over the same live session. It polls doctor_kit::interrupt::interrupted()
        // before every probe: a Ctrl-C during a full sweep is acted on rather than queued.
        let audit = tar::audit_with(
            session,
            &args.tar,
            &session::Policy::default(),
            args.terminal_profile,
            &mut || doctor_kit::interrupt::interrupted(),
        )
        .map_err(|e| refuse("tar-audit-failed", &e))?;

        // The third and last checkpoint: an interrupted TAR scan must be reported as
        // interrupted, never rendered as a shorter audit.
        if checkpoint() {
            return Err(self.interrupted());
        }

        let found = scan::findings(&scan::Subject {
            tree: &tree,
            tar: &audit,
            scp03: None,
        })
        .map_err(|e| refuse("rule-misattribution", &e))?;

        // Filtered before it is scored, and the score taken from what is left:
        // the number in the report is a function of the findings in the report.
        let mut verdict = scan::Verdict::new(found, scan::rules_run())
            .tar_audit(audit)
            .at_least(args.severity)
            .scored(args.score);
        let context = scan::Context::new(
            reader.as_str(),
            atr.as_deref(),
            args.dialect,
            options.candidates.clone(),
            options.limits,
        );
        // What this run actually did, which is what a baseline has to record and what a
        // comparison is allowed to assume.
        let facts = scan::run_facts(&tree, &context, &verdict);

        // Compared last, and REFUSED rather than reported when the two runs cannot honestly
        // be compared: data.error, exit 2, no findings and no data.diff.
        if let Some(saved) = self.baseline.lock().unwrap().as_ref() {
            match Diff::compare(saved, &facts, verdict.findings().as_slice()) {
                Ok(diff) => {
                    eprintln!(
                        "sim-doctor: compared against the baseline: {} new, {} fixed, {} persisting",
                        diff.new_findings().len(),
                        diff.fixed().len(),
                        diff.persisting().len(),
                    );
                    if let Some(warning) = diff.rules_warning() {
                        eprintln!("sim-doctor: warning: {warning}");
                    }
                    verdict = verdict.compared_against(diff);
                }
                Err(incomparable) => {
                    return Err(refuse(
                        incomparable.kind(),
                        &incomparable.explain(saved, &facts),
                    ));
                }
            }
        }

        let exit_code = verdict.exit_code(args.fail_on);
        let document = scan::doctor_json(&tree, &context, &verdict, &facts, exit_code);
        let envelope: Envelope = serde_json::from_value(document)
            .map_err(|e| ScanFailure::plain(format!("sim-doctor: {e}")))?;

        if args.tui
            && !(std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout()))
        {
            eprintln!("sim-doctor: --tui needs a terminal; showing the plain report");
        }
        // One line on stderr for a truncated walk, in BOTH modes, on top of the banner and the
        // JSON fields: under --json stdout is the envelope, and a human watching a CI log learns
        // the answer is partial without piping it through a formatter.
        if !tree.is_complete() {
            let hit: Vec<String> = tree
                .limits_hit()
                .iter()
                .copied()
                .map(|limit| limit.to_string())
                .collect();
            eprintln!(
                "sim-doctor: warning: the walk stopped early, so this is not the whole card; \
                 bounds hit: {}",
                if hit.is_empty() {
                    "none recorded".to_owned()
                } else {
                    hit.join(", ")
                }
            );
        }
        // The same for a TAR scan that did not finish.
        if let Some(reason) = verdict.tar().stopped.as_deref() {
            eprintln!(
                "sim-doctor: warning: the TAR scan did not finish, so its findings are partial: {reason}"
            );
        }

        *self.outcome.lock().unwrap() = Some(Outcome {
            states: envelope.findings.iter().map(|f| f.baseline_state).collect(),
            counts: envelope.baseline,
            tree,
            verdict,
            reader: reader.as_str().to_owned(),
            atr,
            dialect: args.dialect,
            candidates: options.candidates,
            limits: options.limits,
        });
        Ok(envelope)
    }
}

impl Doctor for SimDoctor {
    fn name(&self) -> &str {
        "sim-doctor"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn about(&self) -> &str {
        "CLI-first SIM/UICC security testing tool"
    }
    fn categories(&self) -> Vec<&'static str> {
        vec![]
    }
    /// Unused: the rules share one card subject and run from `try_scan` itself.
    fn checks(&self) -> Vec<Box<dyn Check>> {
        vec![]
    }
    fn target(&self) -> TargetKind {
        TargetKind::Detached
    }
    /// `--fail-on` defaults to `critical`: a scan fails only on the worst finding.
    fn default_fail_on(&self) -> Severity {
        Severity::Critical
    }
    /// Only the model name is read (by `failure_envelope`): the score of a scan comes from
    /// `scan::doctor_score`.
    fn score(&self, _: &[doctor_kit::doctor_core::Finding], _: &Ctx) -> Option<Score> {
        Some(Score::new(0, scan::SCORE_MODEL, 1))
    }

    /// The skill text every agent file carries (`src/skill_body.md`).
    fn skill_body(&self) -> String {
        SKILL_BODY.into()
    }

    /// The files `install` writes, byte for byte what it always wrote.
    fn agent_files(&self, agent: Agent) -> Vec<AgentFile> {
        let file = |path: &str, body: String, mode| AgentFile {
            path: path.into(),
            body,
            mode,
        };
        match agent {
            Agent::Claude => vec![file(
                ".claude/skills/sim-doctor/SKILL.md",
                format!("---\nname: sim-doctor\ndescription: Scan a SIM/UICC card over PC/SC with `sim-doctor scan --json` and read the result envelope. Use when asked to examine, audit or score a SIM card.\n---\n\n{SKILL_BODY}"),
                FileMode::Write,
            )],
            Agent::Cursor => vec![file(
                ".cursor/rules/sim-doctor.mdc",
                format!("---\ndescription: How to run sim-doctor and read its JSON envelope\nalwaysApply: false\n---\n\n{SKILL_BODY}"),
                FileMode::Write,
            )],
            // Codex and opencode both read AGENTS.md: one marked block, the rest of the file untouched.
            Agent::Codex | Agent::Opencode => vec![file(
                "AGENTS.md",
                SKILL_BODY.trim_end().to_owned(),
                FileMode::Block {
                    begin: "<!-- sim-doctor:start -->".into(),
                    end: "<!-- sim-doctor:end -->".into(),
                },
            )],
        }
    }

    /// The nine tools of `mcp` (scan, the rule catalogue, the read-only eUICC and GlobalPlatform
    /// queries), which REPLACE the kit's `scan` and `fix`: each runs this binary as a child.
    fn mcp_tools(&self) -> Option<Vec<McpTool>> {
        let cli = Cli::command();
        let scan = cli.find_subcommand("scan")?;
        Some(sim_doctor::mcp::tools(
            scan,
            std::sync::Arc::new(sim_doctor::mcp::run_self),
        ))
    }

    /// The texts of the server it replaces. The protocol answers (`ping`, -32600 for a request
    /// that is not an object, has a bad `id` or no string `method`) are the kit's and were
    /// already sim-doctor's; only two messages differ from the kit's defaults.
    fn mcp_texts(&self) -> McpTexts {
        McpTexts {
            invalid_request: "invalid request: not an object".into(),
            invalid_request_method: "invalid request: no string method".into(),
            ..McpTexts::default()
        }
    }

    /// The findings by category (the kit's tree) and the card's files under `card`: the master
    /// file, then each directory's files as it is entered (`expand`).
    fn tree(&self, env: &Envelope, ctx: &Ctx) -> Node {
        let mut root = doctor_kit::session::default_tree(env, ctx);
        root.meta.retain(|_, v| !v.is_null());
        let text = |key: &str| clean(env.data[key].clone());
        root.meta.insert("target".into(), text("reader"));
        let mut card = Node::new("card", "card", "the card's files")
            .meta("reader", text("reader"))
            .meta("atr", text("atr"))
            .meta("dialect", clean(env.data["dialect"]["id"].clone()))
            .meta("complete", env.data["complete"].clone());
        card.children = vec![];
        root.children.push(card);
        root
    }

    /// The files of one directory, read from the walk that is already in memory.
    fn expand(&self, _: &Envelope, _: &Ctx, path: &[String], _: &Node) -> Option<Vec<Node>> {
        let outcome = self.outcome.lock().unwrap();
        let tree = &outcome.as_ref()?.tree;
        let (first, rest) = path.split_first()?;
        if first != "card" {
            return None;
        }
        let entries = ef::entries(tree);
        let ids: Vec<walk::NodeId> = if rest.is_empty() {
            vec![tree.root()]
        } else {
            let at = rest.join("/");
            let parent = tree.nodes().iter().find(|n| n.path().to_string() == at)?;
            parent.children().to_vec()
        };
        let nodes: Vec<Node> = ids
            .into_iter()
            .filter_map(|id| tree.node(id))
            .filter(|n| !matches!(n.state(), walk::NodeState::Absent))
            .map(|n| file_node(tree, n, &entries))
            .collect();
        (!nodes.is_empty()).then_some(nodes)
    }

    /// An elementary file's decoded contents, when the walk read and recognised it.
    fn decode(&self, node: &Node) -> Option<String> {
        let contents = node.meta.get("contents")?;
        serde_json::to_string_pretty(contents).ok()
    }

    fn try_scan(&self, _: &Ctx) -> Result<Envelope, ScanFailure> {
        if let Some(env) = self.first.lock().unwrap().take() {
            return Ok(env);
        }
        match self.run.get() {
            Some(run) => self.scan_card(run),
            None => Err(ScanFailure::new("this command does not read a card")),
        }
    }

    /// sim-doctor's own baseline file rules (size and string bounds, the run record), unchanged.
    /// The comparison itself (`Diff::compare`) needs the walk, so it runs in `scan_card`.
    fn load_baseline(&self, path: &std::path::Path) -> Result<Saved, ScanFailure> {
        match Baseline::load(path) {
            Ok(saved) => {
                *self.baseline.lock().unwrap() = Some(saved);
                // The kit's set match is redone by `baseline_hook`, so nothing is needed here.
                Ok(Saved {
                    fingerprints: HashSet::new(),
                    doc: Value::Null,
                })
            }
            Err(err) => Err(self.refuse(&scan::Failure::new(err.kind(), err.to_string()))),
        }
    }

    /// `--sarif` and `--baseline` name one file. A baseline that cannot be read is reported first,
    /// as it always was.
    fn preflight_error(&self, kind: PreflightKind, msg: String) -> ScanFailure {
        if let Some(path) = self.run.get().and_then(|a| a.baseline.as_deref()) {
            if let Err(err) = Baseline::load(path) {
                return self.refuse(&scan::Failure::new(err.kind(), err.to_string()));
            }
        }
        let (tag, msg) = match (kind, self.run.get().and_then(|a| a.sarif.as_deref())) {
            (PreflightKind::SarifIsBaseline, Some(sarif)) => (
                "sarif-baseline-same-path",
                format!(
                    "--sarif and --baseline both name {}; the SARIF file would destroy the baseline",
                    sarif.display()
                ),
            ),
            (PreflightKind::SarifIsBaseline, None) => ("sarif-baseline-same-path", msg),
            (PreflightKind::Baseline, _) => ("baseline-unreadable", msg),
        };
        self.refuse(&scan::Failure::new(tag, msg))
    }

    /// sim-doctor's comparison labels each finding (a multiset match on the fingerprint) and
    /// counts `new` / `unchanged` / `fixed` itself; put that back over the kit's set match.
    fn baseline_hook(&self, _: &Value, env: &mut Envelope) -> Result<(), ScanFailure> {
        if let Some(outcome) = self.outcome.lock().unwrap().as_ref() {
            for (finding, state) in env.findings.iter_mut().zip(&outcome.states) {
                finding.baseline_state = *state;
            }
            env.baseline = outcome.counts;
        }
        Ok(())
    }

    /// Compact, keys sorted, one line: what `scan --json` has always printed.
    fn render_json(&self, env: &Envelope) -> String {
        let mut value = env.to_value();
        if let Some(findings) = value["findings"].as_array_mut() {
            for finding in findings {
                // The old document always carried `evidence`, empty or not.
                finding
                    .as_object_mut()
                    .map(|f| f.entry("evidence").or_insert_with(|| json!([])));
            }
        }
        serde_json::to_string(&value).expect("an envelope serializes") + "\n"
    }

    /// The SARIF file: card-path logical locations, the same bytes as ever.
    fn render_sarif(&self, env: &Envelope) -> String {
        let outcome = self.outcome.lock().unwrap();
        let findings = outcome.iter().flat_map(|o| o.verdict.findings().as_slice());
        let score = serde_json::to_value(&env.score).expect("a score serializes");
        let doc = sarif::to_sarif(
            &findings.cloned().collect::<Vec<_>>(),
            &scan::specs(),
            &score,
        );
        serde_json::to_string_pretty(&doc).expect("a SARIF document serializes") + "\n"
    }

    /// The interrupted envelope of a doctor/1 `scan`: no `data`, score 0 with one gap.
    fn interrupted_envelope(&self, _: &Envelope) -> Option<Envelope> {
        Some(Envelope::new(
            "sim-doctor",
            env!("CARGO_PKG_VERSION"),
            130,
            Score::new(0, scan::SCORE_MODEL, 1),
            vec![],
            contract::interrupted_data(),
        ))
    }

    /// What the old report put in banners and warnings, for the face to show first: an
    /// incomplete walk, the standing candidate-set warning, the score warning, a TAR audit that
    /// did not finish, repeated identifiers, files that were forbidden, refused or noted.
    fn notes(&self, env: &Envelope) -> Vec<Note> {
        let d = &env.data;
        let mut notes = doctor_kit::face::notes_of(env);
        let mut add = |level: NoteLevel, text: String| notes.push(Note { level, text });
        if d["complete"] == json!(false) {
            let mut text = "TRUNCATED: this walk did NOT see the whole card; a file outside it is neither present nor absent here".to_owned();
            if let Some(first) = d["truncated_by"].as_str() {
                text.push_str(&format!("; first bound hit: {first}"));
            }
            let hit: Vec<&str> = d["limits_hit"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if !hit.is_empty() {
                text.push_str(&format!("; every bound hit: {}", hit.join(", ")));
            }
            if let Some(why) = d["stopped"].as_str() {
                text.push_str(&format!("; walk stopped: {why}"));
            }
            add(NoteLevel::Error, text);
        }
        if let Some(why) = d["tar"]["stopped"].as_str() {
            add(
                NoteLevel::Warn,
                format!("the TAR scan did not finish, so its findings are partial: {why}"),
            );
        }
        if let Some(blind) = d["tar"]["blind_spot"].as_str() {
            add(NoteLevel::Warn, format!("TAR blind spot: {blind}"));
        }
        if let Some(w) = d["score_detail"]["warning"].as_str() {
            add(NoteLevel::Warn, format!("score: {w}"));
        }
        if let Some(w) = d["candidates"]["warning"].as_str() {
            add(NoteLevel::Info, w.to_owned());
        }
        let count = |key: &str| d["walk"][key].as_u64().unwrap_or(0);
        if count("repeated_ancestors") > 0 {
            add(NoteLevel::Warn, format!("{} repeated identifier(s) in the walk (a directory that lists one of its own ancestors)", count("repeated_ancestors")));
        }
        for (key, what) in [
            ("forbidden", "present but not readable by this terminal"),
            ("refused", "refused for another reason"),
        ] {
            if count(key) > 0 {
                add(
                    NoteLevel::Info,
                    format!("{} file(s) {what}; `--json` lists them", count(key)),
                );
            }
        }
        let noted = d["notes"].as_array().map_or(0, Vec::len);
        if noted > 0 {
            add(
                NoteLevel::Info,
                format!("{noted} walk note(s) on individual files; `--json` lists them"),
            );
        }
        notes
            .iter_mut()
            .for_each(|n| n.text = contract::sanitize(&n.text));
        notes
    }

    /// `--face legacy`: the full report (`scan::to_human`); `--tui`: the terminal view. `None`
    /// (the default) is the kit's face, with [`Doctor::notes`].
    fn render_human(&self, _: &Envelope, _: &Face, _: &doctor_kit::Theme) -> Option<String> {
        let run = self.run.get()?;
        let outcome = self.outcome.lock().unwrap();
        let outcome = outcome.as_ref()?;
        let context = outcome.context();
        let tui = run.tui
            && std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout());
        if tui {
            // The view is the output: nothing goes to stdout but the terminal UI.
            let data = scan::to_json(&outcome.tree, &context, &outcome.verdict);
            // A failed view must not skip the stderr warnings, and must not change the exit
            // status: say so and carry on.
            if let Err(err) = sim_doctor::tui::run(&data) {
                eprintln!("sim-doctor: tui: {err}");
            }
            return Some(String::new());
        }
        run.legacy
            .then(|| scan::to_human(&outcome.tree, &context, &outcome.verdict) + "\n")
    }
}

/// Strips what a card could use to move a terminal (control, escape, bidi, zero-width
/// characters) from every string of `value`.
fn clean(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(contract::sanitize(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(clean).collect()),
        Value::Object(map) => Value::Object(map.into_iter().map(|(k, v)| (k, clean(v))).collect()),
        other => other,
    }
}

/// One walked file as a shell node: its identifier, what the card said about it, and for an
/// elementary file the bytes the walk read (`cat`, `raw`) and what they decode to.
fn file_node(tree: &Tree, file: &walk::Node, entries: &[ef::Entry]) -> Node {
    let path = file.path();
    let id = path.to_string();
    let name = id.rsplit('/').next().unwrap_or(&id).to_owned();
    let info = clean(scan::node_json(file));
    let state = info["state"].as_str().unwrap_or_default().to_owned();
    let kind = info["file_kind"].as_str().unwrap_or(&state).to_owned();
    let octets = info.pointer("/size/value/octets").and_then(Value::as_u64);
    let entry = entries.iter().find(|e| e.path == *path);
    let mut summary = match kind.as_str() {
        "MF" => "master file".to_owned(),
        "DF" => "directory".to_owned(),
        "EF" => format!(
            "{} EF",
            info["descriptor"]["value"]["structure"]
                .as_str()
                .unwrap_or("elementary")
        ),
        other => other.to_owned(),
    };
    if let Some(octets) = octets {
        summary.push_str(&format!(", {octets} bytes"));
    }
    if let Some(entry) = entry {
        summary.push_str(&format!(", {}", entry.ef.name()));
    }
    if let Some(status) = info["status"].as_str() {
        summary.push_str(&format!(" ({status})"));
    }
    let mut node = Node::new(&name, &kind, summary).meta("path", id);
    for (key, value) in info.as_object().into_iter().flatten() {
        if key != "path" {
            node = node.meta(key, value.clone());
        }
    }
    if let Some(entry) = entry {
        node = node.meta("contents", clean(entry.to_json()));
    }
    if let Some(walk::ContentRead::Records(records)) = tree.content_read(path) {
        node = node.raw(records.concat());
    }
    node
}

/// `scan`, on the kit's pipeline.
pub fn scan(d: &SimDoctor, args: ScanArgs) -> contract::ExitCode {
    // A flag's own shape is refused before a reader is opened, as clap would.
    if args.terminal_profile && matches!(args.tar.mode, tar::Mode::Off) {
        eprintln!("sim-doctor: --terminal-profile is only meaningful with --tar other than off");
        return contract::ExitCode::Error;
    }
    let run = d.run.get_or_init(|| Run::scan(&args));
    super::guard_exchange(scan::KIND, run.json);
    let fail_on = Severity::parse(run.fail_on.id()).expect("the same five names");
    // The kit's face, plain when stdout is not a terminal; `--face legacy` is the old report.
    let face = match args.face.as_deref() {
        Some("rich") => Face::Rich,
        Some("plain") => Face::Plain,
        Some("compact") => Face::Compact,
        _ if std::io::IsTerminal::is_terminal(&std::io::stdout()) => Face::Rich,
        _ => Face::Plain,
    };
    let o = OutputArgs {
        json: run.json,
        score: false,
        headless: args.headless,
        face,
        theme: args.theme.clone(),
        theme_file: None,
        color: args.color.unwrap_or(Color::Auto),
        sarif: run.sarif.clone(),
        baseline: run.baseline.clone(),
        fail_on,
        theme_root: None,
    };
    let ctx = Ctx::detached(Config::default(), fail_on);
    // Read the baseline before a reader is opened, and refuse before one is: a --baseline that
    // names a file that is not there, is not a doctor/1 envelope or is over a bound has an
    // answer before a card exists.
    let code = match preflight(d, &o) {
        Ok(pre) => finish(d, pre, d.try_scan(&ctx), &o),
        Err(failure) => doctor_kit::output::report_failure(d, &failure),
    };
    exit_code(code)
}

/// `install`: write the agent guidance, or with `--print-only` show it.
pub fn install(d: &SimDoctor, args: InstallArgs) -> contract::ExitCode {
    let agent = args
        .agent
        .as_deref()
        .and_then(|a| <Agent as clap::ValueEnum>::from_str(a, true).ok());
    let files = plan(d, agent);
    if args.print_only {
        let printed: String = files
            .iter()
            .map(|f| format!("==> {}\n{}\n", f.path.display(), rendered(f)))
            .collect();
        return match emit_stdout(printed.trim_end_matches('\n'), "the skill") {
            Ok(()) => contract::ExitCode::Success,
            Err(message) => {
                eprintln!("sim-doctor: {message}");
                contract::ExitCode::Findings
            }
        };
    }
    for file in &files {
        // The project root is created when it is missing, as `install` always did.
        let written = std::fs::create_dir_all(&args.dir)
            .map_err(|e| e.to_string())
            .and_then(|()| write(&args.dir, std::slice::from_ref(file), Overwrite::Always));
        match written {
            Ok(paths) => println!("wrote {}", paths[0].display()),
            Err(err) => {
                eprintln!("sim-doctor: cannot write {}: {err}", file.path.display());
                return contract::ExitCode::Findings;
            }
        }
    }
    contract::ExitCode::Success
}

/// Reads the card once for `shell` and `explore`, so a missing reader or card is an error (exit 2
/// and the sentence), not an empty session. The read is handed to the kit's own session.
#[cfg(feature = "shell")]
fn open_session(d: &SimDoctor, card: &CardArgs) -> Result<Ctx, u8> {
    d.run.get_or_init(|| Run::session(card));
    let ctx = Ctx::detached(Config::default(), Severity::Critical);
    match d.try_scan(&ctx) {
        Ok(env) => *d.first.lock().unwrap() = Some(env),
        Err(failure) => return Err(doctor_kit::output::report_failure(d, &failure)),
    }
    // An interactive session ends on Ctrl-C and on `kill`: the flag handler `main` installed is
    // for the scan's checkpoints, and nothing here polls it (as in `mcp`).
    // SAFETY: SIG_DFL is a valid disposition for these signals; no handler pointer is involved.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
    }
    Ok(ctx)
}

#[cfg(feature = "shell")]
fn shell(d: &SimDoctor, own: &ArgMatches) -> Result<u8, String> {
    let args = ShellArgs::from_arg_matches(own).map_err(|e| e.to_string())?;
    match open_session(d, &args.card) {
        Ok(ctx) => doctor_kit::repl::run(d, ctx, args.command.as_deref(), args.json),
        Err(code) => Ok(code),
    }
}

#[cfg(feature = "shell")]
fn explore(d: &SimDoctor, own: &ArgMatches) -> Result<u8, String> {
    let args = ExploreArgs::from_arg_matches(own).map_err(|e| e.to_string())?;
    match open_session(d, &args.card) {
        Ok(ctx) => doctor_kit::tui::run(d, ctx).map(|()| 0),
        Err(code) => Ok(code),
    }
}

/// The contract exit code a process code stands for.
fn exit_code(code: u8) -> contract::ExitCode {
    contract::ExitCode::ALL
        .into_iter()
        .find(|c| c.process_code() == code)
        .unwrap_or(contract::ExitCode::Error)
}

/// Runs the mounted command: parse the whole command line again as the derive-built `Cli`.
fn run_cli(d: &SimDoctor, _own: &ArgMatches) -> Result<u8, String> {
    let cli = Cli::from_arg_matches(&d.root).map_err(|e| e.to_string())?;
    Ok(dispatch(d, cli.command).process_code())
}

/// Exit code of a command line clap refused. Help and version are not failures (0); `scan` is a
/// doctor/1 findings command, so a usage error is 2 there; everywhere else it is 129.
fn usage_exit(err: &clap::Error, argv: &[String]) -> u8 {
    use clap::error::ErrorKind;
    let code = match err.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => contract::ExitCode::Success,
        _ if argv
            .iter()
            .skip(1)
            .find(|a| !a.starts_with('-'))
            .map(String::as_str)
            == Some("scan") =>
        {
            contract::ExitCode::Error
        }
        _ => contract::ExitCode::InvalidUsage,
    };
    code.process_code()
}

/// Run the CLI.
pub fn run() -> ExitCode {
    let cli = Cli::command();
    let meta = Meta {
        name: "sim-doctor".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        about: cli.get_about().map(ToString::to_string).unwrap_or_default(),
        fail_on: Severity::Critical,
        target: TargetKind::Detached,
    };
    #[allow(unused_mut)]
    let mut commands: Vec<ExtCommand<SimDoctor>> = cli
        .get_subcommands()
        .cloned()
        .enumerate()
        // Keeps `--help` listing the commands in the order they are declared in.
        .map(|(i, command)| ExtCommand {
            command: command.display_order(i),
            run: run_cli,
        })
        .collect();
    // After the commands above in `--help`, and replacing the kit's own `shell` / `explore`.
    #[cfg(feature = "shell")]
    {
        use clap::Args;
        let n = commands.len();
        commands.push(ExtCommand {
            command: ShellArgs::augment_args(
                clap::Command::new("shell")
                    .about("Interactive shell over the card: its findings and its files")
                    .display_order(n),
            ),
            run: shell,
        });
        commands.push(ExtCommand {
            command: ExploreArgs::augment_args(
                clap::Command::new("explore")
                    .about("Full-screen explorer over the card: its findings and its files")
                    .display_order(n + 1),
            ),
            run: explore,
        });
    }
    let ext = Extensions {
        commands,
        global_args: vec![],
        usage_exit,
    };
    doctor_kit::run_with(meta, ext, |root| {
        Ok(SimDoctor {
            root: root.clone(),
            run: OnceLock::new(),
            first: Mutex::new(None),
            baseline: Mutex::new(None),
            outcome: Mutex::new(None),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::super::Command;
    use super::*;
    use doctor_kit::doctor_core::{Finding, Location, LocationKind};

    fn doctor() -> SimDoctor {
        SimDoctor {
            root: Cli::command().get_matches_from(["sim-doctor", "modules"]),
            run: OnceLock::new(),
            first: Mutex::new(None),
            baseline: Mutex::new(None),
            outcome: Mutex::new(None),
        }
    }

    fn finding() -> Finding {
        Finding {
            id: "gsma/x".into(),
            fingerprint: "0123456789abcdef".into(),
            severity: Severity::High,
            confidence: None,
            category: "gsma".into(),
            message: "m".into(),
            location: Location::new(LocationKind::CardPath, "3F00"),
            evidence: vec![],
            remedy: None,
            baseline_state: None,
            extra: Default::default(),
        }
    }

    /// The document `scan --json` has always printed: one compact line with sorted keys, a
    /// finding without evidence still carrying `"evidence":[]` and `"remedy":null`.
    #[test]
    fn json_is_compact_sorted_and_keeps_empty_evidence() {
        let d = doctor();
        let env = Envelope::new(
            "sim-doctor",
            "1.2.3",
            1,
            Score::new(97, "sim/1", 0),
            vec![finding()],
            json!({"b": 1, "a": 2}),
        );
        let text = d.render_json(&env);
        assert_eq!(
            text,
            r#"{"data":{"a":2,"b":1},"exit_code":1,"findings":[{"category":"gsma","evidence":[],"fingerprint":"0123456789abcdef","id":"gsma/x","location":{"kind":"card-path","ref":"3F00"},"message":"m","remedy":null,"severity":"high"}],"schema":"doctor/1","score":{"coverage_gaps":0,"label":"good","model":"sim/1","value":97},"tool":"sim-doctor","version":"1.2.3"}
"#
        );
    }

    /// A refusal is the doctor/1 failure envelope under `--json` and only a sentence otherwise.
    #[test]
    fn a_refusal_is_a_failure_envelope_only_under_json() {
        let d = doctor();
        let f = scan::Failure::new("no-card", "nothing in the reader");
        assert!(d.refuse(&f).envelope.is_none());
        assert_eq!(d.refuse(&f).stderr, "sim-doctor: nothing in the reader\n");
        let a = Cli::command().get_matches_from(["sim-doctor", "scan", "--json"]);
        let Command::Scan(args) = Cli::from_arg_matches(&a).unwrap().command else {
            unreachable!()
        };
        d.run.set(Run::scan(&args)).ok().unwrap();
        let refusal = d.refuse(&f);
        assert_eq!(refusal.exit, 2);
        let env = refusal.envelope.unwrap();
        assert_eq!(
            (env.exit_code, env.score.value, env.score.coverage_gaps),
            (2, 0, 1)
        );
        assert_eq!(
            env.data,
            json!({"scanned": false, "card_touched": false,
                   "error": {"kind": "no-card", "message": "nothing in the reader"}})
        );
    }
}
