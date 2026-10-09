//! The lpac-shaped JSON envelope and the four process exit codes.
//!
//! **Owns.** The two things an automated caller actually depends on: the shape
//! of a line of JSON on stdout, and the number the process exits with. Both
//! are AGENTS.md section 3, both are load-bearing for every later feature, so
//! both are pinned by tests here rather than by convention.
//!
//! **Does not own.** Findings, rules, severities, or anything about a card. The
//! envelope carries an opaque [`serde_json::Value`] precisely so that it does
//! not have to know: `data` belongs to whoever produced it. This module has no
//! dependencies on any other module in the crate and must not acquire any.
//!
//! **"No dependencies" means no crate-internal ones.** `serde` and
//! `serde_json` are used, and that is the whole of the coupling: this is the
//! one place in the crate that decides what JSON looks like.
//!
//! **Do not change the envelope shape.** Issue #1 says so, and it means it.
//! Any change to a field name, to the field order, or to the set of exit
//! codes is a contract break and has to be recorded in CONTEXT.md first.

/// This module's name, as recorded in [`crate::MODULES`].
///
/// Referenced by value rather than re-spelt as a literal so that the module
/// table cannot name a module that does not exist.
pub const NAME: &str = "contract";

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The `type` a plain success envelope carries.
///
/// `lpac` answers with `"type": "lpa"`, and AGENTS.md section 3 says to adopt
/// that shape, so that is the default. The field exists to say *which* response
/// this is, which is what lets an agent tell a scan result from a profile list
/// without inspecting `data`.
pub const DEFAULT_KIND: &str = "lpa";

/// The `message` an [`ExitCode::Success`] envelope carries.
pub const OK_MESSAGE: &str = "ok";

/// The `message` an [`ExitCode::Interrupted`] envelope carries.
///
/// An interrupted run emits **one** envelope carrying this message and code
/// 130, and never a partial result. That is a decision, not an omission, and it
/// is the reason the constant exists:
///
/// - **stdin stays pure in every mode.** With `--json`, stdout is one complete
///   envelope whether the run finished or was cut short, so a consumer never
///   has to special-case an empty stream.
/// - **`payload.code` keeps meaning what it is documented to mean.**
///   [`Payload::code`] says it is "the same value the process exits with". An
///   interrupted run that printed nothing would break that correspondence on
///   exactly the one code where a caller most wants to check it; a caller that
///   reads only the envelope, and never looks at the exit status, still learns
///   the run was interrupted.
/// - **a half-finished scan is not a result.** A caller must never be able to
///   read partial findings as though a walk had completed, so `data` is an empty
///   object rather than whatever had been gathered when the signal arrived.
///   Empty rather than null so `data` is always indexable.
///
/// In the human (non-`--json`) modes the same event prints a line on **stderr**
/// and nothing on stdout, because stdout there is a report and there is no
/// report to give.
pub const INTERRUPTED_MESSAGE: &str = "interrupted";

/// The `data` an interrupted envelope carries: an empty object.
///
/// Never findings, never a count, never a partial tree. See
/// [`INTERRUPTED_MESSAGE`] for why.
///
/// A function rather than a `const` because `serde_json::Map::new` is not a
/// constant expression; the value it builds is two words wide either way, so
/// callers should not need to hold on to it.
pub fn interrupted_data() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// The four statuses a `sim-doctor` process may exit with.
///
/// `u8` rather than a wider integer because every one of the four fits and
/// because these end up as the exit status of the process itself, which is an
/// octet. The numeric values are the contract and are asserted verbatim in
/// the tests: 130 for SIGINT is the shell convention, 129 is the bad-usage
/// slot, and 1 is deliberately shared by "findings present" and "a check
/// failed" so that a CI gate does not have to tell a dirty card from a broken
/// run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExitCode {
    /// The run finished and nothing was reported at or above threshold.
    Success = 0,

    /// Findings were reported at or above threshold, or a check failed.
    ///
    /// One code for both, on purpose: a caller gating a build cares whether
    /// the card passed, not why it did not.
    Findings = 1,

    /// The command line could not be understood.
    InvalidUsage = 129,

    /// doctor/1 only (`scan`): usage error, bad input, or the run could not
    /// complete. The lpa-style commands keep using [`ExitCode::Findings`] (1)
    /// and [`ExitCode::InvalidUsage`] (129) for these.
    Error = 2,

    /// doctor/1 only (`scan --baseline`): at least one NEW finding at or above
    /// `--fail-on`. Takes precedence over [`ExitCode::Findings`].
    NewFindings = 3,

    /// The operator interrupted the run.
    Interrupted = 130,
}

impl ExitCode {
    /// Every exit code, numerically ascending.
    pub const ALL: [Self; 6] = [
        Self::Success,
        Self::Findings,
        Self::Error,
        Self::NewFindings,
        Self::InvalidUsage,
        Self::Interrupted,
    ];

    /// The number the process exits with.
    pub const fn process_code(self) -> u8 {
        self as u8
    }

    /// Looks an exit code up by its process code.
    ///
    /// `None` for anything outside the four.
    pub const fn from_process_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Success),
            1 => Some(Self::Findings),
            2 => Some(Self::Error),
            3 => Some(Self::NewFindings),
            129 => Some(Self::InvalidUsage),
            130 => Some(Self::Interrupted),
            _ => None,
        }
    }

    /// Whether this status means the run reported nothing.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl Serialize for ExitCode {
    /// Serializes as the bare process code.
    ///
    /// Hand-written because serde renders a fieldless enum as a string by
    /// default, and a code of `"InvalidUsage"` would break every consumer that
    /// compares the number. AGENTS.md section 3 asks for a machine-checkable
    /// status, and a word is not one.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.process_code())
    }
}

impl<'de> Deserialize<'de> for ExitCode {
    /// Rejects any code outside the four.
    ///
    /// A baseline written by a future version, or edited by hand, must not be
    /// read back as a run that succeeded.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u8::deserialize(deserializer)?;
        Self::from_process_code(raw)
            .ok_or_else(|| serde::de::Error::custom(format!("{raw} is not a sim-doctor exit code")))
    }
}

/// One response, in the shape `lpac` returns for everything.
///
/// ```json
/// { "type": "lpa", "payload": { "code": 0, "message": "ok", "data": {} } }
/// ```
///
/// Fields are private so an envelope can only be built through a constructor:
/// there is no literal a caller could spell with the fields in the wrong order
/// or with `data` left as a null by accident.
///
/// What the private fields do **not** do is validate. [`Envelope::new`] takes a
/// `kind` and a `message` and passes both through, so a caller can still build
/// an envelope with an empty `type`, or one whose message contradicts its code.
/// That is a decision, not an oversight: `type` is an open discriminator that
/// grows as commands land, and making the constructor fallible would put a
/// `Result` in front of every command for a mistake only a programmer in this
/// crate can make. Choosing the kind and its message is the caller's
/// responsibility, and the test
/// `an_empty_kind_survives_because_nothing_validates_it` pins that so it stays
/// a decision rather than drifting into an accident nobody noticed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Renamed on the wire. `kind` is a better Rust name than `type`, which
    /// is a keyword, but the JSON field is `type` because that is the shape
    /// `lpac` returns and AGENTS.md section 3 says to adopt it.
    #[serde(rename = "type")]
    kind: String,
    payload: Payload,
}

impl Envelope {
    /// Builds an envelope of any kind carrying any of the four statuses.
    pub fn new(
        kind: impl Into<String>,
        code: ExitCode,
        message: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            kind: kind.into(),
            payload: Payload {
                code,
                message: message.into(),
                data,
            },
        }
    }

    /// Builds an envelope reporting that nothing was found.
    pub fn success(data: serde_json::Value) -> Self {
        Self::new(DEFAULT_KIND, ExitCode::Success, OK_MESSAGE, data)
    }

    /// The `type` field: which response this is.
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The payload.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Renders the envelope as one line of JSON.
    ///
    /// This is what `--json` puts on stdout, alone. The caller writes it and
    /// nothing else, which is what lets an agent pipe it straight into a
    /// parser.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialize`] if `data` cannot be rendered. Every value
    /// this crate builds is renderable, so in practice this cannot fire; the
    /// signature is honest rather than a panic.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(self)?)
    }

    /// Renders the envelope as indented JSON.
    ///
    /// For a human reading a saved file. Never for stdout under `--json`:
    /// line-oriented consumers parse one envelope per line.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialize`] if `data` cannot be rendered.
    pub fn to_json_pretty(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// The body of an [`Envelope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    code: ExitCode,
    message: String,
    data: serde_json::Value,
}

impl Payload {
    /// The machine-checkable status, and the same value the process exits
    /// with.
    pub const fn code(&self) -> ExitCode {
        self.code
    }

    /// The human-readable status.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The result of the command, shaped by whatever produced it.
    pub const fn data(&self) -> &serde_json::Value {
        &self.data
    }
}

/// Everything that can go wrong while producing the output contract.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The envelope could not be rendered as JSON.
    #[error("the JSON envelope could not be rendered: {0}")]
    Serialize(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// doctor/1 (docs/doctor-contract.md): the envelope of a findings command
// ---------------------------------------------------------------------------

/// The `schema` value of the shared doctor envelope.
pub const DOCTOR_SCHEMA: &str = "doctor/1";

/// The doctor/1 score label for `value` and `coverage_gaps` (contract section 3).
///
/// `good` from 90, `needs work` from 60, `critical` below; `incomplete`
/// replaces `good` when anything was not covered.
pub const fn score_label(value: u8, coverage_gaps: usize) -> &'static str {
    if value >= 90 {
        if coverage_gaps > 0 {
            "incomplete"
        } else {
            "good"
        }
    } else if value >= 60 {
        "needs work"
    } else {
        "critical"
    }
}

/// The doctor/1 score object.
pub fn doctor_score(value: u8, model: &str, coverage_gaps: usize) -> serde_json::Value {
    serde_json::json!({
        "value": value,
        "label": score_label(value, coverage_gaps),
        "model": model,
        "coverage_gaps": coverage_gaps,
    })
}

/// The doctor/1 envelope as a [`serde_json::Value`] (`serde_json` orders keys,
/// and key order is not significant in the contract).
///
/// `baseline` is the optional `{new, unchanged, fixed}` block.
pub fn doctor_envelope(
    exit_code: ExitCode,
    score: serde_json::Value,
    findings: Vec<serde_json::Value>,
    data: serde_json::Value,
    baseline: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut envelope = serde_json::json!({
        "schema": DOCTOR_SCHEMA,
        "tool": "sim-doctor",
        "version": env!("CARGO_PKG_VERSION"),
        "exit_code": exit_code.process_code(),
        "score": score,
        "findings": findings,
        "data": data,
    });
    if let Some(baseline) = baseline {
        envelope["baseline"] = baseline;
    }
    envelope
}

/// A doctor/1 envelope for a run that produced no result (could not run, was
/// interrupted): no findings, a zero score with one coverage gap, and `data`
/// carrying the reason. Not a verdict on any card.
pub fn doctor_failure(exit_code: ExitCode, data: serde_json::Value) -> serde_json::Value {
    doctor_envelope(
        exit_code,
        doctor_score(0, "sim/1", 1),
        Vec::new(),
        data,
        None,
    )
}

// ---------------------------------------------------------------------------
// Sanitisation (docs/doctor-contract.md section 8)
// ---------------------------------------------------------------------------

/// Replaces every control and invisible character in `text` with a space.
///
/// **The one helper every human renderer uses** for text that came from a card
/// (file names, labels, messages, the reader name): the scan table, the TUI and
/// the fix prompt. It covers C0/C1 controls (so ESC), bidi controls
/// (U+202A-U+202E, U+2066-U+2069), zero-width characters (U+200B-U+200D,
/// U+FEFF) and the line and paragraph separators (U+2028, U+2029), plus the
/// other format and default-ignorable characters in [`is_invisible`]. A
/// newline is a control character too, so call this on one line at a time (see
/// [`sanitize_lines`]). JSON and SARIF do not use it: the serialiser escapes.
pub fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || is_invisible(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// [`sanitize`] applied to each line of a multi-line report, keeping the line
/// structure (and a final newline, when there is one).
pub fn sanitize_lines(report: &str) -> String {
    let mut out: Vec<String> = report.split('\n').map(sanitize).collect();
    if out.last().is_some_and(String::is_empty) {
        out.pop();
        out.push(String::new());
    }
    out.join("\n")
}

/// Format (Cf), line/paragraph separator, private-use and default-ignorable
/// characters.
///
/// std has no general-category lookup and no new crate is allowed, so this is an
/// explicit table. Unassigned code points (Cn) are NOT covered beyond the ranges
/// below.
pub fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{ad}' | '\u{34f}' | '\u{61c}' | '\u{115f}' | '\u{1160}' | '\u{17b4}' | '\u{17b5}'
        | '\u{180b}'..='\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}' | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}'
        | '\u{ffa0}' | '\u{fff9}'..='\u{fffb}' | '\u{e0000}'..='\u{e007f}'
        | '\u{e0100}'..='\u{e01ef}' | '\u{e000}'..='\u{f8ff}' | '\u{f0000}'..='\u{10ffff}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exit_codes_are_the_documented_numbers() {
        // Spelled out rather than derived, because these numbers are the
        // contract with every CI system that will ever run this binary.
        assert_eq!(ExitCode::Success.process_code(), 0);
        assert_eq!(ExitCode::Findings.process_code(), 1);
        assert_eq!(ExitCode::Error.process_code(), 2);
        assert_eq!(ExitCode::NewFindings.process_code(), 3);
        assert_eq!(ExitCode::InvalidUsage.process_code(), 129);
        assert_eq!(ExitCode::Interrupted.process_code(), 130);
        assert_eq!(ExitCode::ALL.len(), 6);

        for code in ExitCode::ALL {
            assert_eq!(
                ExitCode::from_process_code(code.process_code()),
                Some(code),
                "{code:?} must survive its own round trip",
            );
        }
    }

    #[test]
    fn nothing_outside_the_documented_six_is_an_exit_code() {
        // Exhausts all 256 possible exit statuses. 2 and 3 exist only for the
        // doctor/1 findings command (`scan`); the lpa-style commands never
        // return them.
        let accepted: Vec<u8> = (u8::MIN..=u8::MAX)
            .filter(|&raw| ExitCode::from_process_code(raw).is_some())
            .collect();
        assert_eq!(accepted, vec![0, 1, 2, 3, 129, 130]);
    }

    #[test]
    fn a_success_envelope_is_byte_for_byte_the_documented_shape() {
        // The lpac envelope from AGENTS.md section 3, as one line of stdout.
        let envelope = Envelope::success(serde_json::Value::Object(Default::default()));
        assert_eq!(
            envelope.to_json().unwrap(),
            r#"{"type":"lpa","payload":{"code":0,"message":"ok","data":{}}}"#
        );
    }

    #[test]
    fn an_interrupted_envelope_is_byte_for_byte_the_documented_shape() {
        // The other end of the contract from
        // a_success_envelope_is_byte_for_byte_the_documented_shape. Pinned
        // here because it is the shape an operator triggers by hand, and a
        // change to it is as breaking for an agent as a change to the success
        // envelope.
        let envelope = Envelope::new(
            DEFAULT_KIND,
            ExitCode::Interrupted,
            INTERRUPTED_MESSAGE,
            interrupted_data(),
        );
        assert_eq!(
            envelope.to_json().unwrap(),
            r##"{"type":"lpa","payload":{"code":130,"message":"interrupted","data":{}}}"##
        );

        // The field names and order are the success envelope's, unchanged.
        let parsed: Envelope = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();
        assert_eq!(parsed, envelope);
    }

    #[test]
    fn the_code_serializes_as_a_number_not_a_name() {
        let envelope = Envelope::new(
            DEFAULT_KIND,
            ExitCode::Interrupted,
            "interrupted",
            serde_json::Value::Null,
        );
        assert_eq!(
            envelope.to_json().unwrap(),
            r#"{"type":"lpa","payload":{"code":130,"message":"interrupted","data":null}}"#
        );
    }

    #[test]
    fn an_envelope_round_trips_through_json() {
        let envelope = Envelope::new(
            "scan",
            ExitCode::Findings,
            "3 findings",
            serde_json::json!({ "findings": ["filesystem/unreadable-ef"] }),
        );
        let parsed: Envelope = serde_json::from_str(&envelope.to_json().unwrap()).unwrap();

        assert_eq!(parsed, envelope);
        assert_eq!(parsed.kind(), "scan");
        assert_eq!(parsed.payload().code(), ExitCode::Findings);
        assert_eq!(parsed.payload().message(), "3 findings");
        assert_eq!(
            parsed.payload().data()["findings"][0],
            "filesystem/unreadable-ef",
        );
    }

    #[test]
    fn reading_an_envelope_refuses_a_code_outside_the_four() {
        let forged = r#"{"type":"lpa","payload":{"code":7,"message":"ok","data":{}}}"#;
        let error = serde_json::from_str::<Envelope>(forged).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("7 is not a sim-doctor exit code"),
            "{error}",
        );

        // The string form is refused too, for the same reason it is never
        // produced.
        let named = r#"{"type":"lpa","payload":{"code":"Success","message":"ok","data":{}}}"#;
        assert!(serde_json::from_str::<Envelope>(named).is_err());
    }

    #[test]
    fn pretty_output_is_the_same_envelope_with_more_whitespace() {
        let envelope = Envelope::success(serde_json::json!({ "modules": [] }));
        let pretty = envelope.to_json_pretty().unwrap();

        assert!(pretty.contains("\n  "), "{pretty}");
        assert_eq!(serde_json::from_str::<Envelope>(&pretty).unwrap(), envelope);
    }

    #[test]
    fn an_empty_kind_survives_because_nothing_validates_it() {
        // Known and chosen, not an oversight. `kind` is an open discriminator
        // that grows as commands land, so `new` stays infallible and trusts
        // the caller; see the note on `Envelope`. If a future change decides
        // the crate should reject an empty kind, this test is the thing that
        // has to be rewritten, which is the point of writing it now.
        let envelope = Envelope::new("", ExitCode::Success, OK_MESSAGE, serde_json::json!({}));

        assert_eq!(envelope.kind(), "");
        assert_eq!(
            envelope.to_json().unwrap(),
            r#"{"type":"","payload":{"code":0,"message":"ok","data":{}}}"#
        );
        // The field names and their order - the part of the contract that is
        // fixed - survive regardless of what the discriminator says.
        assert!(serde_json::from_str::<Envelope>(&envelope.to_json().unwrap()).is_ok());
    }

    #[test]
    fn only_success_counts_as_success() {
        assert!(ExitCode::Success.is_success());
        for code in [
            ExitCode::Findings,
            ExitCode::Error,
            ExitCode::NewFindings,
            ExitCode::InvalidUsage,
            ExitCode::Interrupted,
        ] {
            assert!(!code.is_success(), "{code:?}");
        }
    }

    #[test]
    fn score_labels_follow_the_contract_thresholds() {
        assert_eq!(score_label(100, 0), "good");
        assert_eq!(score_label(90, 0), "good");
        assert_eq!(score_label(90, 2), "incomplete");
        assert_eq!(score_label(89, 0), "needs work");
        assert_eq!(score_label(60, 3), "needs work");
        assert_eq!(score_label(59, 0), "critical");
        assert_eq!(score_label(0, 1), "critical");
    }

    #[test]
    fn sanitize_strips_escape_bidi_zero_width_and_separators() {
        let dirty =
            "a\u{1b}[31mb\u{9b}c\u{202e}d\u{2066}e\u{200b}f\u{feff}g\u{2028}h\u{2029}i\u{7}j";
        let clean = sanitize(dirty);
        assert!(
            !clean.chars().any(|c| c.is_control() || is_invisible(c)),
            "{clean:?}"
        );
        assert!(clean.starts_with("a [31mb"));
        assert_eq!(
            sanitize("plain text, ok: \u{e9}\u{4e2d}"),
            "plain text, ok: \u{e9}\u{4e2d}"
        );
        assert_eq!(sanitize_lines("x\u{1b}y\nz\n"), "x y\nz\n");
    }

    #[test]
    fn a_failure_envelope_is_doctor_1_with_no_findings() {
        let v = doctor_failure(
            ExitCode::Error,
            serde_json::json!({"error": {"kind": "no-card"}}),
        );
        assert_eq!(v["schema"], "doctor/1");
        assert_eq!(v["exit_code"], 2);
        assert_eq!(v["findings"], serde_json::json!([]));
        assert_eq!(v["data"]["error"]["kind"], "no-card");
    }
}
