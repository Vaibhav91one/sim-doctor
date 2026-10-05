//! The claim `rules` makes about `contract`, proved from outside the crate.
//!
//! `src/lib.rs` proves the layering from the inside, by reading the
//! `MODULES` table. This file proves the half that table cannot see: that a
//! finding really does reach the envelope as a `serde_json::Value`, and that
//! doing so leaves the envelope's own shape byte-for-byte what it was.
//!
//! It is an integration test rather than a unit test for one reason - it names
//! `sim_doctor::contract` and `sim_doctor::rules` in the same file. Neither
//! module can do that without taking on a dependency the layering forbids, and
//! that is the point being tested. Being outside the crate, this file may hold
//! both without changing anything either of them knows about.

use sim_doctor::contract::{Envelope, ExitCode, OK_MESSAGE};
use sim_doctor::rules::{
    Coverage, Evidence, EvidenceBytes, FileAccess, Finding, Findings, Location, RuleId, Severity,
    Status,
};
use sim_doctor::MODULES;

/// The three envelope keys, in the order AGENTS.md section 3 fixes them.
const ENVELOPE_PREFIX: &str = r#"{"type":"scan","payload":{"code":0,"message":"ok","data":"#;

/// A finding of the kind AGENTS.md section 3 names first.
fn unreadable_ef() -> Finding {
    Finding::new(
        RuleId::new("filesystem/unreadable-ef").expect("documented ID"),
        Severity::High,
        "EF.ICCID could not be selected: 9804",
        Location::forbidden_file("3F00/2F00/6F07", Status::new(0x98, 0x04)),
        Evidence::bytes([0xa4, 0x00, 0x0a, 0x4f]),
    )
}

#[test]
fn a_finding_reaches_the_envelope_without_reshaping_it() {
    // The same three envelope keys, in the same order, with the same values:
    // the finding is inside `data` and nothing above it moved.
    let envelope = Envelope::new(
        "scan",
        ExitCode::Success,
        OK_MESSAGE,
        serde_json::json!({ "findings": [unreadable_ef().to_json()] }),
    );
    let rendered = envelope.to_json().expect("renders");

    assert!(
        rendered.starts_with(ENVELOPE_PREFIX),
        "the envelope shape moved: {rendered}"
    );
    assert!(rendered.ends_with("}}"), "{rendered}");
    assert!(rendered.contains(r#""coverage":{"status":"complete"}"#));

    // The finding survived intact inside `data`.
    let parsed: Envelope = serde_json::from_str(&rendered).expect("reads back");
    let finding = &parsed.payload().data()["findings"][0];
    assert_eq!(finding["rule"], "filesystem/unreadable-ef");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["severity_rank"], 3);
    assert_eq!(finding["location"]["kind"], "file");
    assert_eq!(finding["location"]["path"], "3F00/2F00/6F07");
    assert_eq!(finding["location"]["access"], "forbidden");
    assert_eq!(finding["location"]["status"], "9804");
    assert_eq!(finding["evidence"]["octets"], "a4000a4f");
    assert_eq!(finding["coverage"]["status"], "complete");

    // And the envelope still says exactly what it said before a finding existed.
    assert_eq!(parsed.payload().code(), ExitCode::Success);
    assert_eq!(parsed.payload().message(), OK_MESSAGE);
    assert_eq!(parsed.kind(), "scan");
}

#[test]
fn the_envelope_is_identical_with_and_without_findings() {
    // The strongest form of "without changing the envelope's shape": the bytes
    // outside `data` are the same either way, field for field and value for
    // value.
    let bare = Envelope::new("scan", ExitCode::Success, OK_MESSAGE, serde_json::json!({}))
        .to_json()
        .expect("renders");
    let carrying = Envelope::new(
        "scan",
        ExitCode::Success,
        OK_MESSAGE,
        serde_json::json!({ "findings": [unreadable_ef().to_json()] }),
    )
    .to_json()
    .expect("renders");

    let split = |json: &str| -> (String, String) {
        let at = json.find(r#""data":"#).expect("an envelope has data");
        // at points at the opening quote of "data":, which is seven bytes
        // including the colon.
        (json[..at + 7].to_owned(), json[at + 7..].to_owned())
    };
    let (bare_head, bare_data) = split(&bare);
    let (carrying_head, carrying_data) = split(&carrying);

    // Everything up to and including `"data":` is byte-identical: the same
    // discriminator, the same payload keys, in the same order, with the same
    // values. Only what follows moved.
    assert_eq!(bare_head, carrying_head);
    assert_eq!(bare_head, ENVELOPE_PREFIX);
    // The empty data object, and the closing brace of payload and of the
    // envelope around it.
    assert_eq!(bare_data, "{}}}");
    assert!(carrying_data.ends_with("}}"), "{carrying_data}");
    assert!(carrying_data.len() > bare_data.len());
}

#[test]
fn a_whole_set_reaches_the_envelope_and_says_whether_it_finished() {
    // The set, not the bare finding: this is the shape a scan emits, and
    // "exhaustive" is the flag a consumer has to look at before treating the
    // list as the whole card.
    let clean = Envelope::new(
        "scan",
        ExitCode::Success,
        OK_MESSAGE,
        Findings::complete(vec![unreadable_ef()]).to_json(),
    );
    let truncated = Envelope::new(
        "scan",
        ExitCode::Findings,
        "1 finding",
        Findings::partial(vec![unreadable_ef()], "max_depth bound hit").to_json(),
    );

    let clean = clean.to_json().expect("renders");
    let truncated = truncated.to_json().expect("renders");

    assert!(clean.contains(r#""exhaustive":true"#), "{clean}");
    assert!(truncated.contains(r#""exhaustive":false"#), "{truncated}");
    assert!(
        truncated.contains(r#""reason":"max_depth bound hit""#),
        "{truncated}"
    );
    // The per-finding copy is there too, so an agent that greps one rule ID out
    // of the list still learns the scan was cut.
    assert!(
        truncated.contains(
            r#""findings":[{"coverage":{"reason":"max_depth bound hit","status":"partial"}"#
        ),
        "{truncated}"
    );
}

#[test]
fn a_forbidden_finding_and_an_absent_one_stay_distinguishable_through_the_envelope() {
    // The security distinction has to survive every hop, and the envelope is
    // the hop an agent actually reads. Same rule, same severity, same message:
    // only `location.access` and `location.status` tell them apart, so those
    // two fields are what is asserted.
    let absent = Finding::new(
        RuleId::new("filesystem/unreadable-ef").expect("documented ID"),
        Severity::High,
        "EF.ICCID could not be selected: 9804",
        Location::absent_file("3F00/2F00/6F07"),
        Evidence::None,
    );

    let envelope = Envelope::new(
        "scan",
        ExitCode::Findings,
        "2 findings",
        Findings::complete(vec![unreadable_ef(), absent]).to_json(),
    );
    let data = Envelope::to_json(&envelope).expect("renders");
    let parsed: Envelope = serde_json::from_str(&data).expect("reads back");

    let forbidden = &parsed.payload().data()["findings"][0];
    let missing = &parsed.payload().data()["findings"][1];
    assert_eq!(forbidden["rule"], missing["rule"]);
    assert_eq!(forbidden["severity"], missing["severity"]);
    assert_eq!(forbidden["location"]["access"], "forbidden");
    assert_eq!(forbidden["location"]["status"], "9804");
    assert_eq!(missing["location"]["access"], "absent");
    assert_eq!(missing["location"]["status"], serde_json::Value::Null);
}

#[test]
fn evidence_cannot_blow_up_the_line_an_agent_would_parse() {
    // The bound is enforced at construction, so this is not a test that the
    // limit works - it is a test that the limit is REACHED from outside, where
    // a rule author would be writing.
    let body: Vec<u8> = (0..=255u8).cycle().take(65_535).collect();
    let finding = Finding::new(
        RuleId::new("fs/big-evidence").expect("valid ID"),
        Severity::Low,
        "a whole elementary file was attached",
        Location::Card,
        Evidence::bytes(body.clone()),
    );
    let rendered = finding.to_json().to_string();

    assert!(
        rendered.len() < 1024,
        "one finding rendered to {} bytes",
        rendered.len()
    );
    assert_eq!(
        finding.evidence().as_bytes().expect("octets").offered(),
        body.len()
    );
    assert_eq!(
        finding
            .evidence()
            .as_bytes()
            .expect("octets")
            .as_slice()
            .len(),
        sim_doctor::rules::MAX_EVIDENCE_BYTES
    );
    // Text is bounded by its own named limit, through its own type.
    assert_eq!(
        Evidence::text("9".repeat(100_000))
            .as_text()
            .expect("text")
            .as_str()
            .len(),
        sim_doctor::rules::MAX_EVIDENCE_CHARS
    );
    assert_eq!(EvidenceBytes::new(vec![]).omitted(), 0);
}

#[test]
fn coverage_travels_on_the_finding_and_not_only_on_the_report() {
    // The case the module doc argues for: an agent that greps one rule ID reads
    // one object. If completeness were only on the report, that object would
    // read as exhaustive and the whole point of the field is gone.
    let finding = unreadable_ef().partial("max_nodes bound hit");
    let json = finding.to_json();

    assert_eq!(
        finding.coverage(),
        &Coverage::Partial {
            reason: "max_nodes bound hit".to_owned()
        }
    );
    assert!(!finding.coverage().is_complete());
    assert_eq!(json["coverage"]["status"], "partial");
    assert_eq!(json["coverage"]["reason"], "max_nodes bound hit");
    assert_eq!(finding.access(), Some(FileAccess::Forbidden));
    assert!(finding.is_forbidden());
}

#[test]
fn neither_contract_nor_rules_declares_a_dependency_on_the_other() {
    // Asserted from outside as well as inside, because the inside version reads
    // a table somebody could edit and this one reads the declarations. Both
    // leaves, and neither is allowed a single module above it.
    for name in ["contract", "rules"] {
        let module = MODULES
            .iter()
            .find(|module| module.name == name)
            .expect("a module root");
        assert!(
            module.depends_on.is_empty(),
            "{name} must stay a leaf, but depends on {:?}",
            module.depends_on
        );
    }
}
