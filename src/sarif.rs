//! SARIF 2.1.0 for a scan's findings (issue #42).
//!
//! One pure function over [`rules`] types. A card has no files on disk, so no
//! result carries a `physicalLocation`: the place a finding was seen is a
//! `logicalLocation` (the card path). Partial coverage is a fact about the
//! whole run and is surfaced in `runs[0].properties`, never dropped.
//!
//! Whether GitHub code scanning accepts this document is NOT verified.

use crate::rules::{Finding, RuleSpec, Severity};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// This module's name in [`crate::MODULES`].
pub const NAME: &str = "sarif";

const fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Info | Severity::Low => "note",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    }
}

/// CVSS-style number GitHub sorts by, as a string; a fixed table of this tool's choosing.
const fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

/// FNV-1a 64-bit over the finding's identity, as 16 lowercase hex digits.
///
/// Digits in the message are masked so a count in the prose cannot change
/// which finding this is: findings differing only in digits share a
/// fingerprint by design. Fields are length-prefixed so no separator inside
/// one of them can be mistaken for a boundary.
pub fn fingerprint(finding: &Finding) -> String {
    let mut masked = String::new();
    let mut in_digits = false;
    for c in finding.message().chars() {
        if c.is_ascii_digit() {
            if !in_digits {
                masked.push('#');
            }
            in_digits = true;
        } else {
            in_digits = false;
            masked.push(c);
        }
    }
    let location = finding.location().to_string();
    let identity: String = [finding.rule().as_str(), location.as_str(), masked.as_str()]
        .iter()
        .map(|field| format!("{}:{field}", field.len()))
        .collect();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in identity.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Writes `doc` (pretty, trailing newline) to `path` through a temporary file
/// in the same directory and a rename; the temporary file is removed on error.
pub fn write(path: &std::path::Path, doc: &Value) -> std::io::Result<()> {
    let mut text = serde_json::to_string_pretty(doc).map_err(std::io::Error::other)?;
    text.push('\n');
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let temporary = path.with_file_name(name);
    let result = std::fs::write(&temporary, text.as_bytes())
        .and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// The findings as a SARIF 2.1.0 document, with one rule per spec.
///
/// `score` is the doctor/1 score object (contract section 5); the fingerprint
/// under `doctorFinding/v1` is the same value as the finding's JSON `fingerprint`.
pub fn to_sarif(findings: &[Finding], specs: &[RuleSpec], score: &Value) -> Value {
    let mut rules: Vec<Value> = specs
        .iter()
        .map(|spec| {
            let mut rule = json!({
                "id": spec.id().as_str(),
                "name": spec.id().as_str(),
                "shortDescription": {"text": spec.summary()},
                "defaultConfiguration": {"level": level(spec.severity())},
                "properties": {"security-severity": security_severity(spec.severity()), "tags": ["security"]},
            });
            if let Some(remediation) = spec.remediation() {
                rule["help"] = json!({"text": remediation});
            }
            rule
        })
        .collect();
    let mut ids: Vec<String> = specs.iter().map(|s| s.id().as_str().to_owned()).collect();

    let mut results = Vec::with_capacity(findings.len());
    for finding in findings {
        let id = finding.rule().as_str();
        let index = ids.iter().position(|known| known == id).unwrap_or_else(|| {
            // A finding whose rule is not in `specs` still needs a rules[] entry.
            ids.push(id.to_owned());
            rules.push(json!({
                "id": id,
                "name": id,
                "shortDescription": {"text": finding.message()},
                "defaultConfiguration": {"level": level(finding.severity())},
                "properties": {"security-severity": security_severity(finding.severity()), "tags": ["security"]},
            }));
            ids.len() - 1
        });
        let mut properties = json!({
            "severity": finding.severity().id(),
            "coverage": if finding.coverage().is_complete() { "complete" } else { "partial" },
        });
        if let Some(reason) = finding.coverage().reason() {
            properties["coverageReason"] = json!(reason);
        }
        results.push(json!({
            "ruleId": id,
            "ruleIndex": index,
            "level": level(finding.severity()),
            "message": {"text": finding.message()},
            "locations": [{"logicalLocations": [{
                "name": finding.location().to_string(),
                "kind": "resource",
            }]}],
            "partialFingerprints": {"doctorFinding/v1": fingerprint(finding)},
            "properties": properties,
        }));
    }

    let reasons: BTreeSet<&str> = findings
        .iter()
        .filter_map(|f| f.coverage().reason())
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "sim-doctor",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Vaibhav91one/sim-doctor",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "coverage": if reasons.is_empty() { "complete" } else { "partial" },
                "coverageReasons": reasons,
                "score": score,
            },
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Evidence, Location, RuleId, Status};

    fn finding(severity: Severity, message: &str) -> Finding {
        Finding::new(
            RuleId::new("gsma/msl-zero-allowed").unwrap(),
            severity,
            message,
            Location::forbidden_file("3F00/2F00/6F07", Status::new(0x98, 0x04)),
            Evidence::bytes([0xa4, 0x00, 0x0a, 0x4f]),
        )
    }

    fn specs() -> Vec<RuleSpec> {
        crate::scan::specs()
    }

    fn score() -> Value {
        crate::contract::doctor_score(100, "sim/1", 0)
    }

    #[test]
    fn document_shape() {
        let doc = to_sarif(&[], &specs(), &score());
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"].as_array().unwrap().len(), 1);
        assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "sim-doctor");
    }

    #[test]
    fn empty_findings_is_well_formed() {
        let doc = to_sarif(&[], &specs(), &score());
        assert_eq!(doc["runs"][0]["results"], json!([]));
        assert_eq!(doc["runs"][0]["properties"]["coverage"], "complete");
        assert_eq!(doc["runs"][0]["properties"]["coverageReasons"], json!([]));
        assert!(!doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn every_severity_maps_to_a_level() {
        let all: Vec<Finding> = Severity::LADDER.iter().map(|s| finding(*s, "m")).collect();
        let doc = to_sarif(&all, &specs(), &score());
        let levels: Vec<&str> = doc["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap())
            .collect();
        assert_eq!(levels, ["note", "note", "warning", "error", "error"]);
        for r in doc["runs"][0]["results"].as_array().unwrap() {
            assert_eq!(r["ruleId"], "gsma/msl-zero-allowed");
        }
    }

    #[test]
    fn security_severity_is_a_string_per_spec() {
        for (s, want) in [
            (Severity::Critical, "9.5"),
            (Severity::High, "8.0"),
            (Severity::Medium, "5.0"),
            (Severity::Low, "3.0"),
            (Severity::Info, "0.0"),
        ] {
            assert_eq!(security_severity(s), want);
        }
        let doc = to_sarif(&[], &specs(), &score());
        for rule in doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
        {
            assert!(rule["properties"]["security-severity"].is_string());
        }
    }

    #[test]
    fn logical_locations_and_no_physical_location() {
        let doc = to_sarif(&[finding(Severity::High, "m")], &specs(), &score());
        let loc = &doc["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0];
        assert_eq!(loc["kind"], "resource");
        assert!(loc["name"].as_str().unwrap().contains("3F00/2F00/6F07"));
        assert!(!serde_json::to_string(&doc)
            .unwrap()
            .contains("physicalLocation"));
    }

    #[test]
    fn partial_coverage_surfaces_in_run_properties() {
        let doc = to_sarif(
            &[
                finding(Severity::High, "a"),
                finding(Severity::High, "b").partial("walk bound reached"),
                finding(Severity::High, "c").partial("walk bound reached"),
            ],
            &specs(),
            &score(),
        );
        let props = &doc["runs"][0]["properties"];
        assert_eq!(props["coverage"], "partial");
        assert_eq!(props["coverageReasons"], json!(["walk bound reached"]));
        let results = &doc["runs"][0]["results"];
        assert_eq!(results[0]["properties"]["coverage"], "complete");
        assert!(results[0]["properties"].get("coverageReason").is_none());
        assert_eq!(results[1]["properties"]["coverage"], "partial");
        assert_eq!(
            results[1]["properties"]["coverageReason"],
            "walk bound reached"
        );

        let all_complete = to_sarif(&[finding(Severity::High, "a")], &specs(), &score());
        assert_eq!(
            all_complete["runs"][0]["properties"]["coverage"],
            "complete"
        );
    }

    fn fp(f: &Finding) -> String {
        to_sarif(std::slice::from_ref(f), &specs(), &score())["runs"][0]["results"][0]
            ["partialFingerprints"]["doctorFinding/v1"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn fingerprint_is_stable_and_masks_digits_only() {
        let a = fp(&finding(Severity::High, "accepted TAR 000000 in 12 probes"));
        assert_eq!(a.len(), 16);
        assert!(a
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(
            a,
            fp(&finding(Severity::High, "accepted TAR 000000 in 12 probes"))
        );
        assert_eq!(
            a,
            fp(&finding(Severity::High, "accepted TAR 9 in 7 probes"))
        );
        assert_ne!(
            a,
            fp(&finding(Severity::High, "rejected TAR 000000 in 12 probes"))
        );
    }

    #[test]
    fn the_run_carries_the_score_object() {
        let doc = to_sarif(&[], &specs(), &score());
        assert_eq!(doc["runs"][0]["properties"]["score"], score());
    }

    #[test]
    fn rule_index_points_at_the_same_id() {
        let doc = to_sarif(&[finding(Severity::High, "m")], &specs(), &score());
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        for r in doc["runs"][0]["results"].as_array().unwrap() {
            let i = usize::try_from(r["ruleIndex"].as_u64().unwrap()).unwrap();
            assert_eq!(rules[i]["id"], r["ruleId"]);
        }
    }

    #[test]
    fn a_rule_missing_from_specs_still_gets_an_entry() {
        let doc = to_sarif(&[finding(Severity::High, "m")], &[], &score());
        let rules = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(doc["runs"][0]["results"][0]["ruleIndex"], 0);
    }

    #[test]
    fn fingerprint_golden_and_field_sensitive() {
        let base = finding(Severity::Critical, "the card accepted TAR 000000");
        assert_eq!(fp(&base), "f405c45b121ae11d");
        let other_rule = Finding::new(
            RuleId::new("gsma/other").unwrap(),
            Severity::Critical,
            "the card accepted TAR 000000",
            Location::forbidden_file("3F00/2F00/6F07", Status::new(0x98, 0x04)),
            Evidence::bytes([0xa4]),
        );
        let other_location = Finding::new(
            RuleId::new("gsma/msl-zero-allowed").unwrap(),
            Severity::Critical,
            "the card accepted TAR 000000",
            Location::forbidden_file("3F00/2F00/6F08", Status::new(0x98, 0x04)),
            Evidence::bytes([0xa4]),
        );
        assert_ne!(fp(&base), fp(&other_rule));
        assert_ne!(fp(&base), fp(&other_location));
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sarif-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn write_creates_then_overwrites_without_leftovers() {
        let dir = scratch("ok");
        let path = dir.join("out.sarif");
        write(&path, &json!({"a": 1})).unwrap();
        write(&path, &json!({"a": 2})).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["a"], 2);
        assert_eq!(entries(&dir), ["out.sarif"]);
    }

    #[test]
    fn write_to_a_missing_parent_fails_cleanly() {
        let dir = scratch("noparent");
        assert!(write(&dir.join("missing/out.sarif"), &json!({})).is_err());
        assert!(entries(&dir).is_empty());
    }

    #[test]
    fn write_onto_a_directory_fails_and_leaves_no_temp() {
        let dir = scratch("isdir");
        let target = dir.join("out.sarif");
        std::fs::create_dir(&target).unwrap();
        assert!(write(&target, &json!({})).is_err());
        assert_eq!(entries(&dir), ["out.sarif"]);
    }
}
