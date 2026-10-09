//! `docs/rule_docs/` is generated from the rule declarations (issue #40).
//!
//! One file per rule, `docs/rule_docs/<namespace>/<name>.json`, holding
//! `{id, severity, description, remediation, cwe, reference}`. The declarations in code are
//! the only source (`sim-doctor rules explain` reads the same ones), so this test fails when
//! a file is missing, stale or orphaned. Regenerate with:
//! `UPDATE_RULE_DOCS=1 cargo test --test rule_docs`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use sim_doctor::scan;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/rule_docs")
}

fn render(spec: &sim_doctor::rules::RuleSpec) -> String {
    let doc = serde_json::json!({
        "id": spec.id().as_str(),
        "severity": spec.severity().id(),
        "description": spec.summary(),
        "remediation": spec.remediation(),
        "cwe": spec.cwe(),
        "reference": spec.reference(),
    });
    format!("{}\n", serde_json::to_string_pretty(&doc).unwrap())
}

fn files(dir: &Path, out: &mut BTreeSet<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.insert(path);
        }
    }
}

#[test]
fn every_rule_has_a_current_doc_and_no_doc_is_orphaned() {
    let update = std::env::var_os("UPDATE_RULE_DOCS").is_some();
    let mut expected = BTreeSet::new();
    for spec in scan::all_specs() {
        let path = root().join(format!("{}.json", spec.id().as_str()));
        let text = render(&spec);
        assert!(
            spec.remediation().is_some_and(|r| !r.is_empty()),
            "{} has no remediation",
            spec.id()
        );
        if update {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &text).unwrap();
        }
        assert_eq!(
            fs::read_to_string(&path).ok().as_deref(),
            Some(text.as_str()),
            "{} is missing or stale; run UPDATE_RULE_DOCS=1 cargo test --test rule_docs",
            path.display()
        );
        expected.insert(path);
    }
    let mut present = BTreeSet::new();
    files(&root(), &mut present);
    for orphan in present.difference(&expected) {
        if update {
            fs::remove_file(orphan).unwrap();
        } else {
            panic!("{} documents no registered rule", orphan.display());
        }
    }
}

#[test]
fn security_rules_cite_a_weakness_class_and_a_clause() {
    for spec in scan::all_specs() {
        if spec.id().as_str().starts_with("ts48/") {
            // A comparison against a test profile, not a weakness.
            assert!(spec.cwe().is_none(), "{}", spec.id());
            continue;
        }
        assert!(
            spec.cwe().is_some_and(|c| c.starts_with("CWE-")),
            "{} has no CWE",
            spec.id()
        );
        assert!(spec.reference().is_some(), "{} cites no clause", spec.id());
    }
}
