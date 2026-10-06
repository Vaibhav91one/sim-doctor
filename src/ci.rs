//! `sim-doctor ci install`: the GitHub Actions workflow that runs this repo's composite action.
//!
//! Every option lands inside YAML, so each is validated before anything is written. The file work refuses to
//! write through a symlink anywhere from the root down. Never touches a reader, a card or stdout.

use crate::rules::Severity;
use std::path::{Path, PathBuf};

/// The module's name, as `sim-doctor modules` reports it.
pub const NAME: &str = "ci";

/// The workflow path, relative to the project root.
pub const WORKFLOW: &str = ".github/workflows/sim-doctor.yml";

const TEMPLATE: &str = include_str!("ci_workflow.yml");

/// What goes into the workflow's `with:` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Build the software card on the runner (CI has no card otherwise).
    pub swsim: bool,
    /// Committed baseline path, relative to the repository.
    pub baseline: String,
    /// A missing baseline fails the job.
    pub require_baseline: bool,
    /// Optional `--severity` threshold.
    pub severity: Option<Severity>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            swsim: true,
            baseline: ".sim-doctor/baseline.json".into(),
            require_baseline: true,
            severity: None,
        }
    }
}

/// Why `install` did not write.
#[derive(Debug, PartialEq, Eq)]
pub enum CiError {
    /// An option value is not safe to put in YAML (usage error).
    Invalid(String),
    /// A path component is a symlink.
    Symlink(PathBuf),
    /// The file exists, differs, and `force` was not given.
    Differs(PathBuf),
    /// Any other I/O failure.
    Io(String),
}

impl std::fmt::Display for CiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CiError::Invalid(m) => f.write_str(m),
            CiError::Symlink(p) => write!(
                f,
                "{} is a symlink; refusing to write through it",
                p.display()
            ),
            CiError::Differs(p) => write!(
                f,
                "skipped {}: it exists and differs (use --force to overwrite)",
                p.display()
            ),
            CiError::Io(m) => f.write_str(m),
        }
    }
}

/// What `install` did.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// `print_only`: the text, nothing written.
    Printed(String),
    /// The file was written.
    Wrote(PathBuf),
    /// The file already held exactly this text.
    Unchanged(PathBuf),
}

/// Refuses any value that is not safe inside the YAML template.
pub fn validate(options: &Options, ref_: &str) -> Result<(), String> {
    let path = &options.baseline;
    let path_ok = !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c))
        && !path.starts_with('-')
        && !path.starts_with('/')
        && !path.contains("..");
    if !path_ok {
        return Err(format!(
            "--baseline: '{path}' is not a relative path of letters, digits and . _ / - (no '..', no leading '-' or '/')"
        ));
    }
    let mut chars = ref_.chars();
    let ref_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && ref_
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c));
    if !ref_ok {
        return Err(format!("--ref: '{ref_}' is not a tag or branch name"));
    }
    Ok(())
}

/// The workflow text. Pure; callers validate first (`install` does).
pub fn workflow(options: &Options, ref_: &str) -> String {
    let severity = options
        .severity
        .map(|s| format!("          severity: \"{}\"\n", s.id()))
        .unwrap_or_default();
    TEMPLATE
        .replace("__REF__", ref_)
        .replace("__SWSIM__", &options.swsim.to_string())
        .replace("__BASELINE__", &options.baseline)
        .replace(
            "__REQUIRE_BASELINE__",
            &options.require_baseline.to_string(),
        )
        .replace("__SEVERITY__", &severity)
}

/// Validates, then prints or writes the workflow under `root`.
pub fn install(
    root: &Path,
    options: &Options,
    ref_: &str,
    force: bool,
    print_only: bool,
) -> Result<InstallOutcome, CiError> {
    validate(options, ref_).map_err(CiError::Invalid)?;
    let text = workflow(options, ref_);
    if print_only {
        return Ok(InstallOutcome::Printed(text));
    }
    let target = root.join(WORKFLOW);
    // Writing through a symlink could land outside the repository: refuse any link from the root down.
    let mut current = root.to_path_buf();
    for part in Path::new(WORKFLOW).components() {
        current.push(part);
        if std::fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(CiError::Symlink(current));
        }
    }
    let io = |e: std::io::Error| CiError::Io(format!("cannot write {}: {e}", target.display()));
    if target.exists() {
        if std::fs::read_to_string(&target).map_err(io)? == text {
            return Ok(InstallOutcome::Unchanged(target));
        }
        if !force {
            return Err(CiError::Differs(target));
        }
    }
    std::fs::create_dir_all(target.parent().expect("WORKFLOW has a parent")).map_err(io)?;
    std::fs::write(&target, text).map_err(io)?;
    Ok(InstallOutcome::Wrote(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bad_baseline(value: &str) -> Options {
        Options {
            baseline: value.into(),
            ..Options::default()
        }
    }

    #[test]
    fn default_workflow_pins_this_version_and_carries_every_input() {
        let ref_ = format!("v{}", env!("CARGO_PKG_VERSION"));
        let text = workflow(&Options::default(), &ref_);
        assert!(text.starts_with("# Written by `sim-doctor ci install`."));
        for line in [
            format!("uses: Vaibhav91one/sim-doctor@{ref_}").as_str(),
            "swsim: \"true\"",
            "baseline: \".sim-doctor/baseline.json\"",
            "require-baseline: \"true\"",
            "comment: \"true\"",
            "upload-sarif: \"true\"",
            "fetch-depth: 0",
            "on:\n  pull_request:\n",
            "contents: read",
            "pull-requests: write",
            "security-events: write",
            "runs-on: ubuntu-latest",
        ] {
            assert!(text.contains(line), "missing {line}\n{text}");
        }
        assert!(!text.contains("__"), "leftover placeholder\n{text}");
        assert!(!text.contains("severity:"), "no severity unless asked");
    }

    #[test]
    fn severity_and_flags_land_in_the_workflow() {
        let options = Options {
            swsim: false,
            require_baseline: false,
            severity: Some(Severity::High),
            ..Options::default()
        };
        let text = workflow(&options, "v1");
        assert!(text.contains("swsim: \"false\""));
        assert!(text.contains("require-baseline: \"false\""));
        assert!(text.contains("          severity: \"high\"\n          comment:"));
    }

    #[test]
    fn hostile_baselines_are_refused() {
        for value in [
            "a b", "../x", "a/../x", "/etc/x", "-x", "a\"b", "a'b", "a`b`", "$(id)", "${{ x }}",
            "a\nb", "a\\b", "",
        ] {
            assert!(
                validate(&bad_baseline(value), "v1").is_err(),
                "accepted baseline {value:?}"
            );
        }
        assert!(validate(&bad_baseline("ci/base-line_1.json"), "v1").is_ok());
        assert!(validate(&Options::default(), "v1").is_ok());
    }

    #[test]
    fn hostile_refs_are_refused() {
        for value in [
            "v1 && rm", "../x", "-x", "a b", "", "/x", "a\"b", "$(id)", "a\nb",
        ] {
            assert!(
                validate(&Options::default(), value).is_err(),
                "accepted ref {value:?}"
            );
        }
        for value in ["v0.1.0", "main", "release/1.x"] {
            assert!(
                validate(&Options::default(), value).is_ok(),
                "refused ref {value:?}"
            );
        }
    }

    // ---- file work ----

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sim-doctor-ci-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn go(root: &Path, force: bool, print_only: bool) -> Result<InstallOutcome, CiError> {
        install(root, &Options::default(), "v1", force, print_only)
    }

    #[test]
    fn writes_the_file() {
        let root = tempdir("write");
        let outcome = go(&root, false, false).unwrap();
        let target = root.join(WORKFLOW);
        assert_eq!(outcome, InstallOutcome::Wrote(target.clone()));
        assert_eq!(
            std::fs::read_to_string(target).unwrap(),
            workflow(&Options::default(), "v1")
        );
    }

    #[test]
    fn print_only_writes_nothing() {
        let root = tempdir("print");
        let outcome = go(&root, false, true).unwrap();
        assert_eq!(
            outcome,
            InstallOutcome::Printed(workflow(&Options::default(), "v1"))
        );
        assert!(!root.join(".github").exists());
    }

    #[test]
    fn invalid_options_write_nothing() {
        let root = tempdir("invalid");
        let err = install(&root, &bad_baseline("../x"), "v1", false, false).unwrap_err();
        assert!(matches!(err, CiError::Invalid(_)));
        assert!(!root.join(".github").exists());
    }

    #[test]
    fn a_differing_file_is_kept_unless_forced_and_an_identical_one_is_fine() {
        let root = tempdir("differs");
        let target = root.join(WORKFLOW);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "mine\n").unwrap();
        let err = go(&root, false, false).unwrap_err();
        assert_eq!(err, CiError::Differs(target.clone()));
        assert!(err.to_string().contains("--force"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "mine\n");

        assert_eq!(
            go(&root, true, false).unwrap(),
            InstallOutcome::Wrote(target.clone())
        );
        assert_eq!(
            go(&root, false, false).unwrap(),
            InstallOutcome::Unchanged(target)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_workflows_directory_is_refused_and_nothing_lands_outside() {
        let root = tempdir("symdir");
        let outside = tempdir("symdir-outside");
        std::fs::create_dir_all(root.join(".github")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".github/workflows")).unwrap();
        let err = go(&root, true, false).unwrap_err();
        assert!(matches!(err, CiError::Symlink(_)), "{err:?}");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_github_directory_is_refused() {
        let root = tempdir("symgh");
        let outside = tempdir("symgh-outside");
        std::os::unix::fs::symlink(&outside, root.join(".github")).unwrap();
        assert!(matches!(go(&root, true, false), Err(CiError::Symlink(_))));
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_workflow_file_is_refused_and_the_victim_is_unchanged() {
        let root = tempdir("symfile");
        let outside = tempdir("symfile-outside");
        let victim = outside.join("victim.txt");
        std::fs::write(&victim, "precious\n").unwrap();
        let target = root.join(WORKFLOW);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        let err = go(&root, true, false).unwrap_err();
        assert!(matches!(err, CiError::Symlink(_)), "{err:?}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious\n");
    }
}
